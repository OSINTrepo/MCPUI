#!/usr/bin/env python3
"""OSINT Orchestrator — MCP-сервер-фронт над всеми остальными серверами.

LibreChat видит 4 инструмента; оркестратор сам подбирает серверы по задаче
(правила + LLM для нечётких случаев), зовёт их и собирает единый отчёт.

Запуск: stdio (supergateway оборачивает в Streamable HTTP). См. реестр.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

import recipes
import report
from mcp_client import MCPClient

CATALOG_PATH = Path(os.environ.get("CATALOG_PATH", "/app/catalog.json"))
LITELLM_BASE = os.environ.get("LITELLM_BASE_URL", "http://litellm:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
MODEL = os.environ.get("ORCHESTRATOR_MODEL", "GigaChat-2-Pro")
PER_TARGET = int(os.environ.get("ORCHESTRATOR_PER_TARGET", "3"))
CALL_TIMEOUT = float(os.environ.get("ORCHESTRATOR_CALL_TIMEOUT", "25"))
# Персональные таймауты. Быстрые API режем на 25с; медленным docker-run/sherlock
# (maigret/openosint) даём дожить (иначе орк. режет вызов на полпути и оставляет
# запущенный docker-контейнер — утечка памяти).
SERVER_TIMEOUT: dict[str, float] = {"maigret": 75, "openosint": 75}
# Мягкий дедлайн всего расследования: собираем то, что успело; остальное
# помечаем «не успел», чтобы один медленный сервер не подвешивал investigate.
SOFT_DEADLINE = float(os.environ.get("ORCHESTRATOR_SOFT_DEADLINE", "80"))
# Куда писать отчёты и по какому URL их отдаёт файловый сервис.
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/reports")
REPORTS_URL_BASE = os.environ.get("REPORTS_URL_BASE", "http://localhost:8899").rstrip("/")

mcp = FastMCP("orchestrator")


def load_catalog() -> dict[str, dict]:
    try:
        items = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {it["id"]: it for it in items if it.get("id") != "orchestrator"}


CATALOG = load_catalog()


# --------------------------------- LLM ------------------------------------
async def llm(messages: list[dict], max_tokens: int = 900) -> str | None:
    """Вызов LiteLLM. None при любой ошибке (graceful fallback на правила)."""
    if not LITELLM_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=90) as c:
            r = await c.post(f"{LITELLM_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                json={"model": MODEL, "messages": messages, "max_tokens": max_tokens,
                      "temperature": 0.2})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _json_from(text: str) -> dict | None:
    if not text:
        return None
    a, b = text.find("{"), text.rfind("}")
    if a >= 0 and b > a:
        try:
            return json.loads(text[a:b + 1])
        except Exception:
            return None
    return None


# ---------------------------- server selection -----------------------------
def select_servers(target_type: str) -> list[str]:
    """Серверы под тип цели: только курированный PREFERRED (быстрые/надёжные).
    Если для типа PREFERRED пуст — падаем на каталог по полю inputs."""
    pref = [s for s in recipes.PREFERRED.get(target_type, []) if s in CATALOG]
    if pref:
        return pref[:PER_TARGET]
    others = [sid for sid, it in CATALOG.items() if target_type in it.get("inputs", [])]
    return others[:PER_TARGET]


async def pick_generic_call(sid: str, endpoint: str, target: dict) -> dict | None:
    """Для сервера без curated-рецепта: выбрать tool+args (LLM, иначе эвристика)."""
    try:
        tools = await asyncio.wait_for(MCPClient(endpoint).list_tools(), timeout=30)
    except Exception:
        return None
    if not tools:
        return None
    slim = [{"name": t["name"],
             "required": (t.get("inputSchema", {}) or {}).get("required", []),
             "props": list(((t.get("inputSchema", {}) or {}).get("properties", {}) or {}).keys())}
            for t in tools[:40]]
    # 1) LLM выбирает
    ans = await llm([
        {"role": "system", "content": "Ты выбираешь MCP-инструмент. Верни ТОЛЬКО JSON "
         '{"tool": "...", "arguments": {...}} чтобы найти цель. Без пояснений.'},
        {"role": "user", "content": f"Цель: тип={target['type']} значение={target['value']}\n"
         f"Инструменты: {json.dumps(slim, ensure_ascii=False)}"}],
        max_tokens=300)
    j = _json_from(ans or "")
    if j and j.get("tool") in {t["name"] for t in tools}:
        return {"tool": j["tool"], "arguments": j.get("arguments", {})}
    # 2) эвристика: первый tool, значение в первый required string / array
    t0 = tools[0]
    sch = t0.get("inputSchema", {}) or {}
    props = sch.get("properties", {}) or {}
    args = {}
    for req in sch.get("required", []):
        p = props.get(req, {})
        args[req] = [target["value"]] if p.get("type") == "array" else target["value"]
    if not args and props:
        first = next(iter(props))
        p = props[first]
        args[first] = [target["value"]] if p.get("type") == "array" else target["value"]
    return {"tool": t0["name"], "arguments": args}


async def run_one(sid: str, target: dict) -> dict:
    """Выполнить один вызов сервера под цель. Возвращает запись результата."""
    it = CATALOG.get(sid)
    if not it:
        return {"server": sid, "ok": False, "text": "нет в каталоге"}
    endpoint = it["endpoint"]
    curated = recipes.CURATED.get((target["type"], sid))
    if curated:
        tool, args = curated[0], curated[1](target["value"])
        # Рецепт может переопределить инструмент по значению цели (напр. ИНН:
        # 10 цифр → get_company, 12 → get_entrepreneur) через ключ __tool__.
        if isinstance(args, dict) and "__tool__" in args:
            tool = args.pop("__tool__")
    else:
        pick = await pick_generic_call(sid, endpoint, target)
        if not pick:
            return {"server": sid, "name": it["display_name"], "ok": False,
                    "text": "источник недоступен (не удалось выбрать инструмент)"}
        tool, args = pick["tool"], pick["arguments"]
    # Персональный таймаут для медленных источников (maigret/openosint). Важно:
    # передаём его В САМ MCPClient (у него свой httpx-таймаут 60с) — иначе httpx
    # рвал бы соединение на 60с раньше нашего лимита (ReadTimeout у maigret ~62с).
    timeout = SERVER_TIMEOUT.get(sid, CALL_TIMEOUT)
    try:
        res = await asyncio.wait_for(
            MCPClient(endpoint, timeout=timeout).call(tool, args), timeout=timeout + 5)
    except asyncio.TimeoutError:
        return {"server": sid, "name": it["display_name"], "tool": tool, "ok": False,
                "text": "источник недоступен (таймаут)"}
    except Exception as e:
        return {"server": sid, "name": it["display_name"], "tool": tool, "ok": False,
                "text": f"источник недоступен ({type(e).__name__})"}
    return {"server": sid, "name": it["display_name"], "tool": tool,
            "ok": res["ok"], "text": res["text"] or ("пусто" if res["ok"] else "ошибка")}


def catalog_text() -> str:
    """Каталог источников по категориям (используется и как MCP-инструмент,
    и как ответ на вопрос «что ты умеешь»)."""
    by_cat: dict[str, list[str]] = {}
    for it in CATALOG.values():
        by_cat.setdefault(it["category"], []).append(
            f"  - {it['display_name']}: {it['description']}")
    out = ["Доступные источники:"]
    for cat, items in sorted(by_cat.items()):
        out.append(f"\n[{cat}]")
        out.extend(sorted(items))
    return "\n".join(out)


def build_plan(task: str) -> dict:
    targets = recipes.detect_targets(task)
    if not targets:
        targets = [{"type": "query", "value": task.strip()}]
    steps = []
    for tg in targets:
        for sid in select_servers(tg["type"]):
            steps.append({"target": tg, "server": sid,
                          "name": CATALOG.get(sid, {}).get("display_name", sid)})
    return {"targets": targets, "steps": steps}


_NOISE_PREFIX = ("[*]", "[♥]", "[!]", "[-]", "[i]", "Searching |", "Report saved")


def _clean(text: str) -> str:
    """Убираем баннеры/лог-шум CLI-инструментов (maigret и т.п.), оставляем суть."""
    kept = [ln for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith(_NOISE_PREFIX)]
    return " ".join(" ".join(kept).split())


# Текст-«ошибка», который сервер вернул как обычный контент (isError=false).
_ERR_HINT = ("not installed", "not in path", "scan error", "traceback",
             "payment required", "unauthorized", "forbidden")

# Классификация причины сбоя по тексту ответа — чтобы в отчёте было ПОНЯТНО,
# почему источник недоступен (нужен ключ / баланс / сервер сломан / лимит).
_FAIL_PATTERNS: list[tuple[tuple[str, ...], str]] = [
    (("payment required", "402", "no valid session", "x402", "insufficient balance",
      "balance is 0", "\"balance\": 0", "requires payment"), "нужен баланс/оплата"),
    (("unauthorized", "forbidden", "401", "403", "provide your api key",
      "no api key", "invalid api key", "api key required", "missing api key"), "нужен ключ"),
    (("-32602", "invalid tools/call result", "invalid_type",
      "не удалось выбрать инструмент", "0 tools"), "сервер вернул битый ответ"),
    (("rate limit", "too many requests", "429", "quota exceeded"), "лимит запросов"),
    (("not installed", "not in path", "traceback", "internal server error",
      "500 ", "scan error"), "ошибка на стороне сервера"),
]


def _fail_reason(text: str) -> str | None:
    low = (text or "").lower()
    for pats, reason in _FAIL_PATTERNS:
        if any(p in low for p in pats):
            return reason
    return None


def render_report(task: str, results: list[dict]) -> str:
    # переклассифицируем «ok, но текст = ошибка» в неуспех
    for r in results:
        low = (r.get("text") or "").lower()
        if r["ok"] and any(h in low for h in _ERR_HINT):
            r["ok"] = False
            r["text"] = "источник недоступен (" + low[:60].strip() + "…)"
    used = ", ".join(sorted({r.get("name", r["server"]) for r in results})) or "—"
    ok = [r for r in results if r["ok"] and r["text"] not in ("пусто", "")]
    lines = [f"Цель: {task} | Инструменты: {used}", "", "## Находки"]
    if ok:
        for r in ok:
            snippet = _clean(r["text"])[:1400]
            lines.append(f"- **{r.get('name', r['server'])}**: {snippet}")
    else:
        lines.append("- Значимых находок нет (источники не вернули данных).")
    lines += ["", "## Источники"]
    for r in results:
        status = "ok" if r["ok"] else "недоступен"
        lines.append(f"- {r.get('name', r['server'])} ({r.get('tool', '?')}): {status}")
    conf = "высокая" if len(ok) >= 2 else "средняя" if ok else "низкая"
    lines += ["", "## Уверенность", f"{conf} — данные от {len(ok)} из {len(results)} источников."]
    return "\n".join(lines)


def reclassify(results: list[dict]) -> None:
    """«ok, но текст = ошибка» → неуспех, с понятной причиной сбоя."""
    for r in results:
        if not r.get("ok"):
            # уже сбой — тоже уточним причину, если распознаётся
            reason = _fail_reason(r.get("text", ""))
            if reason:
                r["text"] = f"источник недоступен: {reason}"
            continue
        # ВАЖНО: причину-сбоя ищем только в КОРОТКИХ ответах. Крупный успешный
        # отчёт (maigret ~3000 симв.) может содержать «403»/«not found» от
        # проверяемых сайтов — это не сбой источника, а данные о целях.
        text = r.get("text", "") or ""
        if len(text.strip()) <= 400:
            reason = _fail_reason(text)
            if reason:
                r["ok"] = False
                r["text"] = f"источник недоступен: {reason}"


def render_chat_summary(task: str, results: list[dict], info: dict) -> str:
    """Краткая сводка для чата: ссылки на скачивание + топ-находки. Полная
    детализация — в файлах отчёта (главный агент их не пересказывает)."""
    meta = info["meta"]
    # Две строки ссылок: посмотреть в браузере и скачать файлом (/download/ →
    # Content-Disposition: attachment). Аналитику обычно нужен файл на диск.
    view = f"📄 **Открыть:** [Markdown]({info['md_url']})"
    if info.get("pdf_url"):
        view += f" · [PDF]({info['pdf_url']})"
    dl = f"⬇️ **Скачать:** [Markdown]({info['md_dl_url']})"
    if info.get("pdf_dl_url"):
        dl += f" · [PDF]({info['pdf_dl_url']})"
    lines = [f"✅ Досье по «{task}» готово.", "", view, dl, "",
             f"**Кратко:** ответили {meta['ok']} из {meta['total']} источников; "
             f"найдено ссылок/профилей: {meta['links_total']}.", "", "## Находки"]
    any_find = False
    for r in results:
        if not r.get("ok"):
            continue
        name = r.get("name", r["server"])
        links = report.extract_links(r.get("text", "") or "")
        if links:
            any_find = True
            top = ", ".join(f"[{lab or 'ссылка'}]({url})" for lab, url in links[:8])
            more = f" … и ещё {len(links) - 8}" if len(links) > 8 else ""
            lines.append(f"- **{name}** — {len(links)} ссылок: {top}{more}")
        else:
            snip = " ".join(_clean(r.get("text", "") or "").split())[:220]
            if snip:
                any_find = True
                lines.append(f"- **{name}**: {snip}")
    if not any_find:
        lines.append("- Значимых находок нет.")
    lines += ["", "_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._"]
    return "\n".join(lines)


async def synthesize(task: str, results: list[dict]) -> str:
    """LLM-сводка поверх сырых результатов; при сбое — детерминированный шаблон."""
    template = render_report(task, results)
    payload = [{"server": r.get("name", r["server"]), "ok": r["ok"], "text": r["text"][:1500]}
               for r in results]
    out = await llm([
        {"role": "system", "content": "Ты OSINT-аналитик. Собери отчёт СТРОГО по схеме "
         "(Цель/Инструменты, ## Находки, ## Источники, ## Уверенность) на русском. "
         "Используй ТОЛЬКО данные из результатов, ничего не выдумывай; недоступные "
         "источники помечай как недоступные."},
        {"role": "user", "content": f"Задача: {task}\nРезультаты: "
         f"{json.dumps(payload, ensure_ascii=False)}\n\nШаблон для ориентира:\n{template}"}],
        max_tokens=1200)
    return out.strip() if out and "##" in out else template


# --------------------------------- tools -----------------------------------
@mcp.tool()
async def investigate(task: str) -> str:
    """Провести OSINT-расследование по задаче: подобрать источники, опросить их и
    вернуть готовое досье. Передай текст запроса пользователя (username, домен, IP,
    компанию/ИНН, хеш/URL или свободное описание)."""
    if not CATALOG:
        return "Оркестратор: каталог серверов не загружен."
    # Этический гейт — до любых вызовов источников.
    harm = recipes.harm_notice(task)
    if harm:
        return harm
    # «Что ты умеешь» — это про каталог, а не про веб-поиск.
    if recipes.RE_META.search(task):
        return catalog_text()
    plan = build_plan(task)
    # Телефон/криптокошелёк/ФИО: серверов под них нет. Честно говорим об этом,
    # вместо общего веб-поиска, который выдаст правдоподобный мусор.
    notice = recipes.unsupported_notice(task)
    if notice and all(t["type"] == "query" for t in plan["targets"]):
        return notice
    if not plan["steps"]:
        return f"Не удалось определить источники для задачи: {task}"
    # Запускаем все опросы параллельно с мягким дедлайном.
    task_map = {asyncio.ensure_future(run_one(st["server"], st["target"])): st
                for st in plan["steps"]}
    done, pending = await asyncio.wait(task_map, timeout=SOFT_DEADLINE)
    results = [t.result() for t in done]
    for t in pending:
        st = task_map[t]
        t.cancel()
        results.append({"server": st["server"], "name": st["name"], "ok": False,
                        "text": "источник не успел ответить в срок"})
    reclassify(results)
    # Полный структурированный отчёт → файлы .md/.pdf (в них — почти все данные
    # инструментов со ссылками). В чат возвращаем краткую сводку + ссылки на файлы,
    # чтобы главный агент не потерял детали при пересказе.
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        info = await asyncio.to_thread(
            report.save_report, task, results, when, REPORTS_DIR, REPORTS_URL_BASE)
    except Exception as e:
        # Если сохранение отчёта упало — отдаём детерминированный отчёт как раньше.
        return render_report(task, results) + f"\n\n_(отчёт-файл не создан: {type(e).__name__})_"
    return render_chat_summary(task, results, info)


@mcp.tool()
async def plan(task: str) -> str:
    """Показать, какие источники будут задействованы под задачу, БЕЗ запуска."""
    harm = recipes.harm_notice(task)
    if harm:
        return harm
    if recipes.RE_META.search(task):
        return catalog_text()
    p = build_plan(task)
    notice = recipes.unsupported_notice(task)
    if notice and all(t["type"] == "query" for t in p["targets"]):
        return notice
    tg = ", ".join(f"{t['type']}={t['value']}" for t in p["targets"])
    steps = "\n".join(f"- {s['name']} ← {s['target']['type']}:{s['target']['value']}"
                      for s in p["steps"]) or "- (нет подходящих серверов)"
    return f"Цели: {tg}\n\nБудут опрошены:\n{steps}"


@mcp.tool()
async def catalog() -> str:
    """Список доступных OSINT-источников по категориям (что умеет система)."""
    return catalog_text()


@mcp.tool()
async def call_server(server_id: str, tool: str, arguments: dict) -> str:
    """Прямой вызов конкретного инструмента конкретного сервера (escape hatch)."""
    it = CATALOG.get(server_id)
    if not it:
        return f"Неизвестный сервер: {server_id}. Доступные: {', '.join(CATALOG)}"
    try:
        res = await asyncio.wait_for(MCPClient(it["endpoint"]).call(tool, arguments or {}),
                                     timeout=CALL_TIMEOUT)
    except Exception as e:
        return f"Ошибка вызова {server_id}.{tool}: {type(e).__name__}"
    return res["text"] or ("ok (пусто)" if res["ok"] else "ошибка")


if __name__ == "__main__":
    mcp.run()
