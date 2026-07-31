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
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

import dossier
import recipes
import report
from mcp_client import MCPClient

CATALOG_PATH = Path(os.environ.get("CATALOG_PATH", "/app/catalog.json"))
LITELLM_BASE = os.environ.get("LITELLM_BASE_URL", "http://litellm:4000/v1")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
MODEL = os.environ.get("ORCHESTRATOR_MODEL", "GigaChat-2-Pro")
# Модель для НАПИСАНИЯ отчёта-досье (синтез). Отделена от MODEL (маршрутизация),
# чтобы писателя можно было усилить независимо: GigaChat сейчас → DeepSeek →
# Claude/GPT позже, сменой ОДНОЙ переменной, без правки кода.
REPORT_MODEL = os.environ.get("ORCHESTRATOR_REPORT_MODEL", MODEL)
# Глубокое досье по домену/IP (веер VT-связей + RDAP/crt.sh/DNS/GLEIF/Censys).
DOMAIN_DEEP = os.environ.get("ORCHESTRATOR_DOMAIN_DEEP", "1") not in ("0", "false", "")
# Сколько VT-связей звать (free-тариф ~4 req/min; платный ключ — можно поднять).
# 5 = все связи (resolutions/subdomains/historical_ssl/communicating_files/historical_whois).
VT_REL_CAP = int(os.environ.get("ORCHESTRATOR_VT_RELATIONSHIPS", "5"))
# Сколько доменов компании доразведывать инфраструктурным веером (каждый ~11 шагов).
# 1, а не 2-3: бюджет запросов конечен (VT free — 4 req/min), и размазывание веера
# по нескольким доменам оставляло ГЛАВНЫЙ домен без IP/сертификатов/поддоменов.
# Лучше одно глубокое досье, чем три поверхностных.
COMPANY_DOMAINS_CAP = int(os.environ.get("ORCHESTRATOR_COMPANY_DOMAINS", "1"))
PER_TARGET = int(os.environ.get("ORCHESTRATOR_PER_TARGET", "3"))
CALL_TIMEOUT = float(os.environ.get("ORCHESTRATOR_CALL_TIMEOUT", "25"))
# Персональные таймауты. Быстрые API режем на 25с; медленным docker-run/sherlock
# (maigret/openosint) даём дожить (иначе орк. режет вызов на полпути и оставляет
# запущенный docker-контейнер — утечка памяти).
SERVER_TIMEOUT: dict[str, float] = {"maigret": 85, "openosint": 75}
# Мягкий дедлайн всего расследования: собираем то, что успело; остальное
# помечаем «не успел», чтобы один медленный сервер не подвешивал investigate.
# 150с: холодный старт maigret (~77с) + веер VirusTotal, который на free-тарифе
# отдаёт 4 запроса/мин (6 VT-вызовов на домен ≈ 90с только на VT). На 90с
# VT-связи не успевали, и в досье пропадали IP/сертификаты/поддомены/репутация.
SOFT_DEADLINE = float(os.environ.get("ORCHESTRATOR_SOFT_DEADLINE", "150"))
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
async def llm(messages: list[dict], max_tokens: int = 900,
              model: str | None = None) -> str | None:
    """Вызов LiteLLM. None при любой ошибке (graceful fallback на правила).
    model=None → маршрутизирующая MODEL; для синтеза отчёта передаём REPORT_MODEL."""
    if not LITELLM_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(f"{LITELLM_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                json={"model": model or MODEL, "messages": messages,
                      "max_tokens": max_tokens, "temperature": 0.2})
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


async def run_one(sid: str, target: dict,
                  pinned_tool: str | None = None,
                  pinned_args: dict | None = None) -> dict:
    """Выполнить один вызов сервера под цель. Возвращает запись результата.
    Если заданы pinned_tool/pinned_args (глубокий веер) — зовём их напрямую,
    минуя CURATED/generic-подбор."""
    it = CATALOG.get(sid)
    if not it:
        return {"server": sid, "ok": False, "text": "нет в каталоге"}
    endpoint = it["endpoint"]
    if pinned_tool is not None:
        tool, args = pinned_tool, dict(pinned_args or {})
    else:
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


def _deep_label(sid: str, tool: str, args: dict) -> str:
    """Читаемое имя шага глубокого веера (несколько вызовов одного сервера)."""
    base = CATALOG.get(sid, {}).get("display_name", sid)
    rel = args.get("relationship")
    if rel:
        return f"{base} · {rel}"
    if sid == "directapi":
        return f"{base} · {tool}"
    return base


def _steps_from_specs(tg: dict, specs: list[tuple[str, str, dict]]) -> list[dict]:
    """Превратить (server, tool, args)-спеки в шаги плана; отбросить серверы,
    которых нет в каталоге (ключ не введён / сервер не поднят)."""
    steps = []
    for sid, tool, args in specs:
        if sid not in CATALOG:
            continue
        steps.append({"target": tg, "server": sid, "tool": tool, "args": args,
                      "name": _deep_label(sid, tool, args)})
    return steps


def _deep_steps(tg: dict) -> list[dict]:
    """Прикреплённые шаги глубокого досье для домена/IP (обходит лимит CURATED)."""
    if tg["type"] == "domain":
        specs = recipes.deep_domain_steps(tg["value"], VT_REL_CAP)
    else:
        specs = recipes.deep_ip_steps(tg["value"], VT_REL_CAP)
    return _steps_from_specs(tg, specs)


def _company_steps(tg: dict) -> list[dict]:
    """Корпоративный слой досье по компании (юр. идентичность, структура, лица,
    санкции). Инфраструктурный слой (домены) добавляется в investigate после
    резолвинга доменов компании."""
    return _steps_from_specs(tg, recipes.deep_company_steps(tg["value"]))


def build_plan(task: str) -> dict:
    targets = recipes.detect_targets(task)
    if not targets:
        targets = [{"type": "query", "value": task.strip()}]
    steps = []
    for tg in targets:
        # Домен/IP в авто-режиме → глубокий веер (как в референс-досье).
        if DOMAIN_DEEP and tg["type"] in ("domain", "ip"):
            steps.extend(_deep_steps(tg))
            continue
        # Компания → корпоративный слой (домены доразведываются в investigate).
        if DOMAIN_DEEP and tg["type"] == "company":
            steps.extend(_company_steps(tg))
            continue
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


# Явный признак УСПЕШНОГО ответа API. Если он есть — не объявляем сбой по
# косвенным приметам. Пример: Checko на бесплатном дневном лимите отдаёт
# {"status":"ok", ..., "balance":0.0} с пустым списком записей (иностранная
# компания просто не в реестре РФ) — это НЕ «нужен баланс», а корректный ответ.
_OK_MARKERS = ('"status": "ok"', '"status":"ok"', '"success": true', '"success":true')


def _fail_reason(text: str) -> str | None:
    low = (text or "").lower()
    if any(m in low for m in _OK_MARKERS):
        return None
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


_DOSSIER_SYSTEM = (
    "Ты — старший OSINT-аналитик. По СЫРЫМ данным источников напиши связное "
    "аналитическое досье на русском в Markdown — как профессиональный отчёт по "
    "инфраструктуре и организации, а не список «сервер → ответ».\n\n"
    "СТРУКТУРА (включай только те разделы, под которые есть данные):\n"
    "1. **Резюме** — 3–5 предложений: что за цель, ключевые выводы.\n"
    "2. **Организация** — юр. название, адрес, юрисдикция, рег. номер, статус, "
    "связи (материнская/дочерние) — если есть данные реестра (GLEIF/checko).\n"
    "3. **Сетевая инфраструктура** — таблицы: регистрация домена (WHOIS/RDAP: "
    "регистратор, даты, NS, статусы); IP/диапазоны/AS/организация; SSL-сертификаты; "
    "пассивный DNS (домены на адресах). Группируй по диапазонам IP, где уместно.\n"
    "4. **Поддомены** — сведи из всех источников (crt.sh, subfinder, VT, Censys), "
    "убери дубли, СГРУППИРУЙ ПО ФУНКЦИИ (почта, SSO/аутентификация, мониторинг, "
    "ERP/бизнес-приложения, VPN, прочее) по именам.\n"
    "5. **Почтовая безопасность** — разбор SPF и DMARC: приведи записи и объясни, "
    "что политика значит (напр. p=reject — строгая; -all — жёсткий SPF).\n"
    "6. **Угрозы/репутация** — вредоносные/общающиеся файлы, репутация (VirusTotal).\n"
    "7. **Выводы** — 3–6 пунктов: наблюдения аналитика (без домыслов).\n\n"
    "ЖЁСТКИЕ ПРАВИЛА ПРОТИВ ВЫДУМЫВАНИЯ (критично):\n"
    "- Бери ТОЛЬКО то, что буквально есть в данных. Если поля нет — пиши «нет "
    "данных», НЕ придумывай.\n"
    "- ЗАПРЕЩЕНО придумывать имена регистраторов, удостоверяющих центров (CA), "
    "эмитентов сертификатов, версии TLS, «оценки безопасности», IP, поддомены, "
    "даты, если их НЕТ в источниках. Приводи имя CA/регистратора ровно как в "
    "данных (напр. issuer из VirusTotal), иначе — «нет данных».\n"
    "- Недоступные источники («нужен ключ», таймаут) НЕ упоминай — просто опусти.\n"
    "- Оформляй таблицы Markdown; не пересказывай сырой JSON дословно — извлекай "
    "значения в таблицы/прозу.")


async def synthesize_dossier(task: str, targets: list[dict],
                             results: list[dict]) -> str | None:
    """Аналитическое досье (Markdown) из сырых данных через REPORT_MODEL.
    None → писателя нет/сбой, отчёт соберётся детерминированно (report.py)."""
    ok = [r for r in results if r.get("ok") and (r.get("text") or "").strip()
          not in ("", "пусто")]
    if not ok:
        return None  # нечего синтезировать — пусть шаблон честно скажет «находок нет»
    payload = [{"источник": r.get("name", r["server"]), "инструмент": r.get("tool", "?"),
                "данные": (r.get("text") or "")[:3500]} for r in ok]
    tg = ", ".join(f"{t['type']}={t['value']}" for t in targets)
    out = await llm([
        {"role": "system", "content": _DOSSIER_SYSTEM},
        {"role": "user", "content": f"Задача: {task}\nЦели: {tg}\n\n"
         f"СЫРЫЕ ДАННЫЕ ИСТОЧНИКОВ (JSON):\n"
         f"{json.dumps(payload, ensure_ascii=False)}"}],
        max_tokens=4000, model=REPORT_MODEL)
    # Требуем непустой Markdown с разделами; иначе — фолбэк на детерминированный.
    return out.strip() if out and "#" in out and len(out.strip()) > 200 else None


_NARRATIVE_SYSTEM = (
    "Ты — старший OSINT-аналитик. Тебе дают УЖЕ ИЗВЛЕЧЁННЫЕ структурированные факты "
    "по домену (организация, WHOIS, IP/сети, поддомены по функциям, сертификаты, "
    "SPF/DMARC, репутация). Напиши на русском ДВА раздела к досье:\n"
    "1) executive-резюме (4–7 предложений): что за организация/домен, масштаб "
    "инфраструктуры (сколько IP/поддоменов/сертификатов), ключевые наблюдения.\n"
    "2) выводы аналитика (5–8 пунктов): интерпретация — что говорит SPF/DMARC-политика, "
    "о чём свидетельствует набор поддоменов (напр. наличие SSO/VPN/ERP/мониторинга), "
    "распределение по сетям/AS, риски и заметные факты.\n"
    "Опирайся ТОЛЬКО на переданные факты, НИЧЕГО не выдумывай (ни имён, ни чисел). "
    "Верни СТРОГО JSON: {\"summary\": \"...\", \"conclusions\": \"- ...\\n- ...\"}.")


def _as_lines(v) -> str:
    """LLM может вернуть список пунктов или строку — приводим к markdown-строке
    (иначе список печатается как питоновский repr ['- ...'])."""
    if isinstance(v, list):
        return "\n".join(str(x).strip() for x in v if str(x).strip())
    return str(v or "").strip()


async def synthesize_narrative(domain: str, compact: dict) -> tuple[str, str]:
    """LLM пишет резюме + выводы по КОМПАКТНЫМ извлечённым фактам. ('','') при сбое."""
    out = await llm([
        {"role": "system", "content": _NARRATIVE_SYSTEM},
        {"role": "user", "content": f"ФАКТЫ по {domain} (JSON):\n"
         f"{json.dumps(compact, ensure_ascii=False)}"}],
        max_tokens=1800, model=REPORT_MODEL)
    j = _json_from(out or "")
    if j and (j.get("summary") or j.get("conclusions")):
        return _as_lines(j.get("summary")), _as_lines(j.get("conclusions"))
    # Не JSON, но что-то есть — положим всё в резюме.
    return (out.strip() if out else ""), ""


async def build_domain_dossier(domain: str, results: list[dict]) -> str | None:
    """Глубокое досье по домену: детерминированные таблицы данных + LLM-нарратив.
    None → нет значимых данных (тогда отчёт соберётся детерминированно)."""
    data = dossier.extract_domain_data(results)
    sections, counts = dossier.render_sections(domain, data)
    if not sections:
        return None
    summary, conclusions = await synthesize_narrative(
        domain, dossier.data_for_llm(domain, data))
    md = [f"# Аналитическое досье по домену {domain}", ""]
    if summary:
        md += ["## Резюме", "", summary, ""]
    else:
        md += [f"## Резюме", "",
               f"Собрано: поддоменов — {counts['subdomains']}, IP-адресов — "
               f"{counts['ips']}, сертификатов — {counts['certs']}.", ""]
    md += sections
    if conclusions:
        md += ["## Выводы", "", conclusions, ""]
    return "\n".join(md)


_COMPANY_NARRATIVE_SYSTEM = (
    "Ты — старший OSINT-аналитик. Тебе дают УЖЕ ИЗВЛЕЧЁННЫЕ факты по компании "
    "(юр. идентичность и связи из GLEIF, должностные лица, домены и их "
    "инфраструктура: поддомены по функциям, IP/сети, сертификаты, почтовая "
    "политика, живые сервисы Shodan, репутация). Напиши по-русски и верни СТРОГО JSON:\n"
    '{"summary": "...", "conclusions": "- ...\\n- ...", "assumptions": "- ...", '
    '"checks": "- ..."}\n'
    "- summary — executive-резюме (4–7 предложений): что за компания, юрисдикция, "
    "масштаб группы (материнская/дочерние), масштаб инфраструктуры (домены/поддомены/IP).\n"
    "- conclusions — выводы аналитика (5–8 пунктов): что говорит SPF/DMARC-политика, "
    "о чём свидетельствует набор поддоменов (SSO/VPN/ERP/мониторинг), распределение по "
    "сетям/облакам, заметные живые сервисы и риски.\n"
    "- assumptions — обоснованные предположения (2–4 пункта), явно помеченные как гипотезы.\n"
    "- checks — что стоит проверить дальше (пассивно), 3–5 пунктов.\n"
    "ЖЁСТКО: опирайся ТОЛЬКО на переданные факты. НЕ выдумывай имён, чисел, доменов, "
    "дат. Если данных мало — пиши коротко и честно. Санкции/негатив утверждай лишь при "
    "наличии в фактах.")


async def synthesize_company_narrative(name: str, cdata: dict,
                                       infra: list[dict]) -> tuple[str, str, str, str]:
    """LLM пишет резюме/выводы/предположения/проверки по КОМПАКТНЫМ фактам компании.
    Возвращает ('','','','') при сбое (тогда используем детерминированное резюме)."""
    compact = dossier.company_data_for_llm(name, cdata, infra)
    out = await llm([
        {"role": "system", "content": _COMPANY_NARRATIVE_SYSTEM},
        {"role": "user", "content": f"ФАКТЫ по компании {name} (JSON):\n"
         f"{json.dumps(compact, ensure_ascii=False)}"}],
        max_tokens=2200, model=REPORT_MODEL)
    j = _json_from(out or "")
    if j and (j.get("summary") or j.get("conclusions")):
        return (_as_lines(j.get("summary")), _as_lines(j.get("conclusions")),
                _as_lines(j.get("assumptions")), _as_lines(j.get("checks")))
    return (out.strip() if out else "", "", "", "")


def _domain_results(results: list[dict], domain: str) -> list[dict]:
    """Результаты, относящиеся к конкретному домену (+ общие reverse-RDAP по IP,
    которые не привязаны к домену, но нужны для таблицы сетей)."""
    out = []
    for r in results:
        tv = r.get("target_value")
        if (tv is None or tv == domain
                or (r.get("server") == "directapi" and r.get("tool") == "rdap_ip")):
            out.append(r)
    return out


async def resolve_company_domains(task: str, company: str,
                                  existing: set[str]) -> list[str]:
    """Домены компании: LLM-кандидаты + эвристика, ПРОВЕРЕННЫЕ резолвингом.
    Возвращает только реально резолвящиеся НОВЫЕ домены (не выдумывает)."""
    cands: list[str] = []
    ans = await llm([
        {"role": "system", "content": "Верни ТОЛЬКО домены официальных сайтов компании "
         "через запятую (напр. example.com, example.es), без пояснений. Не уверен — пусто."},
        {"role": "user", "content": f"Компания: {company}. Контекст: {task}"}],
        max_tokens=120)
    if ans:
        cands += re.findall(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,}", ans.lower())
    cands += recipes.company_domain_candidates(company)
    seen, uniq = set(existing), []
    for c in cands:
        c = c.strip(". ")
        if c and c not in seen:
            seen.add(c)
            uniq.append(c)
    if not uniq:
        return []
    checks = {asyncio.ensure_future(
        run_one("directapi", {"type": "domain", "value": c}, "dns_records", {"domain": c})): c
        for c in uniq[:10]}
    done, pending = await asyncio.wait(checks, timeout=20)
    for t in pending:
        t.cancel()
    ok_domains = set()
    for t in done:
        c = checks[t]
        try:
            r = t.result()
        except Exception:
            continue
        j = _json_from(r.get("text", "") or "") if r.get("ok") else None
        if j and (j.get("A") or j.get("NS")):
            ok_domains.add(c)
    return [c for c in uniq if c in ok_domains][:COMPANY_DOMAINS_CAP]


async def build_company_dossier(name: str, domains: list[dict | str],
                                results: list[dict]) -> str | None:
    """Глубокое досье по компании: корпоративный слой (GLEIF/officers/структура) +
    инфраструктура каждого домена (детерминированные таблицы) + LLM-нарратив.
    None → нет значимых данных (тогда отчёт соберётся общим синтезом)."""
    cdata = dossier.extract_company_data(results)
    org_sections = dossier.render_company_sections(name, cdata)
    dom_values = [d["value"] if isinstance(d, dict) else d for d in domains]
    infra_md: list[str] = []
    infra_facts: list[dict] = []
    for d in dict.fromkeys(dom_values):
        ddata = dossier.extract_domain_data(_domain_results(results, d))
        dsections, counts = dossier.render_sections(d, ddata)
        if dsections:
            infra_md += [f"## Инфраструктура домена {d}", ""]
            infra_md += dossier._mermaid_dns_topology(d, ddata.get("dns")) + [""]
            infra_md += dsections
            facts = dossier.data_for_llm(d, ddata)
            infra_facts.append({k: facts[k] for k in (
                "domain", "ip_count", "subdomain_count", "cert_count",
                "subdomain_groups", "mail", "reputation", "shodan_ports") if k in facts})
    if not org_sections and not infra_md:
        return None
    summary, conclusions, assumptions, checks = await synthesize_company_narrative(
        name, cdata, infra_facts)
    md = [f"# Аналитическое досье по компании {name}", ""]
    if summary:
        md += ["## Резюме", "", summary, ""]
    else:
        subs = sum(f.get("subdomain_count", 0) for f in infra_facts)
        ips = sum(f.get("ip_count", 0) for f in infra_facts)
        md += ["## Резюме", "",
               f"Компания «{name}». Доменов исследовано: {len(infra_facts)}; "
               f"поддоменов — {subs}, IP-адресов — {ips}.", ""]
    md += org_sections
    md += infra_md
    if conclusions:
        md += ["## Выводы", "", conclusions, ""]
    if assumptions:
        md += ["## Предположения", "", assumptions, ""]
    if checks:
        md += ["## Для проверки (пассивно)", "", checks, ""]
    md += dossier.render_limitations(results, CATALOG)
    return "\n".join(md)


async def enrich_reverse_ip(results: list[dict], limit: int = 12) -> list[dict]:
    """Вторая волна: RDAP по уникальным IP из пассивного DNS/A — для таблицы сетей/AS."""
    if "directapi" not in CATALOG:
        return []
    data = dossier.extract_domain_data(results)
    ips = [ip for ip in (data.get("ips") or {}) if "." in ip][:limit]
    if not ips:
        return []
    tasks = [asyncio.ensure_future(
        run_one("directapi", {"type": "ip", "value": ip}, "rdap_ip", {"ip": ip}))
        for ip in ips]
    done, pending = await asyncio.wait(tasks, timeout=25)
    out = [t.result() for t in done]
    for t in pending:
        t.cancel()
    return out


async def enrich_officers(results: list[dict], company: str) -> list[dict]:
    """Вторая волна: должностные лица по ЮРИДИЧЕСКОМУ имени и юрисдикции из GLEIF.
    Так мы не путаем одноимённые регистрации в разных странах (ES vs ca_qc)."""
    if "directapi" not in CATALOG:
        return []
    g = (dossier.extract_company_data(results).get("gleif") or {})
    name = g.get("legal_name") or company
    args: dict = {"query": name}
    jur = (g.get("jurisdiction") or "").strip().lower()
    if jur:
        args["jurisdiction"] = jur
    r = await run_one("directapi", {"type": "company", "value": company},
                      "opencorporates_officers", args)
    r["target_value"], r["target_type"] = company, "company"
    return [r]


async def enrich_webcontent(results: list[dict], domain: str) -> list[dict]:
    """Вторая волна: забрать контент сайта (Bright Data) — главную + типовые
    страницы «о компании/контакты». Из него детерминированно извлекаются внешние
    связи: почтовые домены, упоминания партнёров/владельцев/ГК (см. dossier).
    Именно так системный отчёт показывает, например, дилерскую связь."""
    if "brightdata" not in CATALOG:
        return []
    paths = ["/", "/kontakty/", "/kontakt/o-kompani/", "/o-kompanii/", "/about/"]
    tasks = [asyncio.ensure_future(
        run_one("brightdata", {"type": "url", "value": f"https://{domain}{p}"},
                "scrape_as_markdown", {"url": f"https://{domain}{p}"}))
        for p in paths]
    done, pending = await asyncio.wait(tasks, timeout=45)
    out = []
    for t in done:
        r = t.result()
        # берём только реально загруженные непустые страницы
        if r.get("ok") and len(r.get("text") or "") > 200:
            r["target_value"], r["target_type"] = domain, "domain"
            out.append(r)
    for t in pending:
        t.cancel()
    return out


async def enrich_shodan(results: list[dict], domain: str, limit: int = 4) -> list[dict]:
    """Вторая волна: Shodan по IP домена → таблица живых активов (порты/сервисы/баннеры),
    как Table 25 референс-отчёта. Результаты помечаем доменом, чтобы они попали в его
    секцию (а не дублировались по всем доменам)."""
    if "shodan" not in CATALOG:
        return []
    data = dossier.extract_domain_data(_domain_results(results, domain))
    ips = [ip for ip in (data.get("ips") or {}) if "." in ip][:limit]
    if not ips:
        return []
    tasks = [asyncio.ensure_future(
        run_one("shodan", {"type": "ip", "value": ip}, "ip_lookup", {"ip": ip}))
        for ip in ips]
    done, pending = await asyncio.wait(tasks, timeout=30)
    out = []
    for t in done:
        r = t.result()
        r["target_value"] = domain
        r["target_type"] = "domain"
        out.append(r)
    for t in pending:
        t.cancel()
    return out


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
    # Компания → доразведать её домены и добавить инфраструктурный веер (как в
    # референс-досье: юр. слой + сеть/поддомены/сертификаты по доменам компании).
    primary_company = next((t["value"] for t in plan["targets"]
                            if t["type"] == "company"), None)
    if primary_company and DOMAIN_DEEP:
        have = {t["value"] for t in plan["targets"] if t["type"] == "domain"}
        # Домен назван пользователем — доверяем ему и идём вглубь ПО НЕМУ, не
        # размывая бюджет запросов на угаданные родственные домены.
        if not have:
            for d in await resolve_company_domains(task, primary_company, have):
                dtg = {"type": "domain", "value": d}
                plan["targets"].append(dtg)
                plan["steps"].extend(_deep_steps(dtg))
    if not plan["steps"]:
        return f"Не удалось определить источники для задачи: {task}"
    # Запускаем все опросы параллельно с мягким дедлайном. Глубокие шаги несут
    # прикреплённые tool/args (несколько вызовов одного сервера).
    task_map = {asyncio.ensure_future(
                    run_one(st["server"], st["target"],
                            st.get("tool"), st.get("args"))): st
                for st in plan["steps"]}
    done, pending = await asyncio.wait(task_map, timeout=SOFT_DEADLINE)
    results = []
    for t in done:
        st = task_map[t]
        r = t.result()
        r.setdefault("target_value", st["target"].get("value"))
        r.setdefault("target_type", st["target"].get("type"))
        results.append(r)
    for t in pending:
        st = task_map[t]
        t.cancel()
        results.append({"server": st["server"], "name": st["name"], "ok": False,
                        "text": "источник не успел ответить в срок",
                        "target_value": st["target"].get("value"),
                        "target_type": st["target"].get("type")})
    reclassify(results)
    # Компания: вторая волна — руководство по юр. имени/юрисдикции из GLEIF.
    if primary_company and DOMAIN_DEEP:
        results += await enrich_officers(results, primary_company)
        reclassify(results)
    # Для домена: вторая волна reverse-RDAP по IP из пассивного DNS → таблица сетей/AS.
    primary_domain = next((t["value"] for t in plan["targets"]
                           if t["type"] == "domain"), None)
    if primary_domain and DOMAIN_DEEP:
        results += await enrich_reverse_ip(results)
        reclassify(results)
        # Живые активы (Shodan) для основного домена → таблица портов/сервисов.
        results += await enrich_shodan(results, primary_domain)
        reclassify(results)
        # Контент сайта → внешние связи (почтовые домены, партнёры/владельцы).
        results += await enrich_webcontent(results, primary_domain)
        reclassify(results)
    # Синтез. Компания → досье (корпоративный слой + инфраструктура доменов); домен →
    # глубокое досье; прочее → общий LLM-синтез. При сбое — None → отчёт строится
    # детерминированно (как раньше).
    if primary_company and DOMAIN_DEEP:
        company_domains = [t["value"] for t in plan["targets"] if t["type"] == "domain"]
        synthesis = await build_company_dossier(primary_company, company_domains, results)
        if synthesis is None:
            synthesis = await synthesize_dossier(task, plan["targets"], results)
    elif primary_domain and DOMAIN_DEEP:
        synthesis = await build_domain_dossier(primary_domain, results)
    else:
        synthesis = await synthesize_dossier(task, plan["targets"], results)
    # Полный структурированный отчёт → файлы .md/.pdf (синтез сверху + сырые данные
    # приложением). В чат возвращаем краткую сводку + ссылки на файлы.
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        info = await asyncio.to_thread(
            report.save_report, task, results, when, REPORTS_DIR, REPORTS_URL_BASE,
            synthesis)
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
