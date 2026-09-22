"""Сборка структурированного OSINT-отчёта (Markdown + PDF) из ответов серверов.

Задача: сохранить почти всю информацию инструментов (ссылки, детали), но
разложить её по секциям — вместо того, чтобы главный агент сжимал всё в пару
строк. Markdown пишется всегда; PDF — best-effort (weasyprint), при сбое молча
пропускается.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from functools import lru_cache
from pathlib import Path

# «[+] Label: https://url» — формат maigret/openosint и подобных.
_PLUS_LINK = re.compile(r"\[\+\]\s*(.+?):\s*(https?://[^\s\\]+)")
# ВАЖНО: обратный слэш исключён из класса. Ответы источников — это чаще всего JSON,
# и перевод строки внутри строки JSON закодирован ДВУМЯ символами «\» + «r»/«n», а
# не реальным пробелом. Без запрета на «\» regex проезжал сквозь HTTP-баннер Shodan
# и рождал «https://1.2.3.4/\r\nContent-Type:» — ссылку, которой не существует.
_BARE_URL = re.compile(r"https?://[^\s\\)\]\}<>\"'`]+")
_NOISE = ("[*]", "[♥]", "[!]", "[-]", "[i]", "Searching |", "Donate", "Support ")
# Режим приложения: slim (по умолчанию) не дублирует разобранное в таблицы сырьё,
# full — прежнее поведение (полное сырьё для аудита), off — без приложения.
APPENDIX_MODE = os.environ.get("ORCHESTRATOR_APPENDIX", "slim")

# Хосты, которые НЕ являются находкой: XML-неймспейсы, CSP-источники, аналитика и
# CDN. Они попадают в текст как часть заголовков/разметки цели, а не как след цели.
_NOISE_HOSTS = (
    "w3.org", "schemas.xmlsoap.org", "schemas.openxmlformats.org", "purl.org",
    "ns.adobe.com", "iptc.org", "www.w3.org",
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "gstatic.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "icann.org",           # epp-статусы из WHOIS — служебные якоря, не находка
)
# Служебные API-эндпоинты. Это следы НАШИХ запросов, а не находки по цели:
# self-link GLEIF, форма SEC, RDAP-сервер регистратора, CT-лог. Раньше они
# считались «профилями» и составляли половину «находок» в сводке.
_API_HOSTS = (
    "api.gleif.org", "data.sec.gov", "www.sec.gov", "sec.gov",
    "crt.sh", "api.crt.sh", "rdap.verisign.com", "rdap.org",
    "api.opencorporates.com", "opencorporates.com/companies",
    "wikipedia.org/w/api.php", "google.serper.dev",
)
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _valid_link(url: str) -> bool:
    """Ссылка ли это на самом деле. Отсекает мусор, который порождают CSP-заголовки
    (`https://*.example.com`), XML-неймспейсы, обрывки HTTP-баннеров и служебные
    API-эндпоинты самих источников."""
    # Обрывок баннера: «https://1.2.3.4/\r\nContent-Type: …» — экранированный
    # перевод строки приезжает внутри JSON двумя символами и склеивает заголовок
    # со ссылкой. Такой «ссылки» не существует.
    if any(bad in url for bad in ("\\r", "\\n", "\r", "\n", "*", ";", " ")):
        return False
    if any(a in url for a in _API_HOSTS):
        return False
    host = url.split("://", 1)[-1]
    host = re.split(r"[/?#]", host, maxsplit=1)[0].split("@")[-1].split(":")[0].lower()
    if not host or "*" in host or "." not in host:
        return False
    # Голый IP — это адрес из скана, а не найденный ресурс цели.
    if _IP_HOST_RE.match(host):
        return False
    if not _HOST_RE.match(host):
        return False
    if not re.search(r"\.[a-z]{2,}$", host):
        return False
    return not any(host == h or host.endswith("." + h) for h in _NOISE_HOSTS)


def _looks_json(text: str) -> bool:
    t = text.strip()
    return t.startswith("{") or t.startswith("[")


def _clean_lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith(_NOISE)]


def extract_links(text: str) -> list[tuple[str, str]]:
    """Список (label, url). Сначала '[+] Label: url', затем голые ссылки.
    ЕДИНСТВЕННОЕ место извлечения ссылок — и отчёт, и сводка в чат считают по нему,
    поэтому цифры в шапке и в теле больше не расходятся."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for label, url in _PLUS_LINK.findall(text):
        url = url.rstrip(".,);'\"")
        if url not in seen and _valid_link(url):
            seen.add(url)
            out.append((label.strip(), url))
    for url in _BARE_URL.findall(text):
        url = url.rstrip(".,);'\"")
        if url not in seen and _valid_link(url):
            seen.add(url)
            out.append(("", url))
    return out


def count_links(results: list[dict]) -> int:
    """Сколько РАЗНЫХ ссылок нашли все успешные источники вместе.

    Раньше счёт вёлся в трёх местах по-разному: `_source_section` возвращал 0 для
    любого JSON-ответа, сводка в чат считала его же ссылки, а фолбэк-сводка — по
    третьему правилу. Отсюда «найдено ссылок/профилей: 0» в шапке при десятках
    ссылок ниже. Теперь счёт один и он же дедуплицирует ссылки МЕЖДУ источниками."""
    seen: set[str] = set()
    for r in results:
        if r.get("ok"):
            seen.update(url for _, url in extract_links(r.get("text", "") or ""))
    return len(seen)


def source_matrix(results: list[dict]) -> list[dict]:
    """Свод по СЕРВЕРАМ, а не по вызовам.

    «22 из 41» — это 41 вызов к ~7 серверам, из которых 12 — один и тот же
    rdap_ip по разным IP. Такой знаменатель описывает размер веера, а не
    покрытие источниками, и в шапке отчёта выглядел как массовый провал."""
    by: dict[str, dict] = {}
    for r in results:
        sid = r.get("server", "?")
        m = by.setdefault(sid, {"server": sid, "name": r.get("name") or sid,
                                "tools": [], "calls": 0, "ok": 0, "failed": 0,
                                "reasons": []})
        # display_name сервера — без «· инструмент» из читаемой метки шага.
        base = (r.get("name") or sid).split(" · ")[0]
        m["name"] = base
        tool = r.get("tool")
        if tool and tool not in m["tools"]:
            m["tools"].append(tool)
        m["calls"] += 1
        if r.get("ok"):
            m["ok"] += 1
        else:
            m["failed"] += 1
            why = (r.get("fail_reason")
                   or re.sub(r"\s+", " ", (r.get("text") or "")).replace(
                       "источник недоступен", "").strip(" :()"))[:60]
            if why and why not in m["reasons"]:
                m["reasons"].append(why)
    return sorted(by.values(), key=lambda m: (-m["ok"], m["name"]))


def coverage(results: list[dict]) -> dict:
    """Покрытие: сколько СЕРВЕРОВ дали данные (и сколько вызовов за этим стоит)."""
    matrix = source_matrix(results)
    with_data = [m for m in matrix if m["ok"]]
    return {"servers_ok": len(with_data), "servers_total": len(matrix),
            "calls_ok": sum(m["ok"] for m in matrix),
            "calls_total": sum(m["calls"] for m in matrix),
            "ratio": (len(with_data) / len(matrix)) if matrix else 0.0}


def confidence(results: list[dict], identity: dict | None = None) -> tuple[str, str]:
    """(метка, обоснование). Считаем по ДОЛЕ СЕРВЕРОВ С ДАННЫМИ, а не по
    «успешных >= 2»: прежнее правило печатало «высокая» на прогоне, где
    отвалилось больше половины источников. Неопознанная сущность ставит потолок:
    сколько бы инфраструктуры мы ни собрали, чьё это — остаётся гипотезой."""
    cov = coverage(results)
    if cov["ratio"] >= 0.7 and cov["servers_ok"] >= 4:
        label = "высокая"
    elif cov["ratio"] >= 0.4 and cov["servers_ok"] >= 2:
        label = "средняя"
    else:
        label = "низкая"
    why = (f"серверов с данными: {cov['servers_ok']} из {cov['servers_total']} "
           f"(вызовов: {cov['calls_ok']} из {cov['calls_total']})")
    if identity is not None:
        ident_conf = identity.get("confidence") or "низкая"
        why += f"; идентификация цели — {ident_conf}"
        if not identity.get("legal_name"):
            why += " (юрлицо не подтверждено)"
        order = {"низкая": 0, "средняя": 1, "высокая": 2}
        if order.get(ident_conf, 0) < order.get(label, 0):
            label = ident_conf
    return label, why


def source_matrix_section(results: list[dict]) -> list[str]:
    """Раздел «Источники и покрытие» в ТЕЛЕ досье (как матрица инструментов в
    референс-отчёте): по какому серверу что спрашивали и что из этого вышло."""
    matrix = source_matrix(results)
    if not matrix:
        return []
    md = ["## Источники и покрытие", "",
          "| Источник | Инструменты | Вызовов | С данными | Сбоев | Причина |",
          "|---|---|---|---|---|---|"]
    for m in matrix:
        tools = ", ".join(f"`{t}`" for t in m["tools"][:6]) or "—"
        if len(m["tools"]) > 6:
            tools += f" … (+{len(m['tools']) - 6})"
        md.append(f"| {m['name']} | {tools} | {m['calls']} | {m['ok']} | "
                  f"{m['failed']} | {'; '.join(m['reasons'][:2]) or '—'} |")
    label, why = confidence(results)
    return md + ["", f"**Вывод:** полнота покрытия — {label}; {why}.", ""]


def _fmt_json(text: str) -> str:
    try:
        obj = json.loads(text)
    except Exception:
        return "```\n" + text.strip()[:6000] + "\n```"
    pretty = json.dumps(obj, ensure_ascii=False, indent=2)
    return "```json\n" + pretty[:8000] + ("\n… (обрезано)" if len(pretty) > 8000 else "") + "\n```"


# Ответы этих инструментов ПОЛНОСТЬЮ разобраны в таблицы тела досье
# (dossier.extract_* → sections). Дублировать их сырьё в приложении незачем —
# именно на этом приложение разрасталось до 71% файла.
CONSUMED: frozenset[tuple[str, str]] = frozenset({
    ("directapi", "gleif_entity"), ("directapi", "rdap_domain"),
    ("directapi", "rdap_ip"), ("directapi", "dns_records"),
    ("directapi", "crtsh"), ("directapi", "sec_edgar"),
    ("directapi", "wikipedia_summary"), ("directapi", "subdomain_ips"),
    ("directapi", "whois_history"), ("directapi", "web_inspect"),
    ("directapi", "opencorporates_officers"), ("directapi", "sec_financials"),
    # google_cse: в теле остаются ТОЛЬКО релевантные результаты + счётчик
    # отсеянных. Сырьё в приложении сводило фильтр на нет — отсеянные чужие
    # пасты, однофамильцы и заголовки-разметка всё равно ехали в файл целиком.
    ("directapi", "google_cse"),
    ("virustotal", "get_domain_relationship"), ("virustotal", "get_domain_report"),
    ("shodan", "ip_lookup"), ("checko", "search"),
})


def _source_section(r: dict, slim: bool = False) -> str:
    """Markdown-секция по одному источнику (сырьё для приложения к отчёту).
    slim=True — не дублировать ответы, уже целиком разобранные в таблицы тела."""
    name = r.get("name", r.get("server", "?"))
    tool = r.get("tool", "?")
    status = "✅ успешно" if r.get("ok") else "❌ " + (r.get("text", "недоступен")[:80])
    head = f"### {name} — `{tool}` · {status}\n"
    if not r.get("ok"):
        return head + "\n_Источник не вернул данных._\n"

    text = r.get("text", "") or ""
    # Единый счётчик: ссылки считаем ДО ветвления по формату. Раньше JSON-ветка
    # выходила досрочно и ссылок не показывала, а шапка их всё равно считала —
    # отсюда расхождение «ссылок/профилей: N» с телом отчёта.
    links = extract_links(text)
    links_line = f"\n**Найдено ссылок/профилей: {len(links)}**\n" if links else ""
    if slim and (r.get("server"), tool) in CONSUMED:
        return (head + links_line +
                "\n_Ответ полностью разобран в таблицы выше; сырьё опущено "
                "(режим приложения: slim)._\n")
    if _looks_json(text):
        return head + links_line + "\n" + _fmt_json(text) + "\n"

    body = ""
    if links:
        body += f"\n**Найдено ссылок/профилей: {len(links)}**\n\n"
        for label, url in links[:400]:
            body += f"- [{label or url}]({url})\n"
    # Полный сырой ответ (очищенный) — в свёрнутом блоке.
    raw = "\n".join(_clean_lines(text))[:12000]
    if raw:
        body += ("\n<details>\n<summary>Полный ответ инструмента</summary>\n\n```\n"
                 + raw + "\n```\n</details>\n")
    if not body.strip():
        body = "\n_Пустой ответ._\n"
    return head + body


def build_markdown(task: str, results: list[dict], when: str,
                   synthesis: str | None = None, identity: dict | None = None,
                   appendix: str = APPENDIX_MODE) -> tuple[str, dict]:
    """Полный отчёт + метаданные {links_total, ok, total, coverage, confidence}.

    synthesis (если задан) — аналитическое досье от сильной модели: идёт главным
    телом, а сырые данные источников уходят в приложение. Без синтеза — прежний
    детерминированный формат (Сводка/Подробности).

    appendix='slim' (по умолчанию) — ответы, уже полностью разобранные в таблицы
    тела, в приложении не дублируются: раньше приложение занимало 71% файла и
    построчно повторяло то, что уже показано выше."""
    matrix = source_matrix(results)
    names = ", ".join(m["name"] for m in sorted(matrix, key=lambda m: m["name"])) or "—"
    ok = [r for r in results if r.get("ok")]
    cov = coverage(results)
    conf_label, conf_why = confidence(results, identity)
    conf_icon = {"высокая": "🟢", "средняя": "🟡", "низкая": "🔴"}.get(conf_label, "⚪")
    md = [f"# OSINT-досье", "",
          f"> **Цель:** {task}",
          f"> **Дата:** {when}  ·  "
          f"**Ответили источников:** {cov['servers_ok']} из {cov['servers_total']}  ·  "
          f"**Вызовов:** {cov['calls_ok']}/{cov['calls_total']}  ·  "
          f"**Уверенность:** {conf_icon} {conf_label}",
          "", "---", ""]

    # Сырьё по источникам + ЕДИНЫЙ счётчик ссылок (см. count_links).
    source_md = [_source_section(r, slim=(appendix == "slim")) for r in results]
    links_total = count_links(results)

    if synthesis:
        # Главное тело — аналитическое досье; сырьё — в приложении.
        md += [synthesis.strip(), "", "---", "",
               "## Приложение: данные источников", "",
               "_Сырые ответы инструментов — для проверки выводов выше._", ""]
        md += source_md
    else:
        # Фолбэк без LLM: прежний детерминированный формат.
        md += ["## Сводка", ""]
        for r in results:
            if r.get("ok"):
                n = len(extract_links(r.get("text", "") or ""))
                extra = f" — {n} ссылок" if n else ""
                md.append(f"- **{r.get('name', r['server'])}**{extra}")
        if not ok:
            md.append("- Значимых находок нет (источники не вернули данных).")
        md += ["", "---", "", "## Подробности", ""]
        md += source_md

    # Поштучный список вызовов — только если нет досье (оно уже содержит таблицу
    # источников через source_matrix_section). При наличии синтеза дублировать не надо.
    if not synthesis:
        md += ["", "---", "", "## Источники и статусы", "",
               "| Источник | Инструменты | Вызовов | С данными | Сбоев | Причина |",
               "|---|---|---|---|---|---|"]
        for m in matrix:
            tools = ", ".join(f"`{t}`" for t in m["tools"][:6]) or "—"
            if len(m["tools"]) > 6:
                tools += f" … (+{len(m['tools']) - 6})"
            md.append(f"| {m['name']} | {tools} | {m['calls']} | {m['ok']} | "
                      f"{m['failed']} | {'; '.join(m['reasons'][:2]) or '—'} |")
        md += [""]

    md += ["", "<details>", "<summary>Все вызовы поштучно</summary>", "",
           "| Источник | Инструмент | Статус |", "|---|---|---|"]
    for r in results:
        st = "ok" if r.get("ok") else "недоступен"
        md.append(f"| {r.get('name', r['server'])} | {r.get('tool', '?')} | {st} |")
    md += ["", "</details>", ""]

    md += ["", "## Уверенность", "",
           f"**{conf_label}** — {conf_why}; всего найдено внешних ссылок/профилей: "
           f"{links_total}.", ""]
    return "\n".join(md), {"links_total": links_total, "ok": len(ok),
                           "total": len(results), "coverage": cov,
                           "confidence": conf_label, "confidence_why": conf_why,
                           "identity": identity}



# ── HTML-отчёт: тёмная тема по умолчанию, кнопка переключения ──────────────
# Дизайн: тёмный navy-black + teal-акцент (#0DCFAB), боковое оглавление, Mermaid.

_HTML_CSS = """\
/* === TOKENS: dark-first ========================================== */
:root {
  --bg:#090C14; --surface:#101827; --raised:#18243A; --border:#1E2C44;
  --text:#B8CEEA; --strong:#D8E8F8; --muted:#53698A;
  --accent:#0DCFAB; --accent-dim:#071F1C;
  --link:#4BA8E0; --link-h:#80C8FF;
  --code-bg:#0C1624; --th-bg:#0B1D2E; --tr-alt:#0A1320; --tr-h:#142338;
  --ok:#22C55E; --warn:#F59E0B; --err:#EF4444;
}
@media (prefers-color-scheme:light) {
  :root:not([data-theme="dark"]) {
    --bg:#F1F5FB; --surface:#FFFFFF; --raised:#F7FAFE; --border:#D8E2F0;
    --text:#293A52; --strong:#0E1D30; --muted:#5E7392;
    --accent:#0A9E82; --accent-dim:#E5F5F1;
    --link:#1862BB; --link-h:#114DA0;
    --code-bg:#EEF3FA; --th-bg:#E8F3EE; --tr-alt:#F5F8FC; --tr-h:#EAF0FA;
    --ok:#16A34A; --warn:#D97706; --err:#DC2626;
  }
}
:root[data-theme="dark"] {
  --bg:#090C14; --surface:#101827; --raised:#18243A; --border:#1E2C44;
  --text:#B8CEEA; --strong:#D8E8F8; --muted:#53698A;
  --accent:#0DCFAB; --accent-dim:#071F1C;
  --link:#4BA8E0; --link-h:#80C8FF;
  --code-bg:#0C1624; --th-bg:#0B1D2E; --tr-alt:#0A1320; --tr-h:#142338;
  --ok:#22C55E; --warn:#F59E0B; --err:#EF4444;
}
:root[data-theme="light"] {
  --bg:#F1F5FB; --surface:#FFFFFF; --raised:#F7FAFE; --border:#D8E2F0;
  --text:#293A52; --strong:#0E1D30; --muted:#5E7392;
  --accent:#0A9E82; --accent-dim:#E5F5F1;
  --link:#1862BB; --link-h:#114DA0;
  --code-bg:#EEF3FA; --th-bg:#E8F3EE; --tr-alt:#F5F8FC; --tr-h:#EAF0FA;
  --ok:#16A34A; --warn:#D97706; --err:#DC2626;
}
@media print {
  :root,:root[data-theme="dark"] {
    --bg:#fff; --surface:#fff; --border:#d1d5db; --text:#111; --strong:#000;
    --muted:#444; --accent:#0A9E82; --accent-dim:#f0fdf4;
    --link:#1558b0; --code-bg:#f5f5f5; --th-bg:#f0fdf4; --tr-alt:#fafafa; --tr-h:#fafafa;
  }
  #sidebar,#theme-btn { display:none!important; }
  #main { max-width:100%!important; padding:0!important; margin:0!important; }
  a[href]::after { content:" ("attr(href)")"; font-size:.8em; color:#555; }
}
*,::before,::after { box-sizing:border-box; margin:0; padding:0; }
html { scroll-behavior:smooth; }
body {
  background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  font-size:16px; line-height:1.7; display:flex; min-height:100vh;
}
#sidebar {
  width:252px; min-width:252px; height:100vh;
  position:sticky; top:0; overflow-y:auto;
  background:var(--surface); border-right:1px solid var(--border);
  padding:24px 14px 48px; flex-shrink:0;
  scrollbar-width:thin; scrollbar-color:var(--border) transparent;
}
#sidebar-logo {
  font-weight:800; font-size:11px; letter-spacing:.16em; text-transform:uppercase;
  color:var(--accent); margin-bottom:22px; padding-bottom:14px;
  border-bottom:1px solid var(--border);
}
#toc-heading {
  font-size:10px; font-weight:700; letter-spacing:.12em; text-transform:uppercase;
  color:var(--muted); margin-bottom:8px;
}
#toc-list { list-style:none; }
#toc-list li { margin:1px 0; }
#toc-list li.h3 { padding-left:14px; }
#toc-list a {
  display:block; padding:4px 10px; border-radius:5px; font-size:13.5px;
  color:var(--muted); text-decoration:none;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  transition:color .15s,background .15s;
}
#toc-list a:hover { color:var(--accent); background:var(--accent-dim); }
#toc-list a.active { color:var(--accent); background:var(--accent-dim); font-weight:600; }
#main { flex:1; min-width:0; padding:44px 60px 80px; max-width:920px; }
#theme-btn {
  position:fixed; top:16px; right:20px; z-index:300;
  background:var(--surface); border:1px solid var(--border);
  color:var(--muted); padding:5px 14px; border-radius:20px;
  cursor:pointer; font-size:13px; transition:color .2s,border-color .2s;
}
#theme-btn:hover { color:var(--accent); border-color:var(--accent); }
h1 {
  font-weight:800; font-size:30px; line-height:1.2; color:var(--strong);
  border-bottom:2px solid var(--accent); padding-bottom:14px; margin-bottom:22px;
}
h2 {
  font-weight:700; font-size:17px; color:var(--accent);
  margin:40px 0 14px; padding-bottom:7px;
  border-bottom:1px solid var(--border); scroll-margin-top:24px; letter-spacing:.01em;
}
h3 {
  font-weight:600; font-size:12px; color:var(--muted);
  margin:22px 0 10px; scroll-margin-top:24px;
  letter-spacing:.1em; text-transform:uppercase;
}
p { margin:8px 0; }
a { color:var(--link); text-decoration:none; }
a:hover { color:var(--link-h); text-decoration:underline; }
strong { color:var(--strong); }
ul,ol { padding-left:22px; margin:8px 0; }
li { margin:3px 0; }
hr { border:none; border-top:1px solid var(--border); margin:28px 0; }
blockquote {
  border-left:3px solid var(--accent); padding:8px 16px; margin:12px 0;
  background:var(--accent-dim); border-radius:0 6px 6px 0; color:var(--muted);
}
code {
  font-family:'JetBrains Mono','Cascadia Code','Fira Code','Courier New',monospace;
  font-size:12.5px; background:var(--code-bg); border-radius:4px; padding:1px 6px;
}
pre {
  background:var(--code-bg); border:1px solid var(--border); border-radius:8px;
  padding:18px 22px; overflow-x:auto; margin:14px 0;
  font-family:'JetBrains Mono',monospace; font-size:13px; line-height:1.6;
}
pre code { background:none; padding:0; }
.report-diagram { margin:14px 0; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.diagram-controls { display:flex; gap:6px; padding:8px; background:var(--raised); }
.diagram-controls[hidden] { display:none; }
.diagram-controls button { cursor:pointer; padding:4px 10px; border:1px solid var(--border);
  border-radius:4px; color:var(--text); background:var(--surface); }
.diagram-viewport { overflow:auto; padding:12px; background:var(--surface); }
.diagram-viewport svg { display:block; margin:auto; }
@media print { .diagram-controls { display:none; } .diagram-viewport svg { max-width:100%!important; } }
.table-wrap {
  overflow-x:auto; margin:14px 0; border-radius:8px; border:1px solid var(--border);
}
table { border-collapse:collapse; width:100%; font-size:14px; min-width:400px; }
thead th {
  background:var(--th-bg); font-weight:700; font-size:11px;
  letter-spacing:.08em; text-transform:uppercase; color:var(--muted);
}
th,td {
  border-bottom:1px solid var(--border); border-right:1px solid var(--border);
  padding:9px 14px; text-align:left; vertical-align:top;
  font-variant-numeric:tabular-nums;
}
th:last-child,td:last-child { border-right:none; }
thead tr:last-child th { border-bottom:2px solid var(--border); }
tbody tr:nth-child(even) { background:var(--tr-alt); }
tbody tr:hover { background:var(--tr-h); }
tbody tr:last-child td { border-bottom:none; }
details { border:1px solid var(--border); border-radius:8px; margin:14px 0; overflow:hidden; }
summary {
  cursor:pointer; padding:10px 16px; font-size:13.5px;
  color:var(--muted); list-style:none; user-select:none;
}
summary::-webkit-details-marker { display:none; }
summary:hover { color:var(--accent); background:var(--accent-dim); }
details[open]>summary { color:var(--text); background:var(--raised); border-bottom:1px solid var(--border); }
details>:not(summary) { padding:14px 16px; }
@media (max-width:900px) {
  #sidebar { display:none; }
  #main { padding:28px 20px 60px; }
  h1 { font-size:24px; }
}
"""

_HTML_JS = r"""
(function() {
  var root = document.documentElement;
  var btn  = document.getElementById('theme-btn');
  var stored = 'dark';
  try { stored = localStorage.getItem('osint-theme') || 'dark'; } catch (_) {}
  root.setAttribute('data-theme', stored);
  setLabel(stored);
  btn.addEventListener('click', function() {
    var t = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', t);
    try { localStorage.setItem('osint-theme', t); } catch (_) {}
    setLabel(t);
    if (window.renderReportDiagrams) window.renderReportDiagrams();
  });
  function setLabel(t) {
    btn.textContent = t === 'dark' ? '☀️ Светлая' : '🌙 Тёмная';
  }

  var content = document.getElementById('content');
  var tocList = document.getElementById('toc-list');

  // Обернуть таблицы для горизонтального скролла
  content.querySelectorAll('table').forEach(function(t) {
    var w = document.createElement('div');
    w.className = 'table-wrap';
    t.parentNode.insertBefore(w, t);
    w.appendChild(t);
  });

  // Построить оглавление из h2/h3
  var headings = Array.prototype.slice.call(content.querySelectorAll('h2, h3'));
  headings.forEach(function(h, i) {
    if (!h.id) h.id = 'h-' + i;
    var li = document.createElement('li');
    li.className = h.tagName.toLowerCase();
    var a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent.replace(/^[^\wЀ-ӿ]+/, '');
    li.appendChild(a);
    tocList.appendChild(li);
  });

  // Подсветка активного заголовка при прокрутке
  if ('IntersectionObserver' in window && headings.length) {
    var activeLink = null;
    var io = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (!e.isIntersecting) return;
        var a = tocList.querySelector('a[href="#' + e.target.id + '"]');
        if (!a) return;
        if (activeLink) activeLink.classList.remove('active');
        a.classList.add('active');
        activeLink = a;
      });
    }, { rootMargin: '0px 0px -60% 0px', threshold: 0 });
    headings.forEach(function(h) { io.observe(h); });
  }
})();
"""


@lru_cache(maxsize=1)
def _diagram_scripts() -> str:
    """Встроенные скрипты работают и при скачивании HTML, и без доступа к CDN."""
    assets = Path(__file__).resolve().parent / "assets"
    scripts = []
    for name in ("mermaid-10.6.1.min.js", "report-diagrams.js"):
        code = (assets / name).read_text(encoding="utf-8")
        # HTML-парсер не должен завершить script из-за строкового литерала в JS.
        code = re.sub(r"</script", lambda _: r"<\/script", code, flags=re.I)
        scripts.append("<script>" + code + "</script>")
    return "\n".join(scripts)


def _protect_body_html(body: str) -> str:
    """Защита при повторной сборке старого Markdown с буквальными HTML-тегами.

    Эти теги не нужны в теле досье и меняют режим разбора всего документа.
    Разметка собственно страницы добавляется отдельно, после этой обработки.
    """
    import html
    return re.sub(r"</?(?:title|script|style|textarea|xmp|iframe|noembed|noframes|plaintext)\b[^>]*>",
                  lambda m: html.escape(m.group(0)), body, flags=re.I)


def write_html(md_text: str, html_path: str, task: str = "", when: str = "") -> bool:
    """Markdown → самодостаточный HTML (тёмная тема, боковое оглавление, Mermaid)."""
    try:
        import markdown as _md
    except Exception:
        return False
    try:
        exts = ["tables", "fenced_code", "sane_lists"]
        try:
            exts.append("md_in_html")
            html_body = _md.markdown(md_text, extensions=exts)
        except Exception:
            exts.remove("md_in_html")
            html_body = _md.markdown(md_text, extensions=exts)

        html_body = _protect_body_html(html_body)

        # ```mermaid ... ``` → <pre class="mermaid">
        html_body = re.sub(
            r'<pre><code class="language-mermaid">(.*?)</code></pre>',
            lambda m: '<pre class="mermaid">' + m.group(1) + '</pre>',
            html_body, flags=re.S,
        )

        import html as _h
        safe_task = _h.escape(task or "OSINT Отчёт")

        page = "\n".join([
            "<!DOCTYPE html>",
            "<html lang='ru' data-theme='dark'>",
            "<head>",
            "<meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            f"<title>OSINT · {safe_task}</title>",
            f"<style>\n{_HTML_CSS}</style>",
            "</head>",
            "<body>",
            "<button id='theme-btn'>☀️ Светлая</button>",
            "<nav id='sidebar'>",
            "  <div id='sidebar-logo'>OSINT</div>",
            "  <div id='toc-heading'>Содержание</div>",
            "  <ul id='toc-list'></ul>",
            "</nav>",
            "<main id='main'>",
            "  <div id='content'>",
            html_body,
            "  </div>",
            "</main>",
            f"<script>{_HTML_JS}</script>",
            _diagram_scripts() if '<pre class="mermaid">' in html_body else "",
            "</body>",
            "</html>",
        ])
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(page)
        return True
    except Exception:
        return False


_PDF_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css}</style>
</head>
<body>

<div class="cover">
  <div class="cover-label">OSINT · КОНФИДЕНЦИАЛЬНО</div>
  <div class="cover-title">{title}</div>
  <div class="cover-meta">
    <div class="meta-item"><span class="meta-key">Дата</span><span class="meta-val">{when}</span></div>
    <div class="meta-item"><span class="meta-key">Источников</span><span class="meta-val">{servers_ok} / {servers_total}</span></div>
    <div class="meta-item"><span class="meta-key">Вызовов</span><span class="meta-val">{calls_ok} / {calls_total}</span></div>
    <div class="meta-item"><span class="meta-key">Уверенность</span><span class="meta-val conf-{conf_css}">{confidence}</span></div>
  </div>
</div>

<div class="body-content">
{body}
</div>

</body>
</html>
"""

_PDF_CSS = """
/* ── Страница ─────────────────────────────────────── */
@page {
  size: A4;
  margin: 2cm 2.2cm 2.4cm 2.2cm;
  @top-right {
    content: "OSINT · Конфиденциально";
    font-family: 'DejaVu Sans', sans-serif;
    font-size: 7pt; color: #7a8fa8; letter-spacing: .08em; text-transform: uppercase;
  }
  @bottom-right {
    content: counter(page) " / " counter(pages);
    font-family: 'DejaVu Sans Mono', monospace;
    font-size: 7.5pt; color: #7a8fa8;
  }
}
/* Обложка: нет полей и колонтитулов — они в самом div.cover */
@page :first {
  margin: 0;
  @top-right { content: ""; }
  @bottom-right { content: ""; }
}

/* ── Reset ────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'DejaVu Sans', Arial, sans-serif;
  font-size: 10pt; line-height: 1.6; color: #1c2433; background: #fff;
}

/* ── Обложка-шапка ────────────────────────────────── */
.cover {
  background: #0a1628;
  padding: 2.4cm 2.2cm 2cm;
  page-break-after: always;
}
.cover-label {
  font-size: 7pt; font-weight: bold; letter-spacing: .18em;
  text-transform: uppercase; color: #0DCFAB; margin-bottom: 1.2cm;
}
.cover-title {
  font-size: 26pt; font-weight: bold; color: #ffffff;
  line-height: 1.2; margin-bottom: 1.6cm; max-width: 14cm;
}
.cover-meta {
  display: flex; flex-wrap: wrap; gap: 0;
  border-top: 1pt solid #1e3050; padding-top: 0.6cm;
}
.meta-item {
  width: 50%; padding: 0.35cm 0; border-bottom: 1pt solid #1e3050;
}
.meta-key {
  display: block; font-size: 7pt; letter-spacing: .1em;
  text-transform: uppercase; color: #53698A; margin-bottom: 2pt;
}
.meta-val {
  font-size: 11pt; font-weight: bold; color: #d8e8f8;
  font-family: 'DejaVu Sans', sans-serif;
}
.conf-high  .meta-val, .meta-val.conf-high  { color: #22C55E; }
.conf-med   .meta-val, .meta-val.conf-med   { color: #F59E0B; }
.conf-low   .meta-val, .meta-val.conf-low   { color: #EF4444; }

/* ── Основной контент ─────────────────────────────── */
/* Отступы задаёт @page — здесь только визуальный зазор */
.body-content {
  padding: 0;
}

/* ── Заголовки ────────────────────────────────────── */
h1 {
  font-size: 20pt; font-weight: bold; color: #0a1628;
  margin-bottom: 8pt; padding-bottom: 8pt;
  border-bottom: 2.5pt solid #0DCFAB;
  page-break-after: avoid;
}
h2 {
  font-size: 12pt; font-weight: bold; color: #ffffff;
  background: #0a1628;
  margin: 20pt 0 8pt; padding: 5pt 10pt;
  page-break-after: avoid;
}
h3 {
  font-size: 9.5pt; font-weight: bold; color: #0a4a38;
  margin: 14pt 0 5pt;
  text-transform: uppercase; letter-spacing: .06em;
  border-bottom: 1pt solid #c0e8d8; padding-bottom: 3pt;
  page-break-after: avoid;
}

/* ── Параграфы / текст ────────────────────────────── */
p { margin: 5pt 0; orphans: 3; widows: 3; }
strong { color: #0a1628; }
em { color: #4a5a72; font-style: italic; }
a { color: #1558b0; text-decoration: none; word-break: break-all; }
hr { border: none; border-top: 1pt solid #dce4ef; margin: 14pt 0; }

/* ── Списки ───────────────────────────────────────── */
ul, ol { padding-left: 16pt; margin: 5pt 0; }
li { margin: 2pt 0; }

/* ── Код ──────────────────────────────────────────── */
code {
  font-family: 'DejaVu Sans Mono', monospace; font-size: 8pt;
  background: #eef3fa; padding: 1pt 4pt; color: #1c3050;
}
pre {
  font-family: 'DejaVu Sans Mono', monospace; font-size: 8pt;
  background: #f5f8fc; border-left: 3pt solid #0DCFAB;
  padding: 8pt 10pt; margin: 8pt 0;
  white-space: pre-wrap; word-break: break-all;
  page-break-inside: avoid;
}
pre code { background: none; padding: 0; }

/* ── Таблицы ──────────────────────────────────────── */
table {
  border-collapse: collapse; width: 100%; font-size: 9pt;
  margin: 8pt 0; page-break-inside: auto;
}
thead { display: table-header-group; }
th {
  background: #0a1628; color: #0DCFAB;
  font-size: 7.5pt; font-weight: bold;
  text-transform: uppercase; letter-spacing: .07em;
  padding: 5pt 8pt; text-align: left; vertical-align: bottom;
  border-bottom: 2pt solid #0DCFAB;
}
td {
  padding: 5pt 8pt; vertical-align: top; text-align: left;
  border-bottom: 1pt solid #dce4ef;
  font-variant-numeric: tabular-nums;
}
tbody tr:nth-child(even) td { background: #f5f9f7; }
tbody tr:last-child td { border-bottom: 2pt solid #b0d0c8; }

/* ── Blockquote (метаданные в шапке md) ───────────── */
blockquote {
  background: #f0fbf8; border-left: 3pt solid #0DCFAB;
  padding: 7pt 12pt; margin: 10pt 0; color: #2a4a3a; font-size: 9.5pt;
}

/* ── Details/summary ──────────────────────────────── */
details { border: 1pt solid #dce4ef; padding: 4pt 8pt; margin: 6pt 0; }
summary { font-size: 8.5pt; color: #4a5a72; }
"""


def write_pdf(md_text: str, pdf_path: str, task: str = "",
              when: str = "", meta: dict | None = None) -> bool:
    """Markdown → красивый PDF (weasyprint). Возвращает True при успехе."""
    try:
        import markdown as _md
        from weasyprint import HTML
    except Exception:
        return False
    try:
        html_body = _md.markdown(
            md_text, extensions=["tables", "fenced_code", "sane_lists"])

        html_body = _protect_body_html(html_body)

        # Убираем первый <h1> из тела — он уже вынесен в обложку
        html_body = re.sub(r'^<h1[^>]*>.*?</h1>\s*', '', html_body,
                           count=1, flags=re.S | re.I)
        # Убираем blockquote с метаданными (он в обложке)
        html_body = re.sub(r'^<blockquote>.*?</blockquote>\s*', '', html_body,
                           count=1, flags=re.S | re.I)
        # Первый <hr> после шапки тоже лишний
        html_body = re.sub(r'^<hr\s*/?>\s*', '', html_body, count=1, flags=re.I)

        cov = (meta or {}).get("coverage") or {}
        conf = (meta or {}).get("confidence") or "низкая"
        conf_css = {"высокая": "high", "средняя": "med", "низкая": "low"}.get(conf, "low")

        import html as _h
        title = _h.escape(task or "OSINT-досье")

        page = _PDF_TEMPLATE.format(
            title=title,
            when=_h.escape(when or ""),
            servers_ok=cov.get("servers_ok", "?"),
            servers_total=cov.get("servers_total", "?"),
            calls_ok=cov.get("calls_ok", "?"),
            calls_total=cov.get("calls_total", "?"),
            confidence=_h.escape(conf),
            conf_css=conf_css,
            css=_PDF_CSS,
            body=html_body,
        )
        HTML(string=page).write_pdf(pdf_path)
        return True
    except Exception:
        return False


# Кириллица → латиница. Раньше кириллица просто ВЫРЕЗАЛАСЬ, поэтому любой русский
# запрос давал безымянный «report-<hex>.md» и файлы было не отличить друг от друга.
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def slugify(task: str) -> str:
    s = "".join(_TRANSLIT.get(ch, ch) for ch in (task or "").lower())
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40].strip("-") or "report"
    return f"{s}-{uuid.uuid4().hex[:6]}"


def save_report(task: str, results: list[dict], when: str,
                reports_dir: str, url_base: str,
                synthesis: str | None = None, identity: dict | None = None) -> dict:
    """Пишет .md + .html (+ .pdf best-effort). Возвращает {md_url, html_url, pdf_url, ...}."""
    os.makedirs(reports_dir, exist_ok=True)
    md_text, meta = build_markdown(task, results, when, synthesis, identity)
    slug = slugify(task)
    md_path = os.path.join(reports_dir, f"{slug}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md_text)
    # HTML — главный формат для браузера (тёмная тема, оглавление, Mermaid).
    html_url = html_dl_url = None
    html_path = os.path.join(reports_dir, f"{slug}.html")
    if write_html(md_text, html_path, task, when):
        html_url = f"{url_base}/{slug}.html"
        html_dl_url = f"{url_base}/download/{slug}.html"
    # PDF — best-effort; при сбое weasyprint молча пропускается.
    pdf_url = pdf_dl_url = None
    pdf_path = os.path.join(reports_dir, f"{slug}.pdf")
    if write_pdf(md_text, pdf_path, task=task, when=when, meta=meta):
        pdf_url = f"{url_base}/{slug}.pdf"
        # /download/ отдаёт тот же файл с Content-Disposition: attachment
        # (см. config/reports-nginx.conf) — «Сохранить как…» вместо просмотра.
        pdf_dl_url = f"{url_base}/download/{slug}.pdf"
    return {"markdown": md_text, "meta": meta,
            "md_url": f"{url_base}/{slug}.md",
            "md_dl_url": f"{url_base}/download/{slug}.md",
            "html_url": html_url, "html_dl_url": html_dl_url,
            "pdf_url": pdf_url, "pdf_dl_url": pdf_dl_url, "slug": slug}
