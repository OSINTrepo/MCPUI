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

# «[+] Label: https://url» — формат maigret/openosint и подобных.
_PLUS_LINK = re.compile(r"\[\+\]\s*(.+?):\s*(https?://\S+)")
_BARE_URL = re.compile(r"https?://[^\s\)\]\}<>\"']+")
_NOISE = ("[*]", "[♥]", "[!]", "[-]", "[i]", "Searching |", "Donate", "Support ")


def _looks_json(text: str) -> bool:
    t = text.strip()
    return t.startswith("{") or t.startswith("[")


def _clean_lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith(_NOISE)]


def extract_links(text: str) -> list[tuple[str, str]]:
    """Список (label, url). Сначала '[+] Label: url', затем голые ссылки."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for label, url in _PLUS_LINK.findall(text):
        url = url.rstrip(".,);")
        if url not in seen:
            seen.add(url)
            out.append((label.strip(), url))
    for url in _BARE_URL.findall(text):
        url = url.rstrip(".,);")
        if url not in seen:
            seen.add(url)
            out.append(("", url))
    return out


def _fmt_json(text: str) -> str:
    try:
        obj = json.loads(text)
    except Exception:
        return "```\n" + text.strip()[:6000] + "\n```"
    pretty = json.dumps(obj, ensure_ascii=False, indent=2)
    return "```json\n" + pretty[:8000] + ("\n… (обрезано)" if len(pretty) > 8000 else "") + "\n```"


def _source_section(r: dict) -> tuple[str, int]:
    """Markdown-секция по одному источнику. Возвращает (md, кол-во ссылок)."""
    name = r.get("name", r.get("server", "?"))
    tool = r.get("tool", "?")
    status = "✅ успешно" if r.get("ok") else "❌ " + (r.get("text", "недоступен")[:80])
    head = f"### {name} — `{tool}` · {status}\n"
    if not r.get("ok"):
        return head + "\n_Источник не вернул данных._\n", 0

    text = r.get("text", "") or ""
    if _looks_json(text):
        return head + "\n" + _fmt_json(text) + "\n", 0

    links = extract_links(text)
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
    return head + body, len(links)


def build_markdown(task: str, results: list[dict], when: str) -> tuple[str, dict]:
    """Полный отчёт + метаданные {links_total, ok, total}."""
    names = ", ".join(sorted({r.get("name", r["server"]) for r in results})) or "—"
    ok = [r for r in results if r.get("ok")]
    md = [f"# 🕵️ OSINT-досье", "",
          f"**Цель:** {task}  ", f"**Дата:** {when}  ",
          f"**Источники:** {names}  ",
          f"**Успешно опрошено:** {len(ok)} из {len(results)}", "", "---", ""]

    # Сводка
    md += ["## Сводка", ""]
    sections = []
    links_total = 0
    for r in results:
        sec, n = _source_section(r)
        sections.append(sec)
        links_total += n
        if r.get("ok"):
            extra = f" — {n} ссылок" if n else ""
            md.append(f"- **{r.get('name', r['server'])}**{extra}")
    if not ok:
        md.append("- Значимых находок нет (источники не вернули данных).")
    md += ["", "---", "", "## Подробности", ""]
    md += sections

    # Таблица источников
    md += ["", "---", "", "## Источники и статусы", "",
           "| Источник | Инструмент | Статус |", "|---|---|---|"]
    for r in results:
        st = "ok" if r.get("ok") else "недоступен"
        md.append(f"| {r.get('name', r['server'])} | {r.get('tool', '?')} | {st} |")

    conf = "высокая" if len(ok) >= 2 else "средняя" if ok else "низкая"
    md += ["", "## Уверенность", "",
           f"**{conf}** — данные получены от {len(ok)} из {len(results)} источников; "
           f"всего найдено ссылок/профилей: {links_total}.", ""]
    return "\n".join(md), {"links_total": links_total, "ok": len(ok), "total": len(results)}


_PDF_CSS = """
@page { size: A4; margin: 1.6cm; }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 10.5pt; line-height: 1.4; color: #1a1a1a; }
h1 { font-size: 20pt; border-bottom: 2px solid #2a7; padding-bottom: 4px; }
h2 { font-size: 14pt; color: #16794e; margin-top: 18px; border-bottom: 1px solid #ddd; }
h3 { font-size: 11.5pt; margin-top: 12px; }
a { color: #1558b0; text-decoration: none; word-break: break-all; }
code, pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt; }
pre { background: #f5f5f5; padding: 8px; border-radius: 4px; white-space: pre-wrap; word-break: break-all; }
table { border-collapse: collapse; width: 100%; font-size: 9.5pt; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }
th { background: #eef6f1; }
li { margin: 1px 0; }
details { margin: 6px 0; }
summary { cursor: pointer; color: #555; font-size: 9pt; }
"""


def write_pdf(md_text: str, pdf_path: str) -> bool:
    """Markdown → HTML → PDF (weasyprint). Возвращает True при успехе."""
    try:
        import markdown as _md
        from weasyprint import HTML
    except Exception:
        return False
    try:
        html_body = _md.markdown(
            md_text, extensions=["tables", "fenced_code", "sane_lists"])
        html = (f"<html><head><meta charset='utf-8'><style>{_PDF_CSS}</style></head>"
                f"<body>{html_body}</body></html>")
        HTML(string=html).write_pdf(pdf_path)
        return True
    except Exception:
        return False


def slugify(task: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9а-яА-Я]+", "-", task).strip("-").lower()[:40]
    s = re.sub(r"[а-яА-Я]", "", s).strip("-") or "report"
    return f"{s}-{uuid.uuid4().hex[:6]}"


def save_report(task: str, results: list[dict], when: str,
                reports_dir: str, url_base: str) -> dict:
    """Пишет .md (+ .pdf best-effort). Возвращает {md_url, pdf_url, meta, markdown}."""
    os.makedirs(reports_dir, exist_ok=True)
    md_text, meta = build_markdown(task, results, when)
    slug = slugify(task)
    md_path = os.path.join(reports_dir, f"{slug}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md_text)
    pdf_url = pdf_dl_url = None
    pdf_path = os.path.join(reports_dir, f"{slug}.pdf")
    if write_pdf(md_text, pdf_path):
        pdf_url = f"{url_base}/{slug}.pdf"
        # /download/ отдаёт тот же файл с Content-Disposition: attachment
        # (см. config/reports-nginx.conf) — «Сохранить как…» вместо просмотра.
        pdf_dl_url = f"{url_base}/download/{slug}.pdf"
    return {"markdown": md_text, "meta": meta,
            "md_url": f"{url_base}/{slug}.md",
            "md_dl_url": f"{url_base}/download/{slug}.md",
            "pdf_url": pdf_url, "pdf_dl_url": pdf_dl_url, "slug": slug}
