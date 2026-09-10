#!/usr/bin/env python3
"""Офлайн-рендер досье по компании на РЕАЛЬНЫХ payload'ах из reports/meta-2542b1.md.

Проверяет сборку отчёта без сети и без LLM: тот же путь, что и в
build_company_dossier (extract_* → sections.render_target → report.build_markdown),
но с зафиксированными ответами источников. Так дефекты сломанного досье
проверяются детерминированно, а не «прогоном по живым API».

    python tests/unit_render.py          # запустить проверки
    python tests/unit_render.py --show   # ещё и напечатать получившееся досье
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "servers", "orchestrator"))

import dossier   # noqa: E402
import entity    # noqa: E402
import report    # noqa: E402
import sections  # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("✅ " if cond else "❌ ") + name + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def j(o) -> str:
    return json.dumps(o, ensure_ascii=False)


# ---- РЕАЛЬНЫЕ ответы источников из отчёта meta-2542b1.md -------------------
SEC = {"name": "Meta Platforms, Inc.", "cik": "0001326801", "tickers": ["META"],
       "exchanges": ["Nasdaq"], "sic": "7370", "sic_description": "Services-Computer Programming",
       "state_of_incorporation": "DE", "entity_type": "operating",
       "address": "1 META WAY, MENLO PARK, CA 94025",
       "recent_filings": [{"form": "10-K", "date": "2026-01-29", "doc": "meta-20251231.htm"}],
       "edgar_url": "https://www.sec.gov/cgi-bin/browse-edgar?CIK=0001326801"}
GLEIF_DK = {"lei": "984500Y657CE399B1547", "legal_name": "META",
            "address": {"lines": ["Molledalvej 16"], "city": "Viborg", "country": "DK"},
            "jurisdiction": "DK", "entity_status": "ACTIVE",
            "registration_status": "LAPSED", "last_update": "2022-05-19",
            "other_matches": ["META FINANCE", "META S.R.L."]}
FIN = {"name": "Meta Platforms, Inc.", "cik": "0001326801", "currency": "USD",
       "source": "SEC XBRL (10-K)", "years": [2025, 2024],
       "metrics": {"Выручка": {"2025": 164501000000, "2024": 134902000000},
                   "Чистая прибыль": {"2025": 62360000000, "2024": 39098000000}}}
# Мусорная выдача веб-поиска — ровно та, что заняла треть тела прошлого отчёта.
CSE = {"engine": "docs_orgs", "total_results": "?", "count": 6, "results": [
    {"title": "META - Pastebin.com", "link": "https://pastebin.com/g4XPxFUj",
     "snippet": "Pastebin.com is the number one paste tool since 2002. Pastebin is a "
                "website where you can store text online for a set period of time."},
    {"title": "<!DOCTYPE html> <html> <meta name=\"viewport\" content ...",
     "link": "https://pastebin.com/7pY3xYVd", "snippet": ""},
    {"title": "Meta Financial Group Annual Report 2025 Form 10-K",
     "link": "https://stocklight.com/stocks/us/nasdaq-cash/meta-financial-group/x.pdf",
     "snippet": "Meta Financial Group Annual Report 2025 (NASDAQ:CASH)"},
    {"title": "2025 Annual Report - Investor Relations - Zoom",
     "link": "https://investors.zoom.us/static-files/f5b92b93.pdf",
     "snippet": "FY25 was a transformative year for Zoom. Meta, making AI accessible."},
    {"title": "Meta Q4 2025 Results", "link": "https://s21.q4cdn.com/399680738/x.pdf",
     "snippet": "Meta Platforms, Inc. reports fourth quarter results, meta.com"},
    {"title": "Introducing Meta Platforms", "link": "https://about.meta.com/company-info/",
     "snippet": "Meta Platforms builds technologies that help people connect."},
]}


def make_results() -> list[dict]:
    """Записи результатов так, как их видит конвейер после reclassify."""
    return [
        # Фаза 0: опрос РАЗГОВОРНОЙ строкой — виден в отчёте, но карточкой юрлица
        # стать не должен (иначе датская META вернулась бы через extract).
        {"server": "directapi", "tool": "gleif_entity", "name": "Direct Lookups · gleif_entity",
         "ok": True, "text": j(GLEIF_DK), "phase": "resolve",
         "target_value": "Meta", "target_type": "company"},
        {"server": "directapi", "tool": "sec_edgar", "name": "Direct Lookups · sec_edgar",
         "ok": True, "text": j(SEC), "phase": "resolve",
         "target_value": "Meta", "target_type": "company"},
        # Основной веер — уже каноническим именем.
        {"server": "directapi", "tool": "sec_financials", "name": "Direct Lookups · sec_financials",
         "ok": True, "text": j(FIN), "target_value": "Meta", "target_type": "company"},
        {"server": "directapi", "tool": "google_cse", "name": "Direct Lookups · google_cse",
         "ok": True, "text": j(CSE), "target_value": "Meta", "target_type": "company"},
        # Сбой: НЕ должен превратиться в вывод «должностных лиц нет».
        {"server": "directapi", "tool": "opencorporates_officers",
         "name": "Direct Lookups · opencorporates_officers", "ok": False,
         "text": "источник недоступен (ConnectError)",
         "target_value": "Meta", "target_type": "company"},
        {"server": "virustotal", "tool": "get_domain_relationship",
         "name": "VirusTotal · subdomains", "ok": True,
         "text": ("🌍 Domain meta.com — subdomains\nShowing 40 of 62 items.\n"
                  "• jobs.meta.com\n• chat.meta.com\n• payments.meta.com\n"),
         "target_value": "meta.com", "target_type": "domain"},
    ]


IDENTITY = {
    "query": "Meta", "legal_name": "Meta Platforms, Inc.", "lei": None,
    "cik": "0001326801", "tickers": ["META"], "jurisdiction": "US-DE",
    "confirms": 2, "confidence": "высокая", "domains": ["meta.com"],
    "candidates": [
        {"name": "Meta Platforms, Inc.", "norm": "meta platforms", "jurisdiction": "US-DE",
         "sources": ["sec_edgar", "domain"], "origins": ["sec_edgar"], "score": 6,
         "why": ["SEC EDGAR: CIK 0001326801"], "chosen": True},
        {"name": "META", "norm": "meta", "jurisdiction": "DK",
         "sources": ["gleif"], "origins": ["gleif"], "score": 2,
         "why": ["GLEIF: регистрация LEI LAPSED — запись неактуальна"], "chosen": False,
         "rejected": "регистрация LEI в статусе LAPSED — запись не актуальна"},
    ],
}


def build() -> str:
    results = make_results()
    cdata = dossier.extract_company_data(results)
    cdata["identity"] = IDENTITY
    cdata["_failed"] = dossier.failed_sources(results)
    tno = [0]
    md = sections.render_target("company", cdata,
                                {"target": IDENTITY["legal_name"], "_tno": tno,
                                 "identity": IDENTITY})
    ddata = dossier.extract_domain_data([r for r in results
                                         if r.get("target_type") == "domain"])
    md += sections.render_target("domain", ddata,
                                 {"target": "meta.com", "_tno": tno,
                                  "identity": IDENTITY, "exclude": {"cse", "org"}})
    md += report.source_matrix_section(results)
    md += dossier.render_limitations(results, {"directapi": {}}, IDENTITY)
    body = "\n".join(md)
    full, meta = report.build_markdown("компания Meta", results, "2026-08-12 00:00 UTC",
                                       body, IDENTITY)
    return full


def main() -> None:
    doc = build()
    low = doc.lower()

    print("--- идентификация ---")
    check("есть раздел идентификации", "## Идентификация цели" in doc)
    check("выбрано верное юрлицо", "Meta Platforms, Inc." in doc)
    check("CIK в досье", "0001326801" in doc)
    check("отвергнутый кандидат показан с причиной",
          "LAPSED" in doc and "отклонён" in doc)
    check("датская карточка НЕ стала карточкой организации",
          "Viborg" not in doc and "984500Y657CE399B1547" not in doc,
          "фаза 0 протекла в extract_company_data")

    print("\n--- потерянные ранее данные ---")
    check("финансы по годам появились", "## Финансовые показатели" in doc)
    check("суммы читаемы (млрд)", "млрд" in doc)
    check("SEC-раздел на месте", "SEC EDGAR" in doc)

    print("\n--- сбой источника ≠ отрицательный факт ---")
    check("падение OpenCorporates названо сбоем, а не отсутствием лиц",
          "Это НЕ означает, что должностных лиц нет" in doc)

    print("\n--- шум веб-поиска ---")
    check("шаблон pastebin отсеян", "number one paste tool" not in low)
    check("заголовок-разметка отсеян", "<!doctype" not in low)
    check("однофамилец Meta Financial отсеян", "meta financial" not in low)
    check("чужой отчёт Zoom отсеян", "investors.zoom.us" not in doc)
    check("релевантный результат сохранён", "about.meta.com" in doc)
    check("объём отсева раскрыт", "Отфильтровано нерелевантных" in doc)

    print("\n--- честность отчёта ---")
    check("шапка считает серверы", "Ответили источников:" in doc)
    check("усечение выдачи раскрыто", "из 62" in doc, "нет пометки Showing 40 of 62")
    check("матрица источников в теле", "## Источники и покрытие" in doc)
    check("нет испанской заглушки BORME", "BORME" not in doc and "Mercantil" not in doc)
    check("подсказка по реестру — по юрисдикции цели (US)", "Secretary of State" in doc)
    check("уверенность не «высокая» при 1 сбое из 4 серверов",
          "**высокая**" not in doc.split("## Уверенность")[-1])

    print("\n--- форма как в эталоне ---")
    check("таблицы пронумерованы", "**Таблица 1." in doc)
    check("нумерация сквозная", "**Таблица 2." in doc)

    print("\n--- тонкое приложение ---")
    check("разобранное сырьё не дублируется",
          "режим приложения: slim" in doc)

    if "--show" in sys.argv:
        print("\n" + "=" * 78 + "\n")
        print(doc)

    print("\n" + ("ВСЁ ЗЕЛЁНОЕ" if not FAILS else f"ПРОВАЛЕНО: {len(FAILS)}"))
    for f in FAILS:
        print("  -", f)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
