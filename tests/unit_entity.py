#!/usr/bin/env python3
"""Юнит-тесты разрешения сущности и честного учёта — БЕЗ сети.

Запуск (в контейнере оркестратора или локально):
    python tests/unit_entity.py

Проверяют ровно те дефекты, из-за которых досье по «компании Meta» описывало
чужое юрлицо: датскую фирму-пустышку META (LEI LAPSED) вместо Meta Platforms.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "servers", "orchestrator"))

import entity          # noqa: E402
import report          # noqa: E402
import recipes         # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("✅ " if cond else "❌ ") + name + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


# --- фикстуры: РЕАЛЬНЫЕ ответы из reports/meta-2542b1.md --------------------
GLEIF_DK = {
    "lei": "984500Y657CE399B1547", "legal_name": "META",
    "address": {"lines": ["Molledalvej 16"], "city": "Viborg", "country": "DK"},
    "jurisdiction": "DK", "legal_form": "D4PU", "entity_status": "ACTIVE",
    "registration_status": "LAPSED", "last_update": "2022-05-19",
    "other_matches": ["META FINANCE", "META S.R.L.", "META-MODELING"],
}
SEC_META = {
    "name": "Meta Platforms, Inc.", "cik": "0001326801", "tickers": ["META"],
    "exchanges": ["Nasdaq"], "sic": "7370", "state_of_incorporation": "DE",
    "address": "1 META WAY, MENLO PARK, CA",
}
WIKI_DISAMBIG = {"title": "Meta", "description": "disambiguation page",
                 "extract": "Meta is a term.", "external_domains": []}
WIKI_REAL = {"title": "Meta Platforms", "description": "American company",
             "extract": "Meta Platforms, Inc. is an American company.",
             "external_domains": [{"domain": "meta.com", "count": 12},
                                  {"domain": "reuters.com", "count": 9}]}


def test_resolution() -> None:
    print("\n--- разрешение сущности ---")
    probes = {"sec": SEC_META, "gleif": GLEIF_DK, "wikipedia": WIKI_DISAMBIG,
              "gleif_hint": None}
    res = entity.resolve("Meta", probes, ["meta.com"])

    check("выбрано юрлицо из SEC, а не датская пустышка",
          res["legal_name"] == "Meta Platforms, Inc.", f"получили {res['legal_name']!r}")
    check("датская META отвергнута",
          "META" != (res["legal_name"] or ""), res["legal_name"])
    check("CIK подхвачен", res["cik"] == "0001326801", str(res["cik"]))
    check("тикер подхвачен", res["tickers"] == ["META"], str(res["tickers"]))

    dk = next((c for c in res["candidates"] if c["name"] == "META"), None)
    check("датский кандидат в отчёте присутствует (не молча выброшен)", dk is not None)
    if dk:
        # Жёсткое правило: протухшая запись реестра не может стать ответом даже
        # с высоким баллом — её имя дословно совпадало с запросом и наследовало
        # подтверждение от домена meta.com.
        check("LAPSED-кандидат заблокирован от выбора", bool(dk.get("rejected")),
              f"score={dk['score']} rejected={dk.get('rejected')!r}")
        check("причина отклонения названа",
              "LAPSED" in (dk.get("rejected") or "")
              or any("LAPSED" in w for w in dk["why"]), str(dk["why"]))
    check("реестры опрашиваются каноническим именем",
          entity.registry_name(res) == "Meta Platforms, Inc.")
    check("код юрисдикции для OpenCorporates", entity.jurisdiction_code(res) == "us",
          entity.jurisdiction_code(res))


def test_sec_timeout() -> None:
    """Именно этот прогон и породил meta-2542b1.md: sec_edgar отвалился по
    ReadTimeout, и единственным «совпадением» осталась датская META."""
    print("\n--- SEC недоступен (регрессия meta-2542b1) ---")
    probes = {"sec": None, "gleif": GLEIF_DK, "wikipedia": WIKI_DISAMBIG,
              "gleif_hint": None}
    res = entity.resolve("Meta", probes, ["meta.com"])
    check("датская META НЕ становится юрлицом цели",
          res["legal_name"] != "META", str(res["legal_name"]))
    check("без подтверждений юрлицо не утверждается вовсе",
          res["legal_name"] is None, str(res["legal_name"]))
    check("уверенность низкая", res["confidence"] == "низкая", res["confidence"])


def test_unresolved() -> None:
    print("\n--- сущность не опознана ---")
    # Только слабая подсказка GLEIF и никаких подтверждений.
    probes = {"sec": None, "gleif": None, "wikipedia": None,
              "gleif_hint": {"did_you_mean": ["ROGA I KOPYTA LLC"]}}
    res = entity.resolve("Ромашка", probes, [])
    check("юрлицо НЕ утверждается без подтверждений", res["legal_name"] is None,
          str(res["legal_name"]))
    check("уверенность низкая", res["confidence"] == "низкая", res["confidence"])
    check("кандидат-подсказка виден аналитику",
          any(c["name"] == "ROGA I KOPYTA LLC" for c in res["candidates"]))


def test_wiki_support() -> None:
    print("\n--- подтверждение статьёй Wikipedia ---")
    probes = {"sec": SEC_META, "gleif": None, "wikipedia": WIKI_REAL, "gleif_hint": None}
    res = entity.resolve("Meta", probes, ["meta.com"])
    check("статья по существу даёт высокую уверенность",
          res["confidence"] == "высокая", f"{res['confidence']} confirms={res['confirms']}")
    probes_d = {"sec": SEC_META, "gleif": None, "wikipedia": WIKI_DISAMBIG,
                "gleif_hint": None}
    res_d = entity.resolve("Meta", probes_d, [])
    check("страница значений подтверждением НЕ считается",
          res_d["confirms"] < res["confirms"],
          f"{res_d['confirms']} vs {res['confirms']}")


def test_domains() -> None:
    print("\n--- кандидаты доменов ---")
    cands = entity.domain_candidates("Meta Platforms, Inc.",
                                     {"wikipedia": WIKI_REAL})
    check("официальный сайт из статьи — первым", cands[0] == "meta.com", str(cands[:3]))
    check("СМИ из ссылочного профиля отфильтрованы", "reuters.com" not in cands,
          str(cands))
    check("brand_match работает", entity.brand_match("Meta Platforms, Inc.", "meta.com"))
    check("brand_match не срабатывает на чужом домене",
          not entity.brand_match("Meta Platforms, Inc.", "example.org"))


def test_links() -> None:
    print("\n--- санитайзер ссылок ---")
    junk = [
        r"https://57.144.68.141/\r\nContent-Type:",   # обрывок HTTP-баннера
        "https://*.google-analytics.com",             # директива CSP
        "https://api.gleif.org/api/v1/lei-records",   # self-link нашего же запроса
        "https://157.240.205.1/",                     # голый IP из скана
    ]
    for u in junk:
        check(f"отброшено: {u[:44]}", not report._valid_link(u))
    check("нормальная ссылка проходит",
          report._valid_link("https://about.meta.com/company-info/"))


def test_accounting() -> None:
    print("\n--- честный учёт источников ---")
    results = [
        {"server": "directapi", "tool": "rdap_ip", "ok": False, "text": "ConnectError"}
        for _ in range(12)
    ] + [
        {"server": "directapi", "tool": "sec_edgar", "ok": True, "text": "{}"},
        {"server": "virustotal", "tool": "get_domain_report", "ok": True, "text": "x"},
    ]
    cov = report.coverage(results)
    check("считаем СЕРВЕРЫ, а не вызовы", cov["servers_total"] == 2,
          str(cov))
    check("вызовы тоже видны", cov["calls_total"] == 14, str(cov))
    matrix = report.source_matrix(results)
    da = next(m for m in matrix if m["server"] == "directapi")
    check("12 одинаковых rdap_ip свёрнуты в одну строку", da["calls"] == 13,
          str(da))

    # Прогон с массовыми отказами не может быть «высокой» уверенности.
    bad = [{"server": f"s{i}", "tool": "t", "ok": i < 2, "text": "x"} for i in range(10)]
    label, why = report.confidence(bad)
    check("уверенность не «высокая» при 80% отказов", label != "высокая",
          f"{label} — {why}")

    # Неопознанная сущность ставит потолок.
    good = [{"server": f"s{i}", "tool": "t", "ok": True, "text": "x"} for i in range(8)]
    label2, _ = report.confidence(good, {"confidence": "низкая", "legal_name": None})
    check("неопознанная сущность ограничивает уверенность", label2 == "низкая", label2)


def test_recipes() -> None:
    print("\n--- состав корпоративного веера ---")
    ident = {"legal_name": "Meta Platforms, Inc.", "tickers": ["META"],
             "jurisdiction": "US-DE", "lei": None}
    steps = recipes.deep_company_steps("Meta Platforms, Inc.", ident, task="компания Meta")
    tools = [(s, t) for s, t, _ in steps]
    check("финансы по годам (XBRL SEC) подключены по тикеру",
          ("directapi", "sec_financials") in tools, str(tools))
    check("нерабочий stockscope в веер не идёт",
          ("stockscope", "stock_financials") not in tools, str(tools))
    check("checko не зовётся для компании США",
          ("checko", "search") not in tools, str(tools))
    check("платный the-stall не зовётся без allow_paid",
          ("the-stall", "sanctions-screening") not in tools, str(tools))
    engines = [a.get("engine") for s, t, a in steps if t == "google_cse"]
    check("паст-сайты убраны из корпоративного веб-поиска",
          "pastebin" not in engines, str(engines))

    ru = recipes.deep_company_steps("Сбербанк", None, task="проверь компанию Сбербанк")
    check("checko зовётся для российской цели",
          ("checko", "search") in [(s, t) for s, t, _ in ru])


def test_reclassify() -> None:
    print("\n--- классификация ответа по payload ---")
    import server  # noqa: E402  (импорт здесь: тянет httpx/mcp)

    long_err = ('{"query": "Meta", "error": "в GLEIF нет точного совпадения по '
                'юридическому названию — передайте ЮРИДИЧЕСКОЕ имя или 20-значный LEI", '
                '"hint": "уточните ЮРИДИЧЕСКОЕ имя или передайте 20-значный LEI напрямую", '
                '"did_you_mean": ["META", "META FINANCE", "META S.R.L.", "META-MODELING", '
                '"META INTERNET GMBH", "META SYSTEMS AG", "META SOLUTIONS LTD", '
                '"META PLATFORMS IRELAND LIMITED", "META PLATFORMS INC", "METALS"]}')
    check("длинный JSON-отказ — это сбой (раньше проходил как успех)",
          len(long_err) > 400 and server._json_error(long_err) is not None)
    check("subfinder not found — сбой",
          server._json_error('{"success": false, "data": null, '
                             '"error": "subfinder not found."}') is not None)
    check("нужен CENSYS_ORG_ID — сбой",
          server._json_error('{"error": "нужен CENSYS_ORG_ID: search Censys '
                             'недоступен на free-аккаунте."}') is not None)
    check("корректный пустой ответ Checko успехом и остаётся",
          server._json_error('{"data": {"Записи": []}, "meta": {"status": "ok"}}')
          is None)
    long_ok = '{"domain": "meta.com", "A": ["157.240.205.1"]}' + " " * 500
    check("длинный успешный JSON не трогаем", server._json_error(long_ok) is None)


if __name__ == "__main__":
    test_resolution()
    test_sec_timeout()
    test_unresolved()
    test_wiki_support()
    test_domains()
    test_links()
    test_accounting()
    test_recipes()
    try:
        test_reclassify()
    except ImportError as e:
        print(f"⚠️  reclassify пропущен (нет зависимостей вне контейнера): {e}")
    print("\n" + ("ВСЁ ЗЕЛЁНОЕ" if not FAILS else f"ПРОВАЛЕНО: {len(FAILS)}"))
    for f in FAILS:
        print("  -", f)
    sys.exit(1 if FAILS else 0)
