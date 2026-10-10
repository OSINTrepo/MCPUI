"""Разрешение сущности компании: разговорное имя → каноническое юрлицо.

Зачем это отдельный этап. GLEIF считает совпадением РАВЕНСТВО нормализованных
имён, поэтому запрос «Meta» точно совпадал с датской фирмой-пустышкой META
(Viborg, LEI в статусе LAPSED) — её карточка уходила в «Резюме» и «Организацию»
досье, хотя вся инфраструктура (meta.com, AS32934) принадлежит Meta Platforms.
Одного реестра мало: имя-существительное совпадает с десятком юрлиц.

Поэтому ДО глубокого веера идёт дешёвая разведочная волна (Wikipedia + SEC EDGAR
+ GLEIF), кандидаты скорятся по НЕЗАВИСИМЫМ подтверждениям, и дальше все реестры
опрашиваются уже КАНОНИЧЕСКИМ юридическим именем. Если подтверждений меньше двух —
юрлицо не утверждается: печатается таблица кандидатов, а досье строится только по
инфраструктуре. Приписать цели чужое юрлицо хуже, чем честно сказать «не опознали».

Модуль намеренно ЧИСТЫЙ (без сети): сетевые вызовы делает server.py через run_one,
сюда приходят уже готовые записи результатов. Так логику можно тестировать отдельно.
"""
from __future__ import annotations

import json
import os
import re

import recipes

# Порог, ниже которого юрлицо НЕ утверждается (см. _score: SEC=3, Wikipedia=2,
# домен=2, GLEIF ISSUED=1). 3 = минимум одно сильное подтверждение.
MIN_SCORE = int(os.environ.get("ORCHESTRATOR_ENTITY_MIN_SCORE", "3"))

# Хосты, которые в «ссылочном профиле» статьи Wikipedia НЕ являются официальным
# сайтом компании: СМИ, соцсети, реестры, агрегаторы. Без этого фильтра в
# кандидаты доменов попадали reuters.com и linkedin.com.
_NOT_OFFICIAL = (
    "wikipedia.org", "wikimedia.org", "wikidata.org", "archive.org",
    "doi.org", "worldcat.org", "jstor.org", "google.com", "books.google.com",
    "reuters.com", "bloomberg.com", "ft.com", "wsj.com", "nytimes.com",
    "forbes.com", "cnbc.com", "bbc.co.uk", "bbc.com", "theguardian.com",
    "techcrunch.com", "theverge.com", "rbc.ru", "kommersant.ru", "vedomosti.ru",
    "tass.ru", "ria.ru", "interfax.ru", "lenta.ru",
    "linkedin.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "youtube.com", "t.me", "vk.com", "github.com",
    "sec.gov", "gleif.org", "opencorporates.com", "crunchbase.com",
    "bloomberg.net", "marketscreener.com", "stocklight.com",
)


def _norm(name: str) -> str:
    """Нормализация имени для сравнения (как в directapi._norm_company):
    без пунктуации и хвостовой юр. формы. «META PLATFORMS, INC.» → «meta platforms»."""
    name = re.sub(r'^(?:(?:публичное|открытое|закрытое)\s+)?акционерное\s+общество\s+|^общество\s+с\s+ограниченной\s+ответственностью\s+', '', (name or '').lower())
    name = re.sub(r"mas[^\w]?uliyati\s+cheklangan\s+jamiyati?", "", name)
    name = re.sub(r"\bmchj\b", "", name)
    toks = [t for t in re.split(r"[^\w]+", name) if t]
    while toks and toks[0] in {"пао", "оао", "зао", "ао", "ооо", "pao", "oao", "zao", "ooo"}:
        toks.pop(0)
    while toks and toks[-1] in recipes._ORG_SUFFIX:
        toks.pop()
    return " ".join(toks)


def _tokens(name: str) -> list[str]:
    """Значащие токены имени (без юр. форм) — для сопоставления с текстом/доменом."""
    return [t for t in _norm(name).split() if len(t) > 1]


def _load(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


# ------------------------- разведочная волна -------------------------------
def probe_specs(name: str, task: str = "") -> list[tuple[str, str, dict]]:
    """Национальный реестр для РФ; международные пробы для остальных компаний."""
    specs = [("directapi", "wikipedia_summary", {"query": name}),
             ("directapi", "gleif_entity", {"query": name})]
    country = recipes.country_hint(task)
    if country == "UZ":
        tax_ids = re.findall(r"\b(?:ИНН|STIR|TIN)[\s:#№=-]*(\d{9})\b", task, re.I)
        args = {"query": name}
        if len(set(tax_ids)) == 1:
            args["tax_id"] = tax_ids[0]
        specs.insert(0, ("directapi", "uz_company_records", args))
    if country == "FI":
        args = {"query": name}
        business_ids = recipes.fi_business_id_values(task)
        if len(business_ids) == 1:
            args["business_id"] = business_ids[0]
        specs.insert(0, ("directapi", "fi_company_records", args))
    if country in ("", "US") and not (recipes.RE_ORG.search(name) or recipes.inn_values(task)):
        ciks = list(dict.fromkeys(recipes.RE_CIK.findall(task)))
        query = ciks[0].zfill(10) if len(ciks) == 1 else name
        specs.insert(0, ("directapi", "sec_edgar", {"query": query}))
    if recipes.looks_russian(name, task):
        inns = list(dict.fromkeys(v for v in recipes.inn_values(task) if len(v) == 10))
        if len(inns) == 1:
            specs.insert(0, ("checko", "get_company", {"inn": inns[0]}))
        else:
            specs.insert(0, ("checko", "search", {"by": "name", "obj": "org", "query": name}))
    for registration_number in recipes.company_registration_values(task):
        specs.append(("directapi", "opencorporates_search", {"query": registration_number}))
    return specs


def parse_probes(results: list[dict]) -> dict:
    """Разобрать ответы разведочной волны в {sec, wikipedia, gleif, gleif_hint}."""
    out: dict = {"sec": None, "wikipedia": None, "gleif": None, "gleif_hint": None,
                 "checko": None, "fi_registry": None, "opencorporates_matches": []}
    for r in results:
        if not r.get("ok") or r.get("server") not in ("directapi", "checko"):
            continue
        j = _load(r.get("text", "") or "")
        if not isinstance(j, dict):
            continue
        tool = r.get("tool", "")
        if r.get("server") == "checko":
            data = j.get("data")
            args = r.get("args") or {}
            if isinstance(data, dict) and isinstance(data.get("Записи"), list):
                matches = [row for row in data["Записи"] if isinstance(row, dict)
                           and _norm(row.get("НаимСокр") or row.get("НаимПолн")) == _norm(args.get("query"))]
                data = matches[0] if len(matches) == 1 else None
            if isinstance(data, dict) and re.fullmatch(r"\d{10}", str(data.get("ИНН", ""))):
                if args.get("inn") and str(data["ИНН"]) != str(args["inn"]):
                    continue
                name = data.get("НаимСокр") or data.get("НаимПолн")
                if name:
                    out["checko"] = dict(name=name, inn=str(data["ИНН"]), ogrn=data.get("ОГРН"),
                        status=(data.get("Статус") or {}).get("Наим") if isinstance(data.get("Статус"), dict) else data.get("Статус"))
            continue
        if tool == "uz_company_records" and j.get("matched") and re.fullmatch(r"\d{9}", j.get("tax_id") or ""):
            args = r.get("args") or {}
            if ((args.get("tax_id") and args["tax_id"] == j["tax_id"]) or
                    (not args.get("tax_id") and _norm(args.get("query")) == _norm(j.get("name")))):
                out["uz_directory"] = j
        elif (tool == "fi_company_records" and not j.get("error") and j.get("matched")
              and j.get("official_registry_verified") and j.get("name")
              and recipes.RE_FI_BUSINESS_ID.fullmatch(j.get("business_id") or "")):
            args = r.get("args") or {}
            # Preserve legal forms here: rf/ry associations cannot become Oy namesakes.
            key = lambda s: " ".join(re.findall(r"\w+", (s or "").casefold()))
            current_names = j.get("current_names") or [j["name"]]
            if ((args.get("business_id") and args["business_id"] == j["business_id"]) or
                    (not args.get("business_id") and key(args.get("query")) in {key(n) for n in current_names})):
                out["fi_registry"] = j
        elif tool == "sec_edgar" and not j.get("error") and j.get("name"):
            out["sec"] = j
        elif tool == "wikipedia_summary" and not j.get("error") and j.get("title"):
            out["wikipedia"] = j
        elif tool == "gleif_entity":
            if not j.get("error") and j.get("legal_name"):
                out["gleif"] = j
            elif j.get("did_you_mean"):
                out["gleif_hint"] = j
        elif tool == "opencorporates_search" and not j.get("error"):
            out["opencorporates_matches"].extend(
                m for m in (j.get("matches") or []) if isinstance(m, dict) and m.get("name"))
    return out


# --------------------------- кандидаты -------------------------------------
def _add(cands: dict, name: str, source: str, **fields) -> dict:
    """Добавить/дополнить кандидата (склейка по нормализованному имени).

    origins — ОТКУДА взялось имя (реестровая запись / подсказка / запрос).
    sources — что его ПОДТВЕРЖДАЕТ (заполняется скорингом). Разделение
    принципиально: раньше это был один список, скоринг дописывал в него
    «wikipedia»/«domain», и нечёткая подсказка GLEIF («META S.R.L.») переставала
    выглядеть подсказкой — она набирала подтверждения и выигрывала."""
    key = _norm(name)
    if not key:
        return {}
    c = cands.get(key)
    if c and ((c.get("jurisdiction") and fields.get("jurisdiction")
               and c["jurisdiction"].split("-")[0] != fields["jurisdiction"].split("-")[0])
              or (c.get("inn") and fields.get("inn") and c["inn"] != fields["inn"])
              or (c.get("business_id") and fields.get("business_id") and c["business_id"] != fields["business_id"])):
        # Одинаковое имя в разных странах/с разными ИНН — разные кандидаты.
        key += ":" + str(fields.get("jurisdiction")) + ":" + str(fields.get("inn") or fields.get("business_id"))
        c = cands.get(key)
    if c is None:
        c = cands[key] = {"name": name, "norm": key, "origins": [], "sources": [],
                          "why": [], "score": 0, "jurisdiction": None, "lei": None,
                          "cik": None, "tickers": [], "reg_status": None,
                          "entity_status": None}
    if source not in c["origins"]:
        c["origins"].append(source)
    if source not in c["sources"]:
        c["sources"].append(source)
    # Более полное юр. имя предпочтительнее короткого («META» → «META PLATFORMS, INC.»).
    if len(name) > len(c["name"]):
        c["name"] = name
    for k, v in fields.items():
        if v not in (None, "", [], {}):
            c[k] = v
    return c


def build_candidates(query: str, probes: dict) -> list[dict]:
    """Собрать кандидатов юрлица из разведочной волны."""
    cands: dict[str, dict] = {}
    sec = probes.get("sec") or {}
    if sec.get("name"):
        _add(cands, sec["name"], "sec_edgar", cik=sec.get("cik"),
             tickers=sec.get("tickers") or [],
             jurisdiction=(f"US-{sec['state_of_incorporation']}"
                           if sec.get("state_of_incorporation") else "US"))
    ck = probes.get("checko") or {}
    if ck.get("name") and ck.get("inn"):
        _add(cands, ck["name"], "checko", inn=ck["inn"], ogrn=ck.get("ogrn"),
             jurisdiction="RU", entity_status=ck.get("status"))
    uz = probes.get("uz_directory") or {}
    if uz.get("name") and uz.get("tax_id"):
        _add(cands, uz["name"], "uz_directory", inn=uz["tax_id"], jurisdiction="UZ",
             registration_number=uz.get("registration_number"), directory_verified=True)
    fi = probes.get("fi_registry") or {}
    if fi.get("name") and fi.get("business_id"):
        _add(cands, fi["name"], "fi_registry", business_id=fi["business_id"], jurisdiction="FI",
             registration_number=fi.get("registration_number") or fi["business_id"],
             official_registry_verified=True, source_url=fi.get("source_url"))
    g = probes.get("gleif") or {}
    if g.get("legal_name"):
        _add(cands, g["legal_name"], "gleif", lei=g.get("lei"),
             jurisdiction=g.get("jurisdiction"),
             reg_status=g.get("registration_status"),
             entity_status=g.get("entity_status"))
    for match in probes.get("opencorporates_matches") or []:
        _add(cands, match["name"], "opencorporates",
             registration_number=match.get("company_number"),
             jurisdiction=match.get("jurisdiction"),
             reg_status=match.get("status"), source_url=match.get("url"))
    # other_matches/did_you_mean — ТОЛЬКО подсказки: похожее имя в реестре обычно
    # принадлежит другой компании, подтверждением это не считается.
    for nm in (g.get("other_matches") or []):
        _add(cands, nm, "gleif_hint")
    for nm in ((probes.get("gleif_hint") or {}).get("did_you_mean") or []):
        _add(cands, nm, "gleif_hint")
    wiki = probes.get("wikipedia") or {}
    if wiki.get("title"):
        _add(cands, wiki["title"], "wikipedia")
    # Исходный запрос — всегда в списке, чтобы было видно, от чего отталкивались.
    _add(cands, query, "query")
    return list(cands.values())


# ----------------------------- скоринг -------------------------------------
def _wiki_supports(cand: dict, wiki: dict) -> bool:
    """Подтверждает ли статья Wikipedia кандидата: все значащие токены его имени
    встречаются в заголовке/описании/тексте статьи. Страница значений («Мета —
    многозначный термин») не содержит «platforms» и подтверждением не станет."""
    if not wiki:
        return False
    hay = " ".join(str(wiki.get(k) or "") for k in
                   ("title", "description", "extract")).lower()
    toks = _tokens(cand["name"])
    return bool(toks) and all(re.search(r"(?<!\w)" + re.escape(t) + r"(?!\w)", hay) for t in toks)


def brand_match(name: str, domain: str) -> bool:
    """Перекликается ли доменное имя с названием компании (стем бренда).
    «Meta Platforms, Inc.» ↔ meta.com — да; ↔ example.org — нет."""
    toks = _tokens(name)
    if not toks or not domain:
        return False
    label = domain.split(".")[0].lower()
    flat = re.sub(r"[^a-z0-9]", "", "".join(toks))
    return bool(label) and (label == toks[0] or label == flat
                            or (len(label) > 2 and flat.startswith(label)))


def _domain_supports(cand: dict, domains: list[str]) -> bool:
    """Подтверждает ли официальный домен кандидата: стем бренда есть в имени домена."""
    return any(brand_match(cand["name"], d) for d in domains)


_BAD_REG_STATUS = ("LAPSED", "RETIRED", "ANNULLED", "DUPLICATE", "MERGED")


def _score(cand: dict, probes: dict, domains: list[str]) -> None:
    """Проставить score/why. Подтверждением считаются только НЕЗАВИСИМЫЕ источники."""
    score, why, confirms = 0, [], 0
    sec = probes.get("sec") or {}
    if "sec_edgar" in cand["sources"]:
        score += 3
        confirms += 1
        why.append(f"SEC EDGAR: CIK {cand.get('cik') or sec.get('cik') or '—'}"
                   + (f", тикер {', '.join(cand['tickers'])}" if cand.get("tickers") else ""))
    if "checko" in cand["sources"]:
        score += 3
        confirms += 1
        why.append(f"ЕГРЮЛ / Checko: ИНН {cand['inn']}, ОГРН {cand.get('ogrn') or '—'}")
    if "uz_directory" in cand["sources"]:
        score += 3
        confirms += 1
        why.append(f"Узбекские справочники: ИНН/STIR {cand['inn']}; не государственная выписка")
    if "fi_registry" in cand["sources"]:
        score += 3
        confirms += 1
        why.append(f"PRH/YTJ: Торговый реестр Финляндии, Y-tunnus {cand['business_id']}")
    if _wiki_supports(cand, probes.get("wikipedia") or {}):
        if "wikipedia" not in cand["sources"]:
            cand["sources"].append("wikipedia")
        score += 2
        confirms += 1
        why.append(f"Wikipedia: «{(probes['wikipedia'] or {}).get('title')}»")
    if _domain_supports(cand, domains):
        if "domain" not in cand["sources"]:
            cand["sources"].append("domain")
        score += 2
        why.append(f"совпадение имени с доменом (не доказательство владения): {', '.join(domains[:2])}")
    if "gleif" in cand["sources"]:
        rs = (cand.get("reg_status") or "").upper()
        if rs in _BAD_REG_STATUS:
            # Протухшая регистрация LEI — сильнейший сигнал «это не оператор бренда».
            score -= 2
            why.append(f"GLEIF: регистрация LEI {rs} — запись неактуальна")
        else:
            score += 1
            confirms += 1
            why.append(f"GLEIF: LEI {cand.get('lei') or '—'}"
                       + (f", {cand['jurisdiction']}" if cand.get("jurisdiction") else ""))
    if "opencorporates" in cand["sources"]:
        score += 1
        why.append(f"OpenCorporates: номер {cand.get('registration_number') or '—'}, "
                   f"статус {cand.get('reg_status') or 'не указан'}; агрегатор, "
                   "первичная запись требует проверки")
    if "gleif_hint" in cand["sources"] and "gleif" not in cand["sources"]:
        why.append("GLEIF: похожее имя в реестре (не подтверждено)")
    # Согласие юрисдикций SEC и GLEIF — слабый, но независимый плюс.
    jur, sec_state = (cand.get("jurisdiction") or ""), sec.get("state_of_incorporation")
    if jur and sec_state and jur.upper().startswith("US") and "sec_edgar" in cand["sources"]:
        score += 1
        why.append(f"юрисдикция согласована: {jur}")
    cand["score"], cand["why"], cand["confirms"] = score, why, confirms


def resolve(query: str, probes: dict, domains: list[str] | None = None, country: str = "") -> dict:
    """Выбрать юрлицо. Чистая функция: вход — разобранные пробы, выход — решение.

    legal_name is None → сущность НЕ опознана; вызывающий код обязан не утверждать
    данные реестров и строить досье только по инфраструктуре."""
    domains = list(domains or [])
    cands = build_candidates(query, probes)
    for c in cands:
        _score(c, probes, domains)
        origins = c["origins"]
        # ЖЁСТКИЕ правила отбраковки — применяются ДО сравнения баллов, потому
        # что балл тут обманчив: односложный бренд («meta») содержится и в
        # статье, и в домене, поэтому любой омоним набирает подтверждения.
        if (c.get("reg_status") or "").upper() in _BAD_REG_STATUS:
            # Протухшая запись реестра не может быть ответом ни при каком балле.
            c["rejected"] = (f"регистрация LEI в статусе {c['reg_status']} — "
                             f"запись не актуальна")
        elif country and c.get("jurisdiction") and c["jurisdiction"].split("-")[0].upper() != country.upper():
            c["rejected"] = "юрисдикция противоречит стране в запросе"
        elif "opencorporates" in origins and not ({"sec_edgar", "gleif", "checko", "uz_directory", "fi_registry"} & set(origins)):
            c["rejected"] = "OpenCorporates — агрегатор; первичный реестр отдельно не подтверждён"
        elif not ({"sec_edgar", "gleif", "checko", "uz_directory", "fi_registry"} & set(origins)):
            # Имя пришло из нечёткой подсказки, заголовка статьи или самого
            # запроса — то есть ни один реестр такого юрлица НЕ утверждал.
            # Приписать цели такое имя хуже, чем честно сказать «не опознали».
            c["rejected"] = ("ни один реестр не подтвердил это юр. лицо "
                             "(имя из подсказки/статьи, а не из записи реестра)")
    ranked = sorted((c for c in cands if not c.get("rejected")),
                    key=lambda c: (c["score"], "sec_edgar" in c["sources"], len(c["name"])),
                    reverse=True)
    winner = ranked[0] if ranked else None
    if winner and winner["score"] < MIN_SCORE:
        winner = None
    for c in cands:
        c["chosen"] = c is winner
    confirms = winner["confirms"] if winner else 0
    confidence = "высокая" if confirms >= 2 else "средняя" if confirms == 1 else "низкая"
    if winner and "uz_directory" in winner["origins"]:
        confidence = "средняя"  # Несколько перепечаток и домен не заменяют первичный реестр.
    sec = probes.get("sec") or {}
    return {
        "query": query,
        "legal_name": winner["name"] if winner else None,
        "inn": (winner or {}).get("inn"),
        "ogrn": (winner or {}).get("ogrn"),
        "lei": (winner or {}).get("lei"),
        "cik": (winner or {}).get("cik"),
        "tickers": (winner or {}).get("tickers") or [],
        "jurisdiction": (winner or {}).get("jurisdiction") or country or None,
        "jurisdiction_basis": "source" if winner else "user" if country else None,
        "directory_verified": (winner or {}).get("directory_verified", False),
        "registration_number": (winner or {}).get("registration_number"),
        "business_id": (winner or {}).get("business_id"),
        "official_registry_verified": (winner or {}).get("official_registry_verified", False),
        "confirms": confirms,
        "confidence": confidence if winner else "низкая",
        "candidates": sorted(cands, key=lambda c: (-c["score"], c["name"])),
        "domains": domains,
    }


def refresh_identity(current: dict | None, query: str, results: list[dict],
                     domains: list[str]) -> dict | None:
    """Поздние реестры дополняют ту же сущность; чужие идентификаторы не склеиваем."""
    recovered = resolve(query, parse_probes(results), domains, ((current or {}).get("jurisdiction") or "").split("-")[0])
    if not recovered.get("legal_name"):
        return current
    if (current or {}).get("legal_name"):
        if _norm(current["legal_name"]) != _norm(recovered["legal_name"]):
            return current
        old_country, new_country = jurisdiction_code(current), jurisdiction_code(recovered)
        if old_country and new_country and old_country != new_country:
            return current
        for key in ("lei", "cik", "inn", "ogrn", "business_id"):
            if current.get(key) and recovered.get(key) and current[key] != recovered[key]:
                return current
        # При временном отказе одного реестра не теряем уже подтверждённые поля.
        for key in ("lei", "cik", "inn", "ogrn", "business_id", "registration_number", "official_registry_verified", "tickers", "jurisdiction"):
            if not recovered.get(key) and current.get(key):
                recovered[key] = current[key]
    recovered["domains"] = domains
    recovered["domain_candidates"] = (current or {}).get("domain_candidates", [])
    return recovered


def registry_name(res: dict) -> str:
    """Имя, которым опрашивать реестры: каноническое юр. имя, иначе исходный запрос."""
    return res.get("legal_name") or res.get("query") or ""


def jurisdiction_code(res: dict) -> str:
    """Двухбуквенный код страны из юрисдикции GLEIF/SEC («US-DE» → «us») — для
    OpenCorporates, который без страны ловит однофамильцев из чужих реестров."""
    jur = (res.get("jurisdiction") or "").strip()
    return jur.split("-")[0].lower() if len(jur) >= 2 else ""


# --------------------------- домены компании -------------------------------
def domain_candidates(name: str, probes: dict, limit: int = 10) -> list[str]:
    """Кандидаты официальных доменов, лучшие — первыми.

    Сначала «ссылочный профиль» статьи Wikipedia (там официальный сайт почти
    всегда в топе по числу ссылок), затем перебор «<бренд>.<tld>». Перебор один
    ловил чужие домены: для компании «Alfa» с сайтом alfabank.ru первым резолвился
    посторонний alfa.com, и всё инфраструктурное досье уходило не туда."""
    out: list[str] = []
    wiki = probes.get("wikipedia") or {}
    for card in (probes.get("uz_directory") or {}).get("records", []):
        for email in recipes.RE_EMAIL.findall(card.get("evidence_text") or ""):
            d = email.split("@", 1)[1].lower()
            if brand_match(name, d) and d not in out:
                out.append(d)
    toks = _tokens(name)
    flat = re.sub(r"[^a-z0-9]", "", "".join(toks))
    for item in (wiki.get("external_domains") or []):
        d = (item.get("domain") or "").lower().strip(". ")
        if not d or any(d == h or d.endswith("." + h) for h in _NOT_OFFICIAL):
            continue
        label = d.split(".")[0]
        # Домен считаем «официальным кандидатом», только если он перекликается с
        # именем компании — иначе в список лезут партнёры и подрядчики из статьи.
        if toks and (label.startswith(toks[0]) or (flat and flat.startswith(label))
                     or label == flat):
            if d not in out:
                out.append(d)
    for d in recipes.company_domain_candidates(name):
        if d not in out:
            out.append(d)
    return out[:limit]
