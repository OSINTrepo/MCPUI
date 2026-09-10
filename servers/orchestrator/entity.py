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
    toks = [t for t in re.split(r"[^\w]+", (name or "").lower()) if t]
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
def probe_specs(name: str) -> list[tuple[str, str, dict]]:
    """Вызовы разведочной волны — (server, tool, args). Дёшево и keyless:
    три запроса, каждый даёт независимый угол на то, «кто это вообще такие»."""
    return [
        ("directapi", "sec_edgar", {"query": name}),
        ("directapi", "wikipedia_summary", {"query": name}),
        ("directapi", "gleif_entity", {"query": name}),
    ]


def parse_probes(results: list[dict]) -> dict:
    """Разобрать ответы разведочной волны в {sec, wikipedia, gleif, gleif_hint}."""
    out: dict = {"sec": None, "wikipedia": None, "gleif": None, "gleif_hint": None}
    for r in results:
        if not r.get("ok") or r.get("server") != "directapi":
            continue
        j = _load(r.get("text", "") or "")
        if not isinstance(j, dict):
            continue
        tool = r.get("tool", "")
        if tool == "sec_edgar" and not j.get("error") and j.get("name"):
            out["sec"] = j
        elif tool == "wikipedia_summary" and not j.get("error") and j.get("title"):
            out["wikipedia"] = j
        elif tool == "gleif_entity":
            if not j.get("error") and j.get("legal_name"):
                out["gleif"] = j
            elif j.get("did_you_mean"):
                out["gleif_hint"] = j
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
    g = probes.get("gleif") or {}
    if g.get("legal_name"):
        _add(cands, g["legal_name"], "gleif", lei=g.get("lei"),
             jurisdiction=g.get("jurisdiction"),
             reg_status=g.get("registration_status"),
             entity_status=g.get("entity_status"))
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
    return bool(toks) and all(t in hay for t in toks)


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
        confirms += 1
        why.append(f"официальный домен: {', '.join(domains[:2])}")
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
    if "gleif_hint" in cand["sources"] and "gleif" not in cand["sources"]:
        why.append("GLEIF: похожее имя в реестре (не подтверждено)")
    # Согласие юрисдикций SEC и GLEIF — слабый, но независимый плюс.
    jur, sec_state = (cand.get("jurisdiction") or ""), sec.get("state_of_incorporation")
    if jur and sec_state and jur.upper().startswith("US") and "sec_edgar" in cand["sources"]:
        score += 1
        why.append(f"юрисдикция согласована: {jur}")
    cand["score"], cand["why"], cand["confirms"] = score, why, confirms


def resolve(query: str, probes: dict, domains: list[str] | None = None) -> dict:
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
        elif not ({"sec_edgar", "gleif"} & set(origins)):
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
        c["chosen"] = bool(winner and c["norm"] == winner["norm"])
    confirms = winner["confirms"] if winner else 0
    confidence = "высокая" if confirms >= 2 else "средняя" if confirms == 1 else "низкая"
    sec = probes.get("sec") or {}
    return {
        "query": query,
        "legal_name": winner["name"] if winner else None,
        "lei": (winner or {}).get("lei"),
        "cik": (winner or {}).get("cik") or (sec.get("cik") if winner else None),
        "tickers": (winner or {}).get("tickers") or [],
        "jurisdiction": (winner or {}).get("jurisdiction"),
        "confirms": confirms,
        "confidence": confidence if winner else "низкая",
        "candidates": sorted(cands, key=lambda c: (-c["score"], c["name"])),
        "domains": domains,
    }


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
