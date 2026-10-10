#!/usr/bin/env python3
"""directapi — self-wrapped прямые публичные API (без ключей).

Закрывает бесплатные источники, которых не было отдельными MCP-серверами:
  - rdap_domain / rdap_ip — RDAP (registrar, даты, NS, сеть/AS/организация)
  - crtsh                 — Certificate Transparency (поддомены из сертификатов)
  - dns_records           — A/AAAA/MX/NS/TXT + SPF/DMARC/DKIM/MTA-STS/BIMI
  - gleif_entity          — глобальный реестр LEI (юр. идентичность + связи)
  - opencorporates_*      — реестр юрлиц и должностных лиц (директора/руководство)
  - sec_edgar             — юр. сведения и отчётность компаний США (SEC, keyless)
  - wikipedia_summary     — описание + ссылочный профиль статьи (keyless)
  - web_inspect           — web-check-инспекция сайта: заголовки/безопасность/CT
  - whois_history         — история регистрации (WhoisXML → резерв Whoxy)
  - crtsh                 — CT-поддомены (crt.sh → резерв certspotter)
  - google_cse            — Google Programmable Search (тематические CSE + дорки)

Все инструменты возвращают JSON-строку. Ошибки — тоже JSON ({"error": ...}),
чтобы оркестратор корректно классифицировал недоступность источника.

Запуск: stdio (supergateway оборачивает в Streamable HTTP). См. реестр.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.whois_history_cache import canonical_domain, get_history

mcp = FastMCP("directapi")

_UA = "osint-directapi/1.0 (+https://github.com/soxoj/awesome-osint-mcp-servers)"
_HDRS = {"User-Agent": _UA, "Accept": "application/json"}

# Платные ключи (опциональны) — из окружения контейнера (.env → compose env).
# Censys Platform требует ДВА заголовка (PAT + Organization-ID), WhoisXML — ключ
# в query. Оба hosted-MCP вендоров нам не подошли (Censys — 2 заголовка, WhoisXML —
# интерактивный OAuth), поэтому REST этих сервисов обёрнут здесь. Без ключей
# инструменты честно отвечают «нужен ключ» — оркестратор это классифицирует.
CENSYS_PAT = os.environ.get("CENSYS_PAT", "").strip()
CENSYS_ORG = os.environ.get("CENSYS_ORG_ID", "").strip()
WHOISXML_KEY = os.environ.get("WHOISXML_API_KEY", "").strip()
# Whoxy — резервный провайдер WHOIS History. Нужен, когда у WhoisXML кончились
# кредиты/ключ (реальный кейс) — тогда история берётся из Whoxy без простоя.
# Студентам Whoxy даёт бесплатный ключ (10k запросов history). whoxy.com
WHOXY_KEY = os.environ.get("WHOXY_API_KEY", "").strip()
# OpenCorporates: реестр юрлиц/должностных лиц. Без ключа v0.4 отдаёт ограниченный
# набор (и часто 401 на карточку) — тогда инструмент честно говорит «нужен ключ».
OPENCORPORATES_KEY = os.environ.get("OPENCORPORATES_API_KEY", "").strip()
# Google Programmable Search (CSE) через Custom Search JSON API. Нужен API-ключ
# (console.cloud.google.com → Custom Search API, 100 запросов/сутки бесплатно).
# GOOGLE_CSE_DEFAULT_CX — «поиск по всему вебу» CSE для дорк-движков (site:/filetype:).
GOOGLE_CSE_KEY = os.environ.get("GOOGLE_CSE_API_KEY", "").strip()
GOOGLE_CSE_DEFAULT_CX = os.environ.get("GOOGLE_CSE_DEFAULT_CX", "").strip()
# Serper.dev — SERP-провайдер (Google-результаты по простому ключу). Основной
# бэкенд веб-поиска: Google Custom Search JSON API закрыт для НОВЫХ проектов
# (freeze — 403 «project does not have access»), а Serper выдаёт новые ключи сразу.
SERPER_KEY = os.environ.get("SERPER_API_KEY", "").strip()


async def _get_json(url: str, *, params: dict | None = None, timeout: float = 20.0,
                    retries: int = 1, headers: dict | None = None
                    ) -> tuple[dict | list | None, str | None]:
    """GET → (json, error). Повторяет при сетевых сбоях/5xx (crt.sh капризен).
    headers переопределяет _HDRS (напр. SEC требует контактный User-Agent)."""
    last = "unknown error"
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         headers=headers or _HDRS) as c:
                r = await c.get(url, params=params)
                if r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                    continue
                if r.status_code == 404:
                    return None, "not found (404)"
                if r.status_code >= 400:
                    return None, f"HTTP {r.status_code}"
                if not r.text.strip():
                    return None, "empty response"
                return r.json(), None
        except (httpx.TimeoutException,) as e:
            last = "timeout"
        except Exception as e:  # noqa: BLE001 — сеть/парсинг: сообщаем как есть
            last = type(e).__name__
        if attempt < retries:
            await asyncio.sleep(1.5)
    return None, last


# --------------------------------- RDAP ------------------------------------
@mcp.tool()
async def rdap_domain(domain: str) -> str:
    """RDAP по домену: регистратор, даты (создание/истечение/изменение), статусы,
    nameservers, контакты. Аналог WHOIS в структурированном виде (rdap.org).
    Передай доменное имя (example.com)."""
    domain = (domain or "").strip().lower().lstrip("*.").split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    data, err = await _get_json(f"https://rdap.org/domain/{domain}", retries=1)
    if err:
        return json.dumps({"error": err, "domain": domain}, ensure_ascii=False)
    events = {e.get("eventAction"): e.get("eventDate")
              for e in (data.get("events") or [])}

    def _vcard_fn(ent: dict) -> str | None:
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn" and item[3]:
                return item[3]
        return None

    contacts = []
    registrar = None
    for ent in (data.get("entities") or [])[:6]:
        nm = _vcard_fn(ent)
        contacts.append({"roles": ent.get("roles"), "name": nm,
                         "handle": ent.get("handle")})
        if not registrar and "registrar" in (ent.get("roles") or []):
            registrar = nm
    out = {
        "domain": domain,
        "handle": data.get("handle"),
        "status": data.get("status"),
        "registrar": registrar,          # реальное имя регистратора (не выдумывать!)
        "registration": events.get("registration"),
        "expiration": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": [n.get("ldhName") for n in (data.get("nameservers") or [])],
        "entities": contacts,
    }
    return json.dumps(out, ensure_ascii=False)


@mcp.tool()
async def rdap_ip(ip: str) -> str:
    """RDAP по IP: диапазон сети, организация-владелец, AS/страна, статусы.
    Частично закрывает разбор RIPE/AS. Передай IPv4/IPv6-адрес."""
    ip = (ip or "").strip()
    if not ip:
        return json.dumps({"error": "no ip"}, ensure_ascii=False)
    data, err = await _get_json(f"https://rdap.org/ip/{ip}", retries=1)
    if err:
        return json.dumps({"error": err, "ip": ip}, ensure_ascii=False)
    org = None
    for ent in (data.get("entities") or []):
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if item and item[0] == "fn":
                org = item[3]
                break
        if org:
            break
    out = {
        "ip": ip,
        "handle": data.get("handle"),
        "name": data.get("name"),
        "range": f"{data.get('startAddress')} - {data.get('endAddress')}",
        "cidr": [c.get("v4prefix") or c.get("v6prefix") for c in (data.get("cidr0_cidrs") or [])],
        "country": data.get("country"),
        "type": data.get("type"),
        "organization": org,
        "status": data.get("status"),
    }
    return json.dumps(out, ensure_ascii=False)


# --------------------------------- crt.sh ----------------------------------
async def _ct_crtsh(domain: str) -> tuple[set[str], set[str], int, str | None]:
    """CT-поддомены/эмитенты из crt.sh. Возвращает (names, issuers, records, err)."""
    data, err = await _get_json("https://crt.sh/", params={"q": f"%.{domain}",
                                "output": "json"}, timeout=40.0, retries=2)
    if err:
        return set(), set(), 0, err
    names, issuers = set(), set()
    for c in (data or []):
        for n in str(c.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and "@" not in n:
                names.add(n)
        if c.get("issuer_name"):
            issuers.add(c["issuer_name"][:80])
    return names, issuers, len(data or []), None


async def _ct_certspotter(domain: str) -> tuple[set[str], set[str], int]:
    """Резервный источник CT — SSLMate certspotter (keyless, есть rate-limit).
    Включается, когда crt.sh недоступен/пуст (частая проблема — см. отзыв)."""
    data, err = await _get_json(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true",
                "expand": "dns_names"}, timeout=30.0, retries=1)
    if err or not isinstance(data, list):
        return set(), set(), 0
    names, issuers = set(), set()
    for iss in data:
        for n in (iss.get("dns_names") or []):
            n = str(n).strip().lower().lstrip("*.")
            if n and "@" not in n:
                names.add(n)
        ik = (iss.get("issuer") or {}).get("name")
        if ik:
            issuers.add(str(ik)[:80])
    return names, issuers, len(data)


@mcp.tool()
async def crtsh(domain: str) -> str:
    """Поддомены из Certificate Transparency. Основной источник crt.sh; при его
    недоступности/пустом ответе (частое явление) автоматически подключается
    резервный CT-источник certspotter. Возвращает уникальные поддомены, эмитентов
    и какой источник сработал. Передай домен."""
    domain = (domain or "").strip().lower().lstrip("*.").split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    names, issuers, records, err = await _ct_crtsh(domain)
    source = "crt.sh"
    # crt.sh упал ИЛИ вернул пусто → пробуем certspotter (устойчивость к сбоям crt.sh)
    if err or not names:
        cs_names, cs_iss, cs_rec = await _ct_certspotter(domain)
        if cs_names:
            names |= cs_names
            issuers |= cs_iss
            records += cs_rec
            source = "certspotter (fallback)" if err or records == cs_rec else "crt.sh + certspotter"
    if not names:
        return json.dumps({"error": err or "пусто", "domain": domain,
                           "note": "оба CT-источника (crt.sh, certspotter) не ответили; "
                           "покрытие поддоменов дают VirusTotal + subfinder"},
                          ensure_ascii=False)
    subs = sorted(n for n in names if n.endswith(domain))
    out = {"domain": domain, "source": source, "cert_records": records,
           "subdomains_count": len(subs), "subdomains": subs[:300],
           "issuers": sorted(issuers)[:20]}
    return json.dumps(out, ensure_ascii=False)


# --------------------------------- DNS -------------------------------------
# Обычный DNS (UDP/TCP через резолвер контейнера), а НЕ DNS-over-HTTPS: на хостах
# с TLS-перехватом (напр. российский CA у GigaChat) DoH-эндпоинты (dns.google)
# отдают самоподписанный сертификат и валидация падает. Обычный DNS не шифруется —
# перехватывать нечего.
def _resolve(name: str, rrtype: str, lifetime: float = 3.0) -> list[str]:
    try:
        import dns.resolver
    except Exception:
        return []
    try:
        ans = dns.resolver.resolve(name, rrtype, lifetime=lifetime)
    except Exception:
        return []
    out = []
    for r in ans:
        if rrtype == "TXT":
            out.append("".join(p.decode() if isinstance(p, bytes) else str(p)
                               for p in r.strings))
        elif rrtype == "MX":
            out.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
        else:
            out.append(r.to_text().rstrip('.'))
    return out


@mcp.tool()
async def dns_records(domain: str) -> str:
    """DNS-записи домена (A/AAAA/MX/NS/TXT) + разбор политики почты SPF и DMARC.
    Заполняет таблицу почтовой безопасности референс-отчёта. Передай домен."""
    domain = (domain or "").strip().lower().lstrip("*.").split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    a, aaaa, mx, ns, txt, dmarc, mtasts, bimi = await asyncio.gather(
        asyncio.to_thread(_resolve, domain, "A"),
        asyncio.to_thread(_resolve, domain, "AAAA"),
        asyncio.to_thread(_resolve, domain, "MX"),
        asyncio.to_thread(_resolve, domain, "NS"),
        asyncio.to_thread(_resolve, domain, "TXT"),
        asyncio.to_thread(_resolve, f"_dmarc.{domain}", "TXT"),
        asyncio.to_thread(_resolve, f"_mta-sts.{domain}", "TXT"),
        asyncio.to_thread(_resolve, f"default._bimi.{domain}", "TXT"))
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    mtasts_rec = next((t for t in mtasts if t.lower().startswith("v=stsv1")), None)
    bimi_rec = next((t for t in bimi if t.lower().startswith("v=bimi1")), None)
    # DKIM: перебираем частые селекторы параллельно (нет способа перечислить их через DNS).
    _dkim_sels = ("default", "google", "selector1", "selector2", "s1", "s2", "k1",
                  "mail", "dkim")
    dkim_results = await asyncio.gather(
        *[asyncio.to_thread(_resolve, f"{sel}._domainkey.{domain}", "TXT")
          for sel in _dkim_sels])
    dkim = {}
    for sel, recs in zip(_dkim_sels, dkim_results):
        hit = next((t for t in recs if "v=dkim1" in t.lower() or "k=rsa" in t.lower()
                    or "p=" in t.lower()), None)
        if hit:
            dkim[sel] = hit[:200]
    out = {
        "domain": domain,
        "A": a, "AAAA": aaaa, "MX": mx, "NS": ns, "TXT": txt,
        "SPF": spf,
        "DMARC": dmarc_rec,
        "MTA_STS": mtasts_rec,
        "BIMI": bimi_rec,
        "DKIM": dkim or None,
    }
    return json.dumps(out, ensure_ascii=False)


# --------------------------------- GLEIF -----------------------------------
async def _gleif_names(rel_url: str, limit: int = 5) -> list[str]:
    data, err = await _get_json(rel_url, timeout=15.0)
    if err or not isinstance(data, dict):
        return []
    recs = data.get("data")
    if isinstance(recs, dict):
        recs = [recs]
    names = []
    for rec in (recs or [])[:limit]:
        nm = (((rec.get("attributes") or {}).get("entity") or {})
              .get("legalName") or {}).get("name")
        if nm:
            names.append(nm)
    return names


# Юридические формы, которые не влияют на идентичность названия.
_LEGAL_FORMS = {
    "ag", "sa", "s", "a", "se", "nv", "bv", "plc", "ltd", "limited", "inc",
    "llc", "gmbh", "spa", "srl", "oy", "ab", "as", "aktiengesellschaft",
    "corp", "corporation", "incorporated",
    "pao", "oao", "ooo", "zao", "пао", "оао", "ооо", "зао", "ао",
}


def _norm_company(name: str) -> str:
    """Нормализация названия для сравнения: без пунктуации и юр. формы.
    «INDRA SISTEMAS, S.A.» == «Indra Sistemas», но «Siemens AG» != «Siemens Energy AG»."""
    toks = [t for t in re.split(r"[^\w]+", (name or "").lower()) if t]
    while toks and toks[-1] in _LEGAL_FORMS:
        toks.pop()
    return " ".join(toks)


async def _gleif_fuzzy(query: str, limit: int = 5) -> list[str]:
    """Похожие названия из GLEIF (fuzzycompletions) — ТОЛЬКО как подсказка
    оператору. НЕ использовать как найденное юрлицо: похожее имя часто
    принадлежит совсем другой компании. Пусто при любой неудаче."""
    data, err = await _get_json("https://api.gleif.org/api/v1/fuzzycompletions",
                                params={"field": "entity.legalName", "q": query},
                                timeout=15.0)
    if err or not isinstance(data, dict):
        return []
    names: list[str] = []
    for item in (data.get("data") or [])[:limit]:
        nm = (item.get("attributes") or {}).get("value")
        if nm and nm not in names:
            names.append(nm)
    return names


@mcp.tool()
async def gleif_entity(query: str) -> str:
    """Глобальный реестр LEI (GLEIF, бесплатно): по названию компании или коду LEI
    возвращает юридическое имя, адрес, юрисдикцию, регистрационный номер, статус и
    связи (материнская/дочерние). Передай название компании или 20-значный LEI."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    d = None
    other_matches: list[str] = []
    if len(query) == 20 and query.isalnum():
        # Уже LEI — прямая карточка.
        rec, err = await _get_json(f"https://api.gleif.org/api/v1/lei-records/{query}",
                                   timeout=15.0)
        if err:
            return json.dumps({"error": err, "lei": query}, ensure_ascii=False)
        d = rec.get("data") or {}
    else:
        # Поиск по названию с ранжированием по релевантности (lei-records filter
        # точнее fuzzycompletions: возвращает реальные юрлица + полную карточку
        # сразу). Из топа берём точное совпадение имени, иначе — первый.
        srch, err = await _get_json(
            "https://api.gleif.org/api/v1/lei-records",
            params={"filter[entity.legalName]": query, "page[size]": 5}, timeout=15.0)
        if err:
            return json.dumps({"error": err, "query": query}, ensure_ascii=False)
        cands = srch.get("data") or []
        def _nm(rec):
            return (((rec.get("attributes") or {}).get("entity") or {})
                    .get("legalName") or {}).get("name") or ""
        # Совпадением считаем только РАВЕНСТВО нормализованных имён (без пунктуации
        # и юр. формы). Брать cands[0] «на всякий случай» нельзя: на «Siemens AG»
        # GLEIF отдаёт «Siemens Energy AG» — другое юрлицо, и досье ушло бы не туда.
        d = next((c for c in cands if _norm_company(_nm(c)) == _norm_company(query)), None)
        if d is None:
            # Точного совпадения нет (или cands пуст). Пробуем через fuzzy: GLEIF
            # иногда хранит иную пунктуацию («INDRA SISTEMAS, S.A.» вместо
            # «Indra Sistemas SA»), но fuzzycompletions находит правильное имя, а
            # filter[entity.legalName] по ЭТОМУ имени уже возвращает карточку.
            hints = await _gleif_fuzzy(query)
            for hint in hints[:3]:
                if _norm_company(hint) != _norm_company(query):
                    continue
                srch2, err2 = await _get_json(
                    "https://api.gleif.org/api/v1/lei-records",
                    params={"filter[entity.legalName]": hint, "page[size]": 5},
                    timeout=15.0)
                if err2:
                    continue
                cands2 = srch2.get("data") or []
                d = next((c for c in cands2 if _norm_company(_nm(c)) == _norm_company(query)), None)
                if d:
                    cands = cands2
                    break
        if d is None:
            hints = await _gleif_fuzzy(query)
            return json.dumps({
                "query": query,
                "error": "в GLEIF нет точного совпадения по юридическому названию",
                "hint": "уточните ЮРИДИЧЕСКОЕ имя или передайте 20-значный LEI",
                "did_you_mean": hints or [_nm(c) for c in cands][:5],
            }, ensure_ascii=False)
        other_matches = [_nm(c) for c in cands if c is not d][:4]
    a = d.get("attributes") or {}
    ent = a.get("entity") or {}
    reg = a.get("registration") or {}
    la = ent.get("legalAddress") or {}
    rel = d.get("relationships") or {}
    # 3) связи (best-effort, короткие GET-ы)
    parents, children = [], []
    dp = ((rel.get("ultimate-parent") or {}).get("links") or {}).get("related")
    dc = ((rel.get("direct-children") or {}).get("links") or {}).get("related")
    if dp:
        parents = await _gleif_names(dp, limit=1)
    if dc:
        children = await _gleif_names(dc, limit=8)
    out = {
        "lei": a.get("lei"),
        "legal_name": (ent.get("legalName") or {}).get("name"),
        "address": {"lines": la.get("addressLines"), "city": la.get("city"),
                    "region": la.get("region"), "country": la.get("country"),
                    "postal_code": la.get("postalCode")},
        "jurisdiction": ent.get("jurisdiction"),
        "legal_form": (ent.get("legalForm") or {}).get("id"),
        "registration_number": ent.get("registeredAs"),
        "registration_authority": (ent.get("registeredAt") or {}).get("id"),
        "entity_status": ent.get("status"),
        "registration_status": reg.get("status"),
        "initial_registration": reg.get("initialRegistrationDate"),
        "last_update": reg.get("lastUpdateDate"),
        "ultimate_parent": parents[0] if parents else None,
        "direct_children": children,
        # Другие похожие юрлица в GLEIF — для контекста (возможно, нужен один из них).
        "other_matches": other_matches,
    }
    return json.dumps(out, ensure_ascii=False)


# ------------------------- Censys Platform (ключ) --------------------------
def _censys_headers(accept: str) -> dict:
    """Заголовки Censys Platform. Organization-ID добавляем ТОЛЬКО если задан:
    lookup-эндпоинты (host/cert) работают и по одному PAT (free/research), а
    пустой заголовок ничего не ломает, но и не нужен. Search требует org ID."""
    h = {"Authorization": f"Bearer {CENSYS_PAT}", "Accept": accept, "User-Agent": _UA}
    if CENSYS_ORG:
        h["X-Organization-ID"] = CENSYS_ORG
    return h


@mcp.tool()
async def censys_host(ip: str) -> str:
    """Censys Platform: детальная карточка хоста по IP — открытые порты, сервисы,
    баннеры, сертификаты, ASN, гео. Требует ключ (CENSYS_PAT + CENSYS_ORG_ID).
    Заполняет глубину по инфраструктуре (аналог reverse-IP/скан-данных из отчёта).
    Работает по одному CENSYS_PAT (lookup доступен и на free/research-аккаунте)."""
    if not CENSYS_PAT:
        return json.dumps({"error": "нужен ключ Censys (CENSYS_PAT)"}, ensure_ascii=False)
    ip = (ip or "").strip()
    if not ip:
        return json.dumps({"error": "no ip"}, ensure_ascii=False)
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.get(url, headers=_censys_headers(
                "application/vnd.censys.api.v3.host.v1+json"))
            if r.status_code in (401, 403):
                return json.dumps({"error": "нужен ключ (Censys 401/403)"},
                                  ensure_ascii=False)
            r.raise_for_status()
            # Слимим до ключевых полей: raw JSON Censys огромный, а обрезка строки
            # [:6000] рвала его на середине → невалидный JSON у потребителя.
            res = ((r.json() or {}).get("result") or {}).get("resource") or r.json()
            asn = res.get("autonomous_system") or {}
            loc = res.get("location") or {}
            svcs = []
            for s in (res.get("services") or [])[:25]:
                soft = s.get("software") or []
                svcs.append({"port": s.get("port"), "protocol": s.get("protocol")
                             or s.get("service_name"),
                             "software": [x.get("product") for x in soft if isinstance(x, dict)][:3],
                             "tls": bool(s.get("tls") or s.get("certificate"))})
            out = {"ip": res.get("ip") or ip,
                   "asn": asn.get("asn"), "as_name": asn.get("name") or asn.get("description"),
                   "country": loc.get("country"), "city": loc.get("city"),
                   "os": (res.get("operating_system") or {}).get("product"),
                   "service_count": len(res.get("services") or []),
                   "services": svcs}
            return json.dumps(out, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})", "ip": ip},
                          ensure_ascii=False)


@mcp.tool()
async def censys_domain(domain: str) -> str:
    """Censys Platform: поиск хостов/сертификатов, связанных с доменом (веб-присутствие,
    инфраструктура). Search-эндпоинт Censys требует ОРГАНИЗАЦИЮ: одного PAT мало
    (free-аккаунту доступен только lookup). Нужны CENSYS_PAT + CENSYS_ORG_ID."""
    if not CENSYS_PAT:
        return json.dumps({"error": "нужен ключ Censys (CENSYS_PAT)"}, ensure_ascii=False)
    if not CENSYS_ORG:
        return json.dumps({"error": "нужен CENSYS_ORG_ID: search Censys недоступен на "
                           "free-аккаунте (только lookup). Дают research/платный доступ."},
                          ensure_ascii=False)
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    url = "https://api.platform.censys.io/v3/global/search/query"
    body = {"query": f'web.endpoints.http.host="{domain}" or '
            f'services.tls.certificates.leaf_data.subject.common_name="{domain}"',
            "page_size": 25}
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.post(url, headers={**_censys_headers("application/json"),
                             "Content-Type": "application/json"}, json=body)
            if r.status_code in (401, 403):
                return json.dumps({"error": "нужен ключ (Censys 401/403)"},
                                  ensure_ascii=False)
            r.raise_for_status()
            # Слимим hits до валидного JSON (raw обрезался [:6000] в невалидный).
            data = r.json() or {}
            hits = (data.get("result") or {}).get("hits") or data.get("hits") or []
            slim = []
            for h in hits[:25]:
                res = h.get("resource") or h
                slim.append({"ip": res.get("ip"),
                             "name": res.get("name") or res.get("dns"),
                             "asn": (res.get("autonomous_system") or {}).get("asn")})
            return json.dumps({"domain": domain, "hits_count": len(hits),
                               "hits": slim}, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})",
                           "domain": domain}, ensure_ascii=False)


# ------------------------- WHOIS History (WhoisXML → Whoxy) ----------------
def _whois_provider_failure(provider: str, data: object = None,
                            transport_error: str | None = None) -> dict | None:
    """Типизированный отказ WHOIS без сообщения, способного содержать ключ."""
    body = data if isinstance(data, dict) else {}
    detail = body.get("ErrorMessage") or body.get("error")
    if isinstance(detail, dict):
        code = detail.get("errorCode") or detail.get("code")
        message = detail.get("message") or detail.get("messages") or detail
    else:
        code = body.get("code")
        message = detail or body.get("messages") or body.get("message")
    failed_code = code not in (None, 0, "0", 200, "200")
    if not transport_error and not detail and not failed_code:
        return None
    http_code = re.search(r"HTTP (\d{3})", transport_error or "")
    status = int(http_code.group(1)) if http_code else None
    if status is None and str(code).isdigit():
        numeric = int(code)
        status = numeric if 400 <= numeric <= 599 else None
    low = f"{code} {message}".lower()
    # HTTP 403 сам по себе не различает баланс, ключ и IP allowlist.
    if status == 403:
        kind, note = "access_denied", "HTTP 403: доступ ограничен; проверьте баланс продукта, ключ и IP allowlist"
    elif status == 402:
        kind, note = "quota_exhausted", "HTTP 402: требуется оплата или пополнение кредитов продукта"
    elif status == 401:
        kind, note = "authentication_failed", "HTTP 401: ключ не принят провайдером"
    elif status == 429:
        kind, note = "rate_limited", "HTTP 429: лимит запросов исчерпан"
    elif any(x in low for x in ("insufficient credit", "not enough credit", "no balance", "quota", "credit limit", "balance limit")):
        kind, note = "quota_exhausted", "кредиты или квота продукта исчерпаны"
    elif any(x in low for x in ("authentication", "invalid api key", "incorrect api key", "invalidapikey", "invalid_api_key", "unauthorized")):
        kind, note = "authentication_failed", "ключ не принят провайдером"
    elif transport_error:
        kind, note = "provider_unavailable", "провайдер недоступен"
    else:
        kind, note = "provider_error", "провайдер вернул ошибку"
    result = {"provider": provider, "error_type": kind, "error": f"{provider}: {note}"}
    safe_code = str(code) if code is not None else ""
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", safe_code) and safe_code not in (WHOISXML_KEY, WHOXY_KEY):
        result["provider_code"] = safe_code
    if status is not None:
        result["http_status"] = status
    return result


def normalize_history_records(records: list) -> list[dict]:
    """Сохраняем весь оплаченный набор истории и даты наблюдения провайдером."""
    out = []
    for record in records:
        if not isinstance(record, dict):
            continue
        contact = record.get("registrantContact")
        if not isinstance(contact, dict):
            contact = record.get("registrant")
        if not isinstance(contact, dict):
            contact = {}
        audit = record.get("audit") if isinstance(record.get("audit"), dict) else {}
        out.append({
            "domainName": record.get("domainName"),
            "domainType": record.get("domainType"),
            "createdDate": record.get("createdDateISO8601") or record.get("createdDateNormalized") or record.get("createdDateRaw") or record.get("createdDate"),
            "updatedDate": record.get("updatedDateISO8601") or record.get("updatedDateNormalized") or record.get("updatedDateRaw") or record.get("updatedDate"),
            "expiresDate": record.get("expiresDateISO8601") or record.get("expiresDateNormalized") or record.get("expiresDateRaw") or record.get("expiresDate"),
            "registrarName": record.get("registrarName"),
            "registrant": contact.get("organization") or contact.get("name") or (record.get("registrant") if isinstance(record.get("registrant"), str) else None),
            "registrantName": contact.get("name"),
            "registrantOrganization": contact.get("organization"),
            "audit": {"createdDate": audit.get("createdDate"), "updatedDate": audit.get("updatedDate")},
            "nameServers": record.get("nameServers") or [],
            "status": record.get("status") or [],
        })
    return out


async def _wx_whoisxml(domain: str) -> tuple[list | None, dict | None]:
    """WhoisXML WHOIS History. Возвращает (records|None, причина-недоступности)."""
    if not WHOISXML_KEY:
        return None, {"provider": "WhoisXML", "error_type": "missing_key", "error": "нет ключа WHOISXML_API_KEY"}
    data, err = await _get_json("https://whois-history.whoisxmlapi.com/api/v1",
                                params={"apiKey": WHOISXML_KEY, "domainName": domain,
                                        "mode": "purchase"}, timeout=25.0, retries=0)
    failure = _whois_provider_failure("WhoisXML", data, err)
    if failure:
        return None, failure
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        return None, {"provider": "WhoisXML", "error_type": "invalid_response", "error": "WhoisXML: ответ истории WHOIS не содержит список records"}
    out = normalize_history_records(data["records"])
    if len(out) != len(data["records"]) or (type(data.get("recordsCount")) is int and data["recordsCount"] != len(out)):
        return None, {"provider": "WhoisXML", "error_type": "invalid_response", "error": "WhoisXML: неполный или некорректный набор истории WHOIS"}
    return out, None


async def _wx_whoxy(domain: str) -> tuple[list | None, dict | None]:
    """Whoxy WHOIS History (резерв). Нормализует к тем же полям, что и WhoisXML."""
    if not WHOXY_KEY:
        return None, {"provider": "Whoxy", "error_type": "missing_key", "error": "нет ключа WHOXY_API_KEY"}
    data, err = await _get_json("https://api.whoxy.com/",
                                params={"key": WHOXY_KEY, "history": domain}, timeout=25.0, retries=0)
    if err:
        return None, _whois_provider_failure("Whoxy", data, err)
    if not isinstance(data, dict) or data.get("status") == 0:
        reason = data.get("status_reason", "ошибка") if isinstance(data, dict) else "ошибка"
        return None, _whois_provider_failure("Whoxy", {"error": reason})
    out = []
    for r in (data.get("whois_records") or []):
        if not isinstance(r, dict):
            continue
        reg = r.get("registrant_contact") or {}
        out.append({
            "createdDate": r.get("create_date"),
            "updatedDate": r.get("update_date"),
            "expiresDate": r.get("expiry_date"),
            "registrarName": (r.get("domain_registrar") or {}).get("registrar_name"),
            "registrant": reg.get("company_name") or reg.get("full_name"),
        })
    return out, None


@mcp.tool()
async def whois_history(domain: str, force_refresh: bool = False) -> str:
    """История регистрации домена (записанные регистранты/регистраторы/даты). Пробует
    WhoisXML, при недоступности/исчерпании кредитов — резервный Whoxy. Если оба
    недоступны, честно сообщает об этом (сбор не ломается). Общий кэш хранит полный
    набор до суток. force_refresh=True принудительно повторяет платный запрос."""
    try:
        domain = canonical_domain(domain)
    except ValueError:
        return json.dumps({"error": "укажите корректный домен", "error_type": "invalid_input"}, ensure_ascii=False)
    if not WHOISXML_KEY and not WHOXY_KEY:
        return json.dumps({"error": "нужен ключ истории WHOIS (WhoisXML или Whoxy)", "error_type": "missing_key", "domain": domain}, ensure_ascii=False)
    reasons = []
    for provider, fn in (("WhoisXML", _wx_whoisxml), ("Whoxy", _wx_whoxy)):
        # Не выдаём отсутствие резервного ключа за причину отказа основного API.
        if (provider == "WhoisXML" and not WHOISXML_KEY) or (provider == "Whoxy" and not WHOXY_KEY):
            continue
        async def fetch():
            recs, why = await fn(domain)
            if recs is None:
                return {"error": (why or {}).get("error", "история WHOIS недоступна"),
                        "provider_errors": [why] if why else [], "domain": domain}
            return {"domain": domain, "source": provider, "records_count": len(recs), "records": recs}

        result = await get_history(domain, provider,
                                   WHOISXML_KEY if provider == "WhoisXML" else WHOXY_KEY,
                                   fetch, force_refresh=force_refresh)
        if "records" in result and not result.get("error"):
            return json.dumps(result, ensure_ascii=False)
        reasons.extend(result.get("provider_errors") or [])
    return json.dumps({"error": "история WHOIS недоступна: " + "; ".join(r["error"] for r in reasons),
                       "provider_errors": reasons, "domain": domain},
                      ensure_ascii=False)


# ---------------------- OpenCorporates (реестр должностных лиц) --------------
_OC_BASE = "https://api.opencorporates.com/v0.4"


def _oc_params(extra: dict | None = None) -> dict:
    p = dict(extra or {})
    if OPENCORPORATES_KEY:
        p["api_token"] = OPENCORPORATES_KEY
    return p


async def _oc_best_match(query: str, jurisdiction: str = "") -> tuple[dict | None, str | None, list]:
    """Компания по названию. Совпадением считаем ТОЛЬКО равенство нормализованных
    имён — брать топ по релевантности нельзя: на «Thales» OpenCorporates отдаёт
    «THALES ESECURITY, INC.» (другое юрлицо), и в досье попали бы чужие директора.
    jurisdiction (напр. 'es') сужает выбор, когда одно имя зарегистрировано в
    нескольких странах («INDRA SISTEMAS, S.A.» есть и в ES, и в ca_qc).
    Возвращает (компания | None, ошибка | None, список кандидатов-подсказок)."""
    search_params = {"q": query, "per_page": 20, "order": "score"}
    if jurisdiction:
        search_params["jurisdiction_code"] = jurisdiction.lower()
    data, err = await _get_json(f"{_OC_BASE}/companies/search",
                                params=_oc_params(search_params), timeout=20.0)
    if err:
        return None, err, []
    comps = [c.get("company") or {} for c in
             (((data or {}).get("results") or {}).get("companies") or [])]
    if not comps:
        return None, "нет совпадений в OpenCorporates", []
    hints = [f"{c.get('name')} ({c.get('jurisdiction_code')})" for c in comps[:6]]
    qn = _norm_company(query)
    named = [c for c in comps if _norm_company(c.get("name") or "") == qn]
    if not named:
        return None, "нет точного совпадения по названию", hints
    if jurisdiction:
        # .startswith() для региональных кодов: es_m (Мадрид), es_b (Барселона) → es
        exact = [c for c in named
                 if (c.get("jurisdiction_code") or "").lower().startswith(jurisdiction.lower())]
        if exact:
            return exact[0], None, hints
        return None, f"название найдено, но не в юрисдикции {jurisdiction}", hints
    # Юрисдикция не задана: предпочитаем действующую регистрацию.
    active = [c for c in named if not c.get("inactive")]
    return (active or named)[0], None, hints


@mcp.tool()
async def opencorporates_search(query: str) -> str:
    """OpenCorporates: поиск юрлиц по названию во множестве национальных реестров.
    Возвращает совпадения (название, номер, юрисдикция, статус). Полный доступ — с
    ключом OPENCORPORATES_API_KEY. Передай название компании."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    data, err = await _get_json(f"{_OC_BASE}/companies/search",
                                params=_oc_params({"q": query, "per_page": 8,
                                                   "order": "score"}), timeout=20.0)
    if err:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OPENCORPORATES_KEY else ""
        return json.dumps({"error": err + hint, "query": query}, ensure_ascii=False)
    comps = (((data or {}).get("results") or {}).get("companies") or [])
    matches = [{
        "name": (c.get("company") or {}).get("name"),
        "company_number": (c.get("company") or {}).get("company_number"),
        "jurisdiction": (c.get("company") or {}).get("jurisdiction_code"),
        "status": (c.get("company") or {}).get("current_status"),
        "inactive": (c.get("company") or {}).get("inactive"),
        "url": (c.get("company") or {}).get("opencorporates_url"),
    } for c in comps[:8]]
    return json.dumps({"query": query, "matches": matches}, ensure_ascii=False)


@mcp.tool()
async def opencorporates_officers(query: str, jurisdiction: str = "") -> str:
    """OpenCorporates: должностные лица (директора/руководство) компании по названию —
    имена, должности, даты. Требует ключ OPENCORPORATES_API_KEY для карточки с
    officers (без ключа обычно 401 → «нужен ключ»). Передай ЮРИДИЧЕСКОЕ название;
    jurisdiction (код страны, напр. 'es', 'de') задай, если одно имя зарегистрировано
    в нескольких странах — иначе можно получить директоров чужого филиала."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    best, err, hints = await _oc_best_match(query, (jurisdiction or "").strip())
    if err or not best:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OPENCORPORATES_KEY else ""
        return json.dumps({"error": (err or "не найдено") + hint, "query": query,
                           "did_you_mean": hints}, ensure_ascii=False)
    jur, num = best.get("jurisdiction_code"), best.get("company_number")
    if not (jur and num):
        return json.dumps({"error": "нет идентификатора компании", "query": query,
                           "match": best.get("name")}, ensure_ascii=False)
    data, err = await _get_json(f"{_OC_BASE}/companies/{jur}/{num}",
                                params=_oc_params(), timeout=20.0)
    if err:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OPENCORPORATES_KEY else ""
        return json.dumps({"error": err + hint, "company": best.get("name")},
                          ensure_ascii=False)
    company = ((data or {}).get("results") or {}).get("company") or {}
    officers = []
    for o in (company.get("officers") or [])[:40]:
        off = o.get("officer") or {}
        officers.append({"name": off.get("name"), "position": off.get("position"),
                         "start_date": off.get("start_date"),
                         "end_date": off.get("end_date")})
    out = {
        "company": company.get("name") or best.get("name"),
        "jurisdiction": jur, "company_number": num,
        "status": company.get("current_status"),
        "incorporation_date": company.get("incorporation_date"),
        "company_type": company.get("company_type"),
        "registry_url": company.get("registry_url"),
        "opencorporates_url": company.get("opencorporates_url"),
        "officers_count": len(officers),
        "officers": officers,
    }
    return json.dumps(out, ensure_ascii=False)


# ======================= BORME / Registro Mercantil España (keyless) =========
_BORME_BASE = "https://libreborme.net/borme/api/v1"


@mcp.tool()
async def borme_company(query: str) -> str:
    """LibreBORME / Registro Mercantil España (keyless): данные из официального
    BORME (Boletín Oficial del Registro Mercantil) — CIF/NIF, текущие и бывшие
    директора (Consejo de Administración), апoderados, даты первой/последней записи.
    Покрывает испанские S.A. и S.L. Передай официальное испанское юридическое
    название (например «INDRA SISTEMAS SA» или «TELEFONICA SA»)."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)

    # LibreBORME чувствителен к формату: "INDRA SISTEMAS, S.A." не найдёт ничего,
    # а "INDRA SISTEMAS SA" или "INDRA SISTEMAS" — найдёт. Пробуем варианты по порядку.
    def _borme_variants(name: str) -> list[str]:
        variants = [name]
        # Убираем ", S.A." / " S.A." / ", S.L." и другие испанские формы
        stripped = re.sub(
            r",?\s+S\.?(?:A\.?U?\.?|L\.?|L\.?U\.?|L\.?L\.?|P\.?|Com\.?|Coop\.?)$",
            "", name, flags=re.I).strip(" ,.")
        if stripped and stripped != name:
            variants.append(stripped)
        # Первые три значимых слова (ещё короче) — фолбэк для длинных юрлиц
        words = stripped.split()
        if len(words) > 2:
            short = " ".join(words[:3])
            if short not in variants:
                variants.append(short)
        return variants

    # 1) Поиск по имени → список объектов (slug, name, nif, date_updated, in_bormes)
    data, err, objects = None, None, []
    for variant in _borme_variants(query):
        data, err = await _get_json(f"{_BORME_BASE}/empresa/",
                                    params={"name": variant},
                                    timeout=25.0, retries=2)
        if err:
            break
        objects = (data or {}).get("objects") or []
        if objects:
            break
    if err:
        # 403 = Cloudflare-защита; «нужен ключ» вводит в заблуждение — уточняем.
        if any(code in err for code in ("403", "401", "forbidden", "unauthorized")):
            err = "libreborme.net недоступен (Cloudflare)"
        return json.dumps({"error": err, "source": "libreborme.net", "query": query},
                          ensure_ascii=False)
    if not objects:
        return json.dumps({"error": "компания не найдена в BORME/LibreBORME",
                           "query": query, "source": "libreborme.net"},
                          ensure_ascii=False)

    # Берём первый результат (наиболее релевантный)
    best = objects[0]
    # slug извлекается из resource_uri вида "/borme/api/v1/empresa/{slug}/"
    slug = (best.get("resource_uri") or "").rstrip("/").rsplit("/", 1)[-1]

    out: dict = {
        "source": "libreborme.net (BORME / Registro Mercantil España)",
        "name": best.get("name"),
        "nif": best.get("nif"),          # CIF (испанский ИНН юрлица)
        "date_updated": best.get("date_updated"),
        "num_announcements": best.get("in_bormes"),
        "url": f"https://libreborme.net/borme/empresa/{slug}/" if slug else None,
    }

    # 2) Карточка с должностными лицами → GET /empresa/{slug}/
    if slug:
        detail, derr = await _get_json(f"{_BORME_BASE}/empresa/{slug}/",
                                       timeout=25.0, retries=1)
        if derr is None and isinstance(detail, dict):
            out["address"] = detail.get("domicilio_social")
            out["capital"] = detail.get("capital_social")
            out["date_constitution"] = detail.get("fecha_constitucion")

            # Агрегируем персон из актов BORME (cargos внутри каждого акта)
            persons: dict[str, dict] = {}
            for act in (detail.get("actos") or []):
                fecha = act.get("fecha_borme")
                for cargo in (act.get("cargos") or []):
                    nm = (cargo.get("nombre") or "").strip()
                    role = cargo.get("tipo_acto") or cargo.get("cargo") or ""
                    if not nm:
                        continue
                    if nm not in persons:
                        persons[nm] = {"name": nm, "roles": [], "first_seen": fecha,
                                       "last_seen": fecha}
                    if role and role not in persons[nm]["roles"]:
                        persons[nm]["roles"].append(role)
                    if fecha and fecha > (persons[nm]["last_seen"] or ""):
                        persons[nm]["last_seen"] = fecha

            out["officers"] = list(persons.values())[:40]

    return json.dumps(out, ensure_ascii=False)


# =================== web-check-style инспекция сайта (keyless) ==============
_SEC_HEADERS = ["strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options", "referrer-policy",
                "permissions-policy", "cross-origin-opener-policy"]


async def _fetch(url: str, timeout: float = 20.0):
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"User-Agent": _UA}, verify=True) as c:
        return await c.get(url)


@mcp.tool()
async def web_inspect(domain: str) -> str:
    """Инспекция веб-присутствия домена (в духе web-check): цепочка редиректов,
    HTTP-статус, сервер/технологии, заголовки безопасности (HSTS/CSP/XFO/…),
    cookies, robots.txt, security.txt, DNSSEC. Каждый блок можно выводить как
    отдельную справку. Keyless. Передай домен."""
    domain = (domain or "").strip().lower().lstrip("*.").split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    out: dict = {"domain": domain}
    try:
        r = await _fetch(f"https://{domain}/")
    except Exception:
        try:
            r = await _fetch(f"http://{domain}/")
        except Exception as e:
            return json.dumps({"error": f"сайт недоступен ({type(e).__name__})",
                               "domain": domain}, ensure_ascii=False)
    h = {k.lower(): v for k, v in r.headers.items()}
    out["final_url"] = str(r.url)
    out["http_status"] = r.status_code
    out["redirect_chain"] = [str(x.url) for x in r.history] + [str(r.url)] \
        if r.history else [str(r.url)]
    out["server"] = h.get("server")
    out["powered_by"] = h.get("x-powered-by")
    # заголовки безопасности: есть/нет + значение
    out["security_headers"] = {k: h.get(k) for k in _SEC_HEADERS}
    out["security_headers_missing"] = [k for k in _SEC_HEADERS if k not in h]
    out["hsts"] = "strict-transport-security" in h
    # cookies (имена + флаги)
    cookies = []
    for sc in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
        nm = sc.split("=", 1)[0]
        cookies.append({"name": nm[:40], "secure": "secure" in sc.lower(),
                        "httponly": "httponly" in sc.lower(),
                        "samesite": "samesite" in sc.lower()})
    out["cookies"] = cookies[:15]
    # <title> и generator
    body = r.text[:200000]
    mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    out["title"] = " ".join(mt.group(1).split())[:120] if mt else None
    mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if mg:
        out["generator"] = mg.group(1)[:80]
    # robots.txt / security.txt / DNSSEC — параллельно, best-effort
    async def _exists(path):
        try:
            rr = await _fetch(f"https://{domain}{path}", timeout=12.0)
            return rr.status_code == 200 and len(rr.text.strip()) > 0
        except Exception:
            return False
    robots, sectxt, sectxt2, dnskey = await asyncio.gather(
        _exists("/robots.txt"), _exists("/.well-known/security.txt"),
        _exists("/security.txt"),
        asyncio.to_thread(_resolve, domain, "DNSKEY"))
    out["robots_txt"] = robots
    out["security_txt"] = sectxt or sectxt2
    out["dnssec"] = bool(dnskey)
    return json.dumps(out, ensure_ascii=False)


# ======================= SEC EDGAR (юр. инфо США, keyless) =================
# SEC требует User-Agent с контактом, иначе 403. Формат «имя контакт».
_SEC_HDRS = {"User-Agent": "OSINT-MCP-UI research (contact: osint@example.com)",
             "Accept": "application/json", "Accept-Encoding": "gzip, deflate",
             "Host": "www.sec.gov"}


class SECLookupError(RuntimeError):
    """Ошибка доступа к SEC, отличная от отсутствия совпадения."""


async def _sec_cik(query: str) -> tuple[str | None, str | None]:
    """Точный тикер, нормализованное имя или явный CIK; неоднозначность не угадываем."""
    direct = re.fullmatch(r"(?:CIK\s*:?\s*)?(\d{1,10})", query.strip(), re.I)
    if direct:
        return direct.group(1).zfill(10), None
    data, err = await _get_json("https://www.sec.gov/files/company_tickers.json",
                                timeout=20.0, headers={k: v for k, v in _SEC_HDRS.items() if k != "Host"})
    if err or not isinstance(data, dict):
        raise SECLookupError("SEC ticker index unavailable: " + (err or "invalid response"))
    ql, norm = query.lower().strip(), _norm_company(query)
    rows = [r for r in data.values() if isinstance(r, dict)]
    for predicate in [lambda r: str(r.get("ticker", "")).lower() == ql,
                      lambda r: str(r.get("title", "")).lower() == ql,
                      lambda r: bool(norm) and _norm_company(r.get("title", "")) == norm,
                      lambda r: bool(norm) and (" " + norm + " ") in (" " + _norm_company(r.get("title", "")) + " ")]:
        hits = {str(r.get("cik_str")): r for r in rows if predicate(r)}
        if len(hits) == 1:
            row = next(iter(hits.values()))
            return str(row["cik_str"]).zfill(10), row.get("title")
        if len(hits) > 1:
            raise SECLookupError("SEC name is ambiguous; provide a ticker or CIK")
    return None, None


@mcp.tool()
async def sec_edgar(query: str) -> str:
    """SEC EDGAR (США, keyless): по тикеру или названию компании возвращает юр.
    сведения (SIC/отрасль, штат регистрации, адрес, статус) и последние отчёты
    (10-K/10-Q/8-K и др.). Заполняет «юридическую информацию» для компаний США.
    Передай тикер (AAPL) или название."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    try:
        cik, name = await _sec_cik(query)
    except SECLookupError as exc:
        return json.dumps({"error": str(exc), "query": query}, ensure_ascii=False)
    if not cik:
        return json.dumps({"error": "Имя не найдено в текущем индексе тикеров SEC; укажите тикер или CIK", "query": query},
                          ensure_ascii=False)
    data, err = await _get_json(f"https://data.sec.gov/submissions/CIK{cik}.json",
                                timeout=20.0, headers={k: v for k, v in _SEC_HDRS.items()
                                                       if k != "Host"})
    if err or not isinstance(data, dict):
        return json.dumps({"error": err or "нет данных", "cik": cik, "name": name},
                          ensure_ascii=False)
    addr = (data.get("addresses") or {}).get("business") or {}
    rec = data.get("filings", {}).get("recent", {})
    filings = []
    forms, dates, docs = (rec.get("form") or [], rec.get("filingDate") or [],
                          rec.get("primaryDocument") or [])
    for i in range(min(12, len(forms))):
        filings.append({"form": forms[i], "date": dates[i] if i < len(dates) else None,
                        "doc": docs[i] if i < len(docs) else None})
    out = {
        "name": data.get("name") or name or query, "cik": cik,
        "tickers": data.get("tickers"), "exchanges": data.get("exchanges"),
        "sic": data.get("sic"), "sic_description": data.get("sicDescription"),
        "entity_type": data.get("entityType"),
        "state_of_incorporation": data.get("stateOfIncorporation"),
        "fiscal_year_end": data.get("fiscalYearEnd"),
        "address": ", ".join(x for x in [addr.get("street1"), addr.get("city"),
                   addr.get("stateOrCountry"), addr.get("zipCode")] if x),
        "recent_filings": filings,
        "edgar_url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
    }
    return json.dumps(out, ensure_ascii=False)


# --------- Финансовые показатели США по XBRL (SEC, keyless) ----------------
# Порядок тегов важен: эмитенты используют разные концепты выручки. Берём первый,
# по которому SEC отдал данные.
_XBRL_METRICS: list[tuple[str, tuple[str, ...]]] = [
    ("Выручка", ("RevenueFromContractWithCustomerExcludingAssessedTax",
                 "Revenues", "SalesRevenueNet")),
    ("Чистая прибыль", ("NetIncomeLoss",)),
    ("Активы", ("Assets",)),
    ("Обязательства", ("Liabilities",)),
    ("Капитал", ("StockholdersEquity",)),
]


def _annual_xbrl_values(data: dict, instant: bool = False) -> dict[str, float]:
    """Период заканчивается в end; fy относится к поданному отчёту и может быть новее.

    Сравнительные периоды не переносятся в год подачи. Квартальные суммы из
    годового отчёта исключаются; поздняя корректировка того же периода приоритетна.
    """
    from datetime import date
    picked = {}
    for row in ((data.get("units") or {}).get("USD") or []):
        if row.get("form") not in ("10-K", "10-K/A") or row.get("fp") != "FY":
            continue
        end, val = row.get("end"), row.get("val")
        try:
            end_date = date.fromisoformat(end)
            if not instant:
                days = (end_date - date.fromisoformat(row["start"])).days
                if not 320 <= days <= 400:
                    continue
        except (ValueError, TypeError, KeyError):
            continue
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            continue
        rank = (row.get("filed", ""), row.get("accn", ""))
        if end not in picked or rank >= picked[end][0]:
            picked[end] = (rank, float(val))
    return {end: value for end, (_, value) in picked.items()}


async def _xbrl_series(cik: str, tag: str) -> dict[str, float]:
    data, err = await _get_json(
        f"https://data.sec.gov/api/xbrl/companyconcept/CIK{cik}/us-gaap/{tag}.json",
        timeout=20.0, headers={k: v for k, v in _SEC_HDRS.items() if k != "Host"})
    if err or not isinstance(data, dict):
        return {}
    return _annual_xbrl_values(data, instant=tag in {"Assets", "Liabilities", "StockholdersEquity"})


@mcp.tool()
async def sec_financials(query: str, years: int = 5) -> str:
    """Финансовые показатели компании США по данным XBRL SEC (keyless): выручка,
    чистая прибыль, активы, обязательства, капитал по годам из отчётности 10-K.
    Передай тикер (AAPL) или название компании. Закрывает «многолетние финансы»,
    которых нет в бесплатных реестрах."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    try:
        cik, name = await _sec_cik(query)
    except SECLookupError as exc:
        return json.dumps({"error": str(exc), "query": query}, ensure_ascii=False)
    if not cik:
        return json.dumps({"error": "Имя не найдено в текущем индексе тикеров SEC; укажите тикер или CIK",
                           "query": query}, ensure_ascii=False)
    metrics: dict[str, dict[str, float]] = {}
    limit = asyncio.Semaphore(3)
    async def load_metric(label, tags):
        async with limit:
            for tag in tags:
                series = await _xbrl_series(cik, tag)
                if series:
                    return label, series
        return label, {}
    for label, series in await asyncio.gather(*(load_metric(label, tags) for label, tags in _XBRL_METRICS)):
        if series:
            metrics[label] = series
    if not metrics:
        return json.dumps({"error": "в XBRL SEC нет годовых показателей",
                           "cik": cik, "name": name}, ensure_ascii=False)
    annual_ends = {y for label in ("Выручка", "Чистая прибыль") for y in metrics.get(label, {})}
    if not annual_ends:
        return json.dumps({"error": "SEC: годовые периоды не подтверждены", "cik": cik}, ensure_ascii=False)
    all_years = sorted(annual_ends, reverse=True)
    keep = all_years[:max(1, years)]
    return json.dumps({
        "name": name or query, "cik": cik, "currency": "USD", "source": "SEC XBRL (10-K)",
        "years": keep, "period_basis": "period_end",
        "source_url": f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik}.json",
        "metrics": {label: {str(y): s.get(y) for y in keep if y in s}
                    for label, s in metrics.items()},
    }, ensure_ascii=False)


# ======================= Stock Quote — yfinance (keyless, global) ===========
@mcp.tool()
async def stock_quote(ticker: str) -> str:
    """Котировки и рыночные данные: цена, капитализация, P/E, 52W диапазон,
    выручка, EBITDA. Yahoo Finance — покрывает ЛЮБУЮ биржу мира: NYSE/NASDAQ,
    IBEX35 (.MC: IDR.MC, SAN.MC), LSE (.L), XETRA (.DE), Euronext (.PA/.AS/.BR).
    Для испанских компаний IBEX35 суффикс .MC (IDR.MC = Indra, ANA.MC = Acciona).
    Передай тикер с суффиксом биржи или без (для NYSE/NASDAQ)."""
    import yfinance as yf
    ticker = (ticker or "").strip().upper()
    if not ticker:
        return json.dumps({"error": "no ticker"}, ensure_ascii=False)
    try:
        def _fetch_info() -> dict:
            return yf.Ticker(ticker).info
        info = await asyncio.to_thread(_fetch_info)
        price = info.get("regularMarketPrice") or info.get("currentPrice")
        if price is None:
            # Попробуем добавить .MC (испанская биржа BME) если суффикса нет
            if "." not in ticker:
                def _fetch_mc() -> dict:
                    return yf.Ticker(ticker + ".MC").info
                info2 = await asyncio.to_thread(_fetch_mc)
                if info2.get("regularMarketPrice") or info2.get("currentPrice"):
                    info = info2
                    ticker = ticker + ".MC"
                    price = info.get("regularMarketPrice") or info.get("currentPrice")
        if price is None:
            return json.dumps({
                "error": f"данных по тикеру {ticker} нет — проверь суффикс биржи "
                         f"(.MC для Испании, .L для LSE, .DE для XETRA, .PA для Euronext)",
                "ticker": ticker}, ensure_ascii=False)
        out = {
            "ticker": ticker, "source": "Yahoo Finance (yfinance)",
            "name": info.get("longName") or info.get("shortName"),
            "exchange": info.get("exchange"),
            "currency": info.get("currency"),
            "price": price,
            "previous_close": info.get("regularMarketPreviousClose") or info.get("previousClose"),
            "market_cap": info.get("marketCap"),
            "pe_ratio": info.get("trailingPE"),
            "forward_pe": info.get("forwardPE"),
            "eps": info.get("trailingEps"),
            "52w_high": info.get("fiftyTwoWeekHigh"),
            "52w_low": info.get("fiftyTwoWeekLow"),
            "revenue": info.get("totalRevenue"),
            "net_income": info.get("netIncomeToCommon"),
            "ebitda": info.get("ebitda"),
            "employees": info.get("fullTimeEmployees"),
            "sector": info.get("sector"),
            "industry": info.get("industryDisp") or info.get("industry"),
            "country": info.get("country"),
            "website": info.get("website"),
        }
        return json.dumps(out, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e), "ticker": ticker}, ensure_ascii=False)


@mcp.tool()
async def stock_ticker_lookup(query: str) -> str:
    """Поиск тикера по названию компании (Yahoo Finance, keyless). Возвращает
    варианты тикеров по всем мировым биржам — выбери нужный суффикс для stock_quote.
    Передай название компании (на английском)."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    data, err = await _get_json(
        "https://query1.finance.yahoo.com/v1/finance/search",
        params={"q": query, "quotesCount": 8, "newsCount": 0,
                "enableFuzzyQuery": False, "enableCb": False},
        timeout=15.0, retries=2,
        headers={"User-Agent": _UA, "Accept": "application/json"})
    if err:
        return json.dumps({"error": err, "query": query}, ensure_ascii=False)
    quotes = (data or {}).get("quotes") or []
    results = [{"ticker": q.get("symbol"), "name": q.get("longname") or q.get("shortname"),
                "exchange": q.get("exchange"), "type": q.get("quoteType")}
               for q in quotes[:8] if q.get("symbol")]
    return json.dumps({"query": query, "results": results}, ensure_ascii=False)


# ========================= Wikipedia (контекст, keyless) ===================
@mcp.tool()
async def wikipedia_summary(query: str, lang: str = "ru") -> str:
    """Wikipedia (keyless): краткое описание сущности (компании/персоны) + внешние
    ссылки из статьи (ссылочный профиль — на официальные сайты, реестры, СМИ).
    Пробует ru, затем en. Передай название."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    for lg in ([lang, "en"] if lang != "en" else ["en", "ru"]):
        # 1) резолвим свободный запрос в точный заголовок статьи (opensearch)
        srch, _ = await _get_json(f"https://{lg}.wikipedia.org/w/api.php",
                                  params={"action": "opensearch", "search": query,
                                          "limit": 1, "format": "json"},
                                  timeout=20.0, retries=2)
        page_title = None
        if isinstance(srch, list) and len(srch) >= 2 and srch[1]:
            page_title = srch[1][0]
        if not page_title:
            continue
        summ, err = await _get_json(
            f"https://{lg}.wikipedia.org/api/rest_v1/page/summary/{page_title.replace(' ', '_')}",
            timeout=20.0, retries=2)
        if err or not isinstance(summ, dict) or summ.get("type", "").endswith("not_found"):
            continue
        title = summ.get("title")
        # внешние ссылки статьи (ссылочный профиль)
        ext, _ = await _get_json(f"https://{lg}.wikipedia.org/w/api.php",
                                 params={"action": "parse", "page": title,
                                         "prop": "externallinks", "format": "json"},
                                 timeout=20.0, retries=1)
        links = ((ext or {}).get("parse") or {}).get("externallinks") or []
        # группируем по домену, вычищаем служебные
        skip = ("web.archive.org", "archive.org", "wikimedia", "wikidata.org",
                "doi.org", "worldcat.org", "wikipedia.org")
        doms: dict[str, int] = {}
        for u in links:
            m = re.search(r"https?://([^/]+)/?", u)
            if m:
                d = m.group(1).lower()
                d = d[4:] if d.startswith("www.") else d
                if not any(s in d for s in skip):
                    doms[d] = doms.get(d, 0) + 1
        top = sorted(doms.items(), key=lambda x: -x[1])[:20]
        return json.dumps({
            "query": query, "lang": lg, "title": title,
            "description": summ.get("description"),
            "extract": (summ.get("extract") or "")[:1200],
            "url": (summ.get("content_urls") or {}).get("desktop", {}).get("page"),
            "external_link_count": len(links),
            "external_domains": [{"domain": d, "count": n} for d, n in top],
        }, ensure_ascii=False)
    return json.dumps({"error": "в Wikipedia (ru/en) статья не найдена", "query": query},
                      ensure_ascii=False)


# ==================== Google Programmable Search (CSE) =====================
# Тематические CSE (cx) — готовые движки под OSINT-задачи. Каждый ищет по своему
# набору сайтов. cx можно добавлять свободно (в т.ч. из config/cse_engines.json).
CSE_ENGINES: dict[str, dict] = {
    "pastebin":        {"cx": "000905274576528531678:zdstbilawf0", "desc": "паст-сайты (утечки текста)"},
    "raw_git":         {"cx": "007791543817084091905:vmwkk8ksx9k", "desc": "raw git / код (секреты)"},
    "docs":            {"cx": "001580308195336108602:hx9tv6r_od4", "desc": "поиск по документам"},
    "docs_formats":    {"cx": "009462381166450434430:nudphlkt3p4", "desc": "документы по форматам"},
    "people":          {"cx": "009305272063906253811:0xqjdapfzsk", "desc": "поиск людей (латиница)"},
    "sites_social_gov":{"cx": "011373762844405469335:vl3rlrf7ziy", "desc": "сайты, соцмедиа, gov"},
    "social_community":{"cx": "016621447308871563343:0p9cd3f8p-k", "desc": "соцсети, комьюнити"},
    "social":          {"cx": "012209864558240645678:orirysy9yqk", "desc": "соцсети"},
    "us_federal":      {"cx": "006636090781133203169:o9hlckv9egm", "desc": "US federal gov"},
    "docs_orgs":       {"cx": "006748068166572874491:55ez0c3j3ey", "desc": "документы и организации"},
    "wiki":            {"cx": "006775555251158006122:nxp0gaipa40", "desc": "wiki"},
    "gpo":             {"cx": "002733260306582994232:6gsdjfrruge", "desc": "gpo.gov (US gov publishing)"},
    "edu":             {"cx": "009267560011000861900:vaap19gqdq8", "desc": "EDU"},
    "jobs":            {"cx": "009305272063906253811:wool_g5jew4", "desc": "вакансии/резюме"},
    "hybrid_analysis": {"cx": "003089153695915392663:yi7j3xmja0w", "desc": "hybrid-analysis (malware)"},
}
# Дорк-движки: применяют шаблон к запросу и ищут по GOOGLE_CSE_DEFAULT_CX
# («весь веб»). Расширяют охват OSINT без отдельных cx. {q} — подстановка запроса.
CSE_DORKS: dict[str, dict] = {
    "linkedin":  {"tpl": "{q} (site:linkedin.com/in OR site:linkedin.com/company)", "desc": "LinkedIn (люди/компании)"},
    "telegram":  {"tpl": "{q} site:t.me", "desc": "Telegram-каналы/чаты"},
    "twitter_x": {"tpl": "{q} (site:x.com OR site:twitter.com OR site:nitter.net)", "desc": "X/Twitter"},
    "github":    {"tpl": "{q} (site:github.com OR site:gitlab.com OR site:bitbucket.org)", "desc": "репозитории кода"},
    "pastes":    {"tpl": "{q} (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:justpaste.it OR site:controlc.com)", "desc": "паст-сайты (расшир.)"},
    "leaks":     {"tpl": "{q} (\"data breach\" OR leaked OR dump OR site:dehashed.com OR site:breachdirectory.org)", "desc": "утечки/пробивы"},
    "files":     {"tpl": "{q} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv OR filetype:pptx)", "desc": "офисные документы"},
    "code_secrets": {"tpl": "{q} (filetype:env OR filetype:log OR filetype:cfg OR \"api_key\" OR \"BEGIN RSA PRIVATE KEY\")", "desc": "конфиги/секреты"},
    "reddit":    {"tpl": "{q} site:reddit.com", "desc": "Reddit"},
    "forums":    {"tpl": "{q} (inurl:forum OR inurl:viewtopic OR site:4pda.to OR site:forum.xda-developers.com)", "desc": "форумы"},
    "vk_ru":     {"tpl": "{q} (site:vk.com OR site:ok.ru)", "desc": "ВКонтакте/Одноклассники"},
    "news":      {"tpl": "{q} (site:reuters.com OR site:bloomberg.com OR site:rbc.ru OR site:kommersant.ru)", "desc": "деловые СМИ"},
}


# Тематические движки → шаблон запроса (site:/filetype: операторы). Работают через
# Serper (Google-результаты). Имена сохранены = совместимость с прежней разводкой.
WEB_ENGINES: dict[str, str] = {
    "pastebin": "{q} (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:justpaste.it OR site:controlc.com)",
    "raw_git": "{q} (site:github.com OR site:gitlab.com OR site:raw.githubusercontent.com OR site:gist.github.com)",
    "docs": "{q} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx)",
    "docs_formats": "{q} (filetype:pdf OR filetype:pptx OR filetype:csv OR filetype:rtf)",
    "docs_orgs": "{q} (filetype:pdf OR filetype:docx) (annual report OR filing OR отчет OR устав)",
    "people": "{q}",
    "sites_social_gov": "{q} (site:.gov OR site:linkedin.com OR site:facebook.com)",
    "social_community": "{q} (site:reddit.com OR site:quora.com OR site:medium.com)",
    "social": "{q} (site:facebook.com OR site:x.com OR site:instagram.com OR site:linkedin.com OR site:vk.com)",
    "us_federal": "{q} site:.gov",
    "wiki": "{q} site:wikipedia.org",
    "gpo": "{q} site:gpo.gov",
    "edu": "{q} site:.edu",
    "jobs": "{q} (site:linkedin.com/jobs OR site:hh.ru OR site:indeed.com OR site:glassdoor.com)",
    "hybrid_analysis": "{q} site:hybrid-analysis.com",
    "linkedin": "{q} (site:linkedin.com/in OR site:linkedin.com/company)",
    "telegram": "{q} site:t.me",
    "twitter_x": "{q} (site:x.com OR site:twitter.com OR site:nitter.net)",
    "github": "{q} (site:github.com OR site:gitlab.com OR site:bitbucket.org)",
    "pastes": "{q} (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:justpaste.it)",
    "leaks": "{q} (\"data breach\" OR leaked OR dump OR site:dehashed.com OR site:breachdirectory.org)",
    "files": "{q} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv OR filetype:pptx)",
    "code_secrets": "{q} (filetype:env OR filetype:log OR \"api_key\" OR \"BEGIN RSA PRIVATE KEY\")",
    "reddit": "{q} site:reddit.com",
    "forums": "{q} (inurl:forum OR inurl:viewtopic)",
    "vk_ru": "{q} (site:vk.com OR site:ok.ru)",
    "news": "{q} (site:reuters.com OR site:bloomberg.com OR site:rbc.ru OR site:kommersant.ru)",
}
_ENGINE_DESC = {**{k: v["desc"] for k, v in CSE_ENGINES.items()},
                **{k: v["desc"] for k, v in CSE_DORKS.items()}}


@mcp.tool()
async def google_cse_engines() -> str:
    """Список тематических движков веб-поиска (pastebin, docs, people, social, wiki,
    edu, jobs, linkedin, telegram, github, leaks, files, news…) для google_cse(engine=…)."""
    return json.dumps({
        "engines": {k: _ENGINE_DESC.get(k, k) for k in WEB_ENGINES},
        "backend": "serper" if SERPER_KEY else ("google_cse" if GOOGLE_CSE_KEY else "none"),
        "note": "Бэкенд Serper (нужен SERPER_API_KEY). Google CSE JSON API — legacy-фолбэк "
                "(закрыт для новых GCP-проектов).",
    }, ensure_ascii=False)


@mcp.tool()
async def russia_connections(company: str, tax_id: str = "", people: list[dict] | None = None) -> str:
    """Публичные связи компании с РФ: контрагенты, ЕГРЮЛ/ЕГРИП, LinkedIn.
    ФИО — только из корпоративных источников. Гражданство по имени не определяется."""
    import connections
    return json.dumps(await connections.collect(company, tax_id, people or [], google_cse), ensure_ascii=False)


@mcp.tool()
async def uz_company_records(query: str, tax_id: str = "") -> str:
    """Публичные карточки Узбекистана по имени или 9-значному ИНН/STIR.
    Сохраняет даты и расхождения; не является официальной выпиской."""
    import uzbekistan
    return json.dumps(await uzbekistan.collect(query, google_cse, tax_id), ensure_ascii=False)


@mcp.tool()
async def fi_company_records(query: str, business_id: str = "") -> str:
    """Официальный открытый PRH/YTJ v3: компании Торгового реестра Финляндии.
    По точному имени или Y-tunnus. Объединения ry/rf требуют отдельного реестра;
    пустой ответ не подтверждает их отсутствие. Без ключа и платных выписок."""
    import finland
    return json.dumps(await finland.collect(query, business_id), ensure_ascii=False)


async def _serper_search(q: str, num: int = 10) -> tuple[dict | None, str | None]:
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.post("https://google.serper.dev/search",
                             headers={"X-API-KEY": SERPER_KEY, "Content-Type": "application/json"},
                             json={"q": q, "num": max(1, min(10, num))})
            if r.status_code == 401:
                return None, "неверный SERPER_API_KEY"
            if r.status_code == 429:
                return None, "лимит Serper исчерпан"
            r.raise_for_status()
            return r.json(), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


@mcp.tool()
async def google_cse(query: str, engine: str = "", cx: str = "", num: int = 10) -> str:
    """Тематический веб-поиск (Google-результаты). Движок engine из google_cse_engines
    (pastebin, docs, people, social, wiki, edu, jobs, linkedin, telegram, github, leaks,
    files, news…) задаёт site:/filetype:-фильтр. Бэкенд — Serper (SERPER_API_KEY);
    при его отсутствии — legacy Google CSE (закрыт для новых проектов). title/link/snippet."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "no query"}, ensure_ascii=False)
    eng_label = engine or "web"
    # Построить запрос из шаблона движка (для Serper). Неизвестный движок → как есть.
    q = WEB_ENGINES[engine].format(q=query) if engine in WEB_ENGINES else query

    # 1) Serper — основной бэкенд
    if SERPER_KEY:
        data, err = await _serper_search(q, num)
        if err:
            return json.dumps({"error": f"веб-поиск недоступен ({err})", "engine": eng_label,
                               "query": query}, ensure_ascii=False)
        items = (data or {}).get("organic") or []
        results = [{"title": it.get("title"), "link": it.get("link"),
                    "snippet": " ".join((it.get("snippet") or "").split())[:300],
                    "source": _host(it.get("link", ""))} for it in items[:num]]
        return json.dumps({"engine": eng_label, "query": q, "backend": "serper",
                           "count": len(results), "results": results}, ensure_ascii=False)

    # 2) legacy Google CSE JSON API (для проектов с доступом до заморозки)
    if GOOGLE_CSE_KEY:
        use_cx = cx or (CSE_ENGINES.get(engine, {}).get("cx")) or GOOGLE_CSE_DEFAULT_CX
        gq = CSE_DORKS[engine]["tpl"].format(q=query) if engine in CSE_DORKS else q
        if not use_cx:
            return json.dumps({"error": "нет cx для Google CSE (engine/GOOGLE_CSE_DEFAULT_CX)"},
                              ensure_ascii=False)
        data, err = await _get_json("https://www.googleapis.com/customsearch/v1",
                                    params={"key": GOOGLE_CSE_KEY, "cx": use_cx, "q": gq,
                                            "num": max(1, min(10, num))}, timeout=25.0)
        if err:
            return json.dumps({"error": f"Google CSE недоступен ({err})", "engine": eng_label,
                               "query": query}, ensure_ascii=False)
        items = (data or {}).get("items") or []
        results = [{"title": it.get("title"), "link": it.get("link"),
                    "snippet": " ".join((it.get("snippet") or "").split())[:300],
                    "source": it.get("displayLink")} for it in items[:num]]
        return json.dumps({"engine": eng_label, "query": gq, "backend": "google_cse",
                           "count": len(results), "results": results}, ensure_ascii=False)

    return json.dumps({"error": "нужен ключ веб-поиска: SERPER_API_KEY (serper.dev, "
                       "бесплатно 2500 запросов) — Google CSE закрыт для новых проектов"},
                      ensure_ascii=False)


def _host(url: str) -> str:
    m = re.search(r"https?://([^/]+)", url or "")
    return (m.group(1).lower().replace("www.", "") if m else "")


# ─────────────────────────── UK Companies House ─────────────────────────────
COMPANIES_HOUSE_KEY = os.getenv("COMPANIES_HOUSE_API_KEY", "").strip()


@mcp.tool()
async def uk_companies_house(query: str) -> str:
    """Реестр компаний Великобритании (Companies House API). Возвращает совпадения
    по названию: регистрационный номер, статус, тип, дату регистрации, адрес.
    Требует COMPANIES_HOUSE_API_KEY (бесплатно на developer.company-information.service.gov.uk).
    Передай название компании или registration number."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "укажите название компании"}, ensure_ascii=False)
    if not COMPANIES_HOUSE_KEY:
        return json.dumps(
            {"error": "нужен COMPANIES_HOUSE_API_KEY — бесплатный ключ на "
             "https://developer.company-information.service.gov.uk/"},
            ensure_ascii=False)
    import base64
    auth = base64.b64encode(f"{COMPANIES_HOUSE_KEY}:".encode()).decode()
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.get(
                "https://api.company-information.service.gov.uk/search/companies",
                params={"q": query, "items_per_page": 10},
                headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
            if r.status_code == 401:
                return json.dumps({"error": "Companies House 401 — проверьте COMPANIES_HOUSE_API_KEY"},
                                  ensure_ascii=False)
            r.raise_for_status()
            data = r.json() or {}
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Companies House недоступен ({type(e).__name__})",
                           "query": query}, ensure_ascii=False)
    items_raw = (data.get("items") or [])[:10]
    items = []
    for it in items_raw:
        addr = it.get("registered_office_address") or it.get("address") or {}
        addr_s = ", ".join(x for x in [
            addr.get("address_line_1"), addr.get("address_line_2"),
            addr.get("locality"), addr.get("postal_code"),
            addr.get("country")] if x)
        items.append({
            "title": it.get("title"),
            "company_number": it.get("company_number"),
            "company_status": it.get("company_status"),
            "company_type": it.get("company_type"),
            "date_of_creation": it.get("date_of_creation"),
            "address": addr_s,
        })
    return json.dumps({"query": query, "total_results": data.get("total_results", len(items)),
                       "items": items}, ensure_ascii=False)


# ─────────────────────────── OCCRP Aleph ────────────────────────────────────
ALEPH_KEY = os.getenv("ALEPH_API_KEY", "").strip()


@mcp.tool()
async def aleph_search(query: str) -> str:
    """OCCRP Aleph — поиск компаний и персон в базах утечек, структурированных
    реестрах и санкционных списках. Часть данных доступна без ключа; с ключом
    ALEPH_API_KEY — расширенный доступ (https://aleph.occrp.org/pages/api-access).
    Передай название компании, персоны или ключевое слово."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "укажите поисковый запрос"}, ensure_ascii=False)
    hdrs: dict = {"Accept": "application/json"}
    if ALEPH_KEY:
        hdrs["Authorization"] = f"ApiKey {ALEPH_KEY}"
    try:
        async with httpx.AsyncClient(timeout=20.0, headers=hdrs) as c:
            r = await c.get(
                "https://aleph.occrp.org/api/2/entities",
                params={"q": query, "filter:schemata": "Company", "limit": 10})
            if r.status_code in (401, 403):
                return json.dumps({"error": "Aleph 401/403 — проверьте ALEPH_API_KEY"},
                                  ensure_ascii=False)
            r.raise_for_status()
            data = r.json() or {}
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Aleph недоступен ({type(e).__name__})",
                           "query": query}, ensure_ascii=False)
    raw = (data.get("results") or [])[:12]
    results = []
    for e in raw:
        props = e.get("properties") or {}
        results.append({
            "caption": e.get("caption"),
            "schema": e.get("schema"),
            "collection": (e.get("collection") or {}).get("label"),
            "countries": e.get("countries") or props.get("country") or [],
            "names": (props.get("name") or [])[:3],
            "addresses": (props.get("address") or [])[:2],
        })
    return json.dumps({
        "query": query,
        "total": data.get("total") or {"value": len(results)},
        "results": results,
    }, ensure_ascii=False)


@mcp.tool()
async def resolve_hosts(hosts: list[str]) -> str:
    """Пакет публичных DNS A/AAAA. NXDOMAIN/пустой ответ отделяются от таймаута."""
    import dns.resolver, dns.message, dns.query, dns.rcode, dns.rdatatype
    def one(host):
        addresses, errors = [], []
        for kind in ("A", "AAAA"):
            try:
                addresses += [str(r) for r in dns.resolver.resolve(host, kind, lifetime=3)]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as e:
                # Docker DNS иногда теряет UDP-ответы под нагрузкой. Повторяем
                # только неудавшийся тип через публичный DNS-over-HTTPS.
                try:
                    answer = dns.query.https(dns.message.make_query(host, kind),
                                             "https://1.1.1.1/dns-query", timeout=4)
                    if answer.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                        raise ValueError("DNS rcode " + str(answer.rcode()))
                    for rrset in answer.answer:
                        if rrset.rdtype == dns.rdatatype.from_text(kind):
                            addresses += [r.to_text() for r in rrset]
                except Exception as fallback:
                    errors.append(type(e).__name__ + "/" + type(fallback).__name__)
        return host, addresses, errors
    clean = list(dict.fromkeys(h.lower().strip() for h in hosts
                               if re.fullmatch(r"[a-zA-Z0-9.-]+", h)))[:80]
    sem = asyncio.Semaphore(12)
    async def bounded(host):
        async with sem:
            return await asyncio.to_thread(one, host)
    rows = await asyncio.gather(*(bounded(h) for h in clean))
    addresses = {h: a for h, a, e in rows if a}
    return json.dumps({"map": {h: a[0] for h, a in addresses.items()},
                       "addresses": addresses,
                       "unresolved": [h for h, a, e in rows if not a and not e],
                       "failures": [{"host": h, "reasons": e} for h, a, e in rows if e],
                       "requested": len(clean)}, ensure_ascii=False)


@mcp.tool()
async def borme_publications(query: str) -> str:
    """Официальные акты BOE/BORME: точное юр. название, события назначения/отзыва
    полномочий, apoderados. Ограниченная выборка публичных бюллетеней с URL."""
    import borme
    return json.dumps(await borme.collect(query, google_cse), ensure_ascii=False)


@mcp.tool()
async def corporate_website(domain: str, query: str = "") -> str:
    """Официальный сайт: юр. сведения, бизнес, совет директоров, комитеты,
    руководство и публикации. URL и время чтения сохраняются для каждой страницы."""
    import corporate
    return json.dumps(await corporate.collect(domain, query, google_cse), ensure_ascii=False)


@mcp.tool()
async def public_document(url: str) -> str:
    """Прочитать публичный HTML/PDF: текст, конечный URL, дата и SHA-256.
    До 5 MB / 30 страниц PDF; закрытые ресурсы и CAPTCHA не обходятся."""
    import documents
    return json.dumps(await documents.collect(url), ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
