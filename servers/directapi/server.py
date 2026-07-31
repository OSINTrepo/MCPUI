#!/usr/bin/env python3
"""directapi — self-wrapped прямые публичные API (без ключей).

Закрывает бесплатные источники, которых не было отдельными MCP-серверами:
  - rdap_domain / rdap_ip — RDAP (registrar, даты, NS, сеть/AS/организация)
  - crtsh                 — Certificate Transparency (поддомены из сертификатов)
  - dns_records           — A/AAAA/MX/NS/TXT + SPF/DMARC/DKIM/MTA-STS/BIMI
  - gleif_entity          — глобальный реестр LEI (юр. идентичность + связи)
  - opencorporates_*      — реестр юрлиц и должностных лиц (директора/руководство)

Все инструменты возвращают JSON-строку. Ошибки — тоже JSON ({"error": ...}),
чтобы оркестратор корректно классифицировал недоступность источника.

Запуск: stdio (supergateway оборачивает в Streamable HTTP). См. реестр.
"""
from __future__ import annotations

import asyncio
import json
import os
import re

import httpx
from mcp.server.fastmcp import FastMCP

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
# OpenCorporates: реестр юрлиц/должностных лиц. Без ключа v0.4 отдаёт ограниченный
# набор (и часто 401 на карточку) — тогда инструмент честно говорит «нужен ключ».
OPENCORPORATES_KEY = os.environ.get("OPENCORPORATES_API_KEY", "").strip()


async def _get_json(url: str, *, params: dict | None = None, timeout: float = 20.0,
                    retries: int = 1) -> tuple[dict | list | None, str | None]:
    """GET → (json, error). Повторяет при сетевых сбоях/5xx (crt.sh капризен)."""
    last = "unknown error"
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         headers=_HDRS) as c:
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
@mcp.tool()
async def crtsh(domain: str) -> str:
    """Поддомены из Certificate Transparency (crt.sh). Возвращает уникальные
    поддомены и эмитентов сертификатов. Best-effort: crt.sh часто отвечает
    медленно/пусто — пустой результат не ошибка. Передай домен."""
    domain = (domain or "").strip().lower().lstrip("*.").split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    # crt.sh капризен: даём щедрый таймаут и 2 повтора.
    data, err = await _get_json("https://crt.sh/", params={"q": f"%.{domain}",
                                "output": "json"}, timeout=40.0, retries=2)
    if err:
        return json.dumps({"error": err, "domain": domain,
                           "note": "crt.sh недоступен/пуст — покрытие дают VT+subfinder"},
                          ensure_ascii=False)
    names: set[str] = set()
    issuers: set[str] = set()
    for c in (data or []):
        for n in str(c.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and "@" not in n:
                names.add(n)
        iss = c.get("issuer_name", "")
        if iss:
            issuers.add(iss[:80])
    subs = sorted(n for n in names if n.endswith(domain))
    out = {"domain": domain, "cert_records": len(data or []),
           "subdomains_count": len(subs), "subdomains": subs[:300],
           "issuers": sorted(issuers)[:20]}
    return json.dumps(out, ensure_ascii=False)


# --------------------------------- DNS -------------------------------------
# Обычный DNS (UDP/TCP через резолвер контейнера), а НЕ DNS-over-HTTPS: на хостах
# с TLS-перехватом (напр. российский CA у GigaChat) DoH-эндпоинты (dns.google)
# отдают самоподписанный сертификат и валидация падает. Обычный DNS не шифруется —
# перехватывать нечего.
def _resolve(name: str, rrtype: str) -> list[str]:
    try:
        import dns.resolver
    except Exception:
        return []
    try:
        ans = dns.resolver.resolve(name, rrtype, lifetime=8.0)
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
    # DKIM: перебираем частые селекторы (нет способа перечислить их через DNS).
    dkim = {}
    for sel in ("default", "google", "selector1", "selector2", "s1", "s2", "k1",
                "mail", "dkim"):
        recs = await asyncio.to_thread(_resolve, f"{sel}._domainkey.{domain}", "TXT")
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
        if not cands:
            # Точного совпадения по legalName нет. НЕЧЁТКИЙ поиск используем ТОЛЬКО
            # как подсказку, а НЕ как ответ: GLEIF на «Thales Group» отдаёт «Thaler
            # Group AG», на «Siemens AG» — «Siemens Energy AG». Приписать чужому
            # юрлицу инфраструктуру цели хуже, чем честно сказать «не нашли».
            hints = await _gleif_fuzzy(query)
            return json.dumps({
                "query": query,
                "error": "в GLEIF нет точного совпадения по юридическому названию",
                "hint": "уточните ЮРИДИЧЕСКОЕ имя или передайте 20-значный LEI",
                "did_you_mean": hints,
            }, ensure_ascii=False)
        def _nm(rec):
            return (((rec.get("attributes") or {}).get("entity") or {})
                    .get("legalName") or {}).get("name") or ""
        # Совпадением считаем только РАВЕНСТВО нормализованных имён (без пунктуации
        # и юр. формы). Брать cands[0] «на всякий случай» нельзя: на «Siemens AG»
        # GLEIF отдаёт «Siemens Energy AG» — другое юрлицо, и досье ушло бы не туда.
        d = next((c for c in cands if _norm_company(_nm(c)) == _norm_company(query)), None)
        if d is None:
            return json.dumps({
                "query": query,
                "error": "в GLEIF нет точного совпадения по юридическому названию",
                "hint": "уточните ЮРИДИЧЕСКОЕ имя или передайте 20-значный LEI",
                "did_you_mean": [_nm(c) for c in cands][:5],
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
            return json.dumps(r.json(), ensure_ascii=False)[:6000]
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
            return json.dumps(r.json(), ensure_ascii=False)[:6000]
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})",
                           "domain": domain}, ensure_ascii=False)


# ------------------------- WhoisXML History (ключ) -------------------------
@mcp.tool()
async def whois_history(domain: str) -> str:
    """WhoisXML WHOIS History API: историческая регистрационная информация домена —
    прошлые владельцы/регистраторы/даты. Требует ключ WHOISXML_API_KEY. Передай домен."""
    if not WHOISXML_KEY:
        return json.dumps({"error": "нужен ключ WHOISXML_API_KEY"}, ensure_ascii=False)
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "no domain"}, ensure_ascii=False)
    data, err = await _get_json("https://whois-history.whoisxmlapi.com/api/v1",
                                params={"apiKey": WHOISXML_KEY, "domainName": domain,
                                        "mode": "purchase"}, timeout=25.0)
    if err:
        return json.dumps({"error": err, "domain": domain}, ensure_ascii=False)
    recs = (data or {}).get("records", []) if isinstance(data, dict) else []
    slim = []
    for rec in recs[:15]:
        r_ = rec.get("registrant") or {}
        slim.append({
            "createdDate": rec.get("createdDateNormalized") or rec.get("createdDateRaw"),
            "updatedDate": rec.get("updatedDateNormalized") or rec.get("updatedDateRaw"),
            "expiresDate": rec.get("expiresDateNormalized") or rec.get("expiresDateRaw"),
            "registrarName": rec.get("registrarName"),
            "registrant": r_.get("organization") or r_.get("name"),
        })
    out = {"domain": domain,
           "records_count": (data or {}).get("recordsCount", len(recs)),
           "records": slim}
    return json.dumps(out, ensure_ascii=False)


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
    data, err = await _get_json(f"{_OC_BASE}/companies/search",
                                params=_oc_params({"q": query, "per_page": 20,
                                                   "order": "score"}), timeout=20.0)
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
        exact = [c for c in named
                 if (c.get("jurisdiction_code") or "").lower() == jurisdiction.lower()]
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


if __name__ == "__main__":
    mcp.run()
