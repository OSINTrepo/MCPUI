"""PRH open YTJ v3: official Finnish Trade Register data, not association extracts.

The free association/YTJ search websites prohibit automated searches without
permission. Keep their links for manual verification; do not scrape them here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from urllib.parse import urlencode

import httpx

API = "https://avoindata.prh.fi/opendata-ytj-api/v3/companies"
SCHEMA = "https://avoindata.prh.fi/opendata-ytj-api/v3/schema?lang=en"
ASSOCIATIONS = "https://yhdistysrekisteri.prh.fi/?userLang=en"
YTJ = "https://tietopalvelu.ytj.fi/yrityshaku.aspx?kielikoodi=3"
SCOPE = ("Открытый API PRH/YTJ v3: Торговый реестр Финляндии и ожидающие регистрации компании. "
         "Реестр объединений (ry/rf) этим источником не подтверждается. Пустой ответ не доказывает "
         "отсутствие объединения. Руководители, учредители, подписанты и финансовая отчётность "
         "не предоставляются этим API.")


def valid_business_id(value: str) -> bool:
    """Finnish Y-tunnus: seven digits plus a mod-11 check digit."""
    if not re.fullmatch(r"\d{7}-\d", value or ""):
        return False
    remainder = sum(int(d) * w for d, w in zip(value[:7], (7, 9, 10, 5, 8, 4, 2))) % 11
    return remainder != 1 and int(value[-1]) == (0 if remainder == 0 else 11 - remainder)


def name_key(value: str) -> str:
    # Preserve legal forms: an association rf is not a namesake Oy company.
    return " ".join(re.findall(r"\w+", (value or "").casefold()))


def _description(values: list, field: str = "description") -> str | None:
    values = [v for v in (values or []) if isinstance(v, dict)]
    for language in ("3", "1", "2"):
        for value in values:
            if str(value.get("languageCode")) == language and value.get(field):
                return value[field]
    return next((v.get(field) for v in values if v.get(field)), None)


def parse_record(company: dict, retrieved_at: str) -> dict | None:
    """Normalize documented v3 fields without inventing officers or status labels."""
    bid = company.get("businessId") or {}
    if not isinstance(bid, dict) or not valid_business_id(bid.get("value")):
        return None
    names = [n for n in company.get("names", []) if isinstance(n, dict)
             and n.get("name") and not n.get("endDate") and n.get("version", 1) == 1]
    primary = [n for n in names if str(n.get("type")) == "1"]
    if not primary:
        return None  # Historical/auxiliary names alone do not identify a current legal entity.
    form = next((f for f in company.get("companyForms", []) if isinstance(f, dict)
                 and f.get("version", 1) == 1 and not f.get("endDate")), {})
    business_line = company.get("mainBusinessLine") or {}
    website = company.get("website") or {}
    address_rows = []
    for address in company.get("addresses", []):
        if not isinstance(address, dict):
            continue
        city = _description(address.get("postOffices"), "city")
        parts = [address.get(k) for k in ("co", "street", "buildingNumber", "entrance",
                                       "apartmentNumber", "postOfficeBox", "postCode")]
        parts += [city, address.get("country"), address.get("freeAddressLine")]
        address_rows.append({"address": " ".join(str(v) for v in parts if v),
                             "type": address.get("type"), "city": city,
                             "registration_date": address.get("registrationDate")})
    source_url = API + "?" + urlencode({"businessId": bid["value"]})
    return {"name": primary[0]["name"], "business_id": bid["value"],
            "registration_number": bid["value"], "jurisdiction": "FI",
            "current_names": [n["name"] for n in primary],
            "names": names, "entity_type": "company", "register": "Finnish Trade Register (PRH)",
            "legal_form": _description(form.get("descriptions")) or form.get("type"),
            "legal_form_code": form.get("type"), "registered_at": company.get("registrationDate"),
            "business_id_registered_at": bid.get("registrationDate"),
            "end_date": company.get("endDate"), "status_code": company.get("status"),
            "trade_register_status_code": company.get("tradeRegisterStatus"),
            "addresses": address_rows, "website": website.get("url") if isinstance(website, dict) else None,
            "activity": _description(business_line.get("descriptions")) if isinstance(business_line, dict) else None,
            "activity_code": business_line.get("type") if isinstance(business_line, dict) else None,
            "registered_entries": company.get("registeredEntries") or [],
            "last_modified": company.get("lastModified"), "source_url": source_url,
            "source_kind": "official_open_registry", "retrieved_at": retrieved_at}


def reconcile(payload: dict, query: str, business_id: str = "", retrieved_at: str = "") -> dict:
    """Accept only one exact ID/current legal-name match; namesakes stay candidates."""
    retrieved_at = retrieved_at or datetime.now(timezone.utc).isoformat()
    records = [r for c in payload.get("companies", []) if isinstance(c, dict)
               if (r := parse_record(c, retrieved_at))]
    exact = [r for r in records if (r["business_id"] == business_id if business_id else
             name_key(query) in {name_key(n) for n in r["current_names"]})]
    ids = {r["business_id"] for r in exact}
    total = payload.get("totalResults", len(records))
    truncated = isinstance(total, int) and total > len(payload.get("companies", []))
    matched = len(ids) == 1 and not (truncated and not business_id)
    out = {"query": query, "requested_business_id": business_id, "jurisdiction": "FI",
           "matched": matched, "official_registry_verified": matched,
           "source_kind": "official_open_registry", "source_url": API + "?" + urlencode(
               {"businessId": business_id} if business_id else {"name": query}),
           "retrieved_at": retrieved_at, "records": exact if matched else records[:20],
           "total_results": total, "truncated": truncated, "scope": SCOPE,
           "manual_verification": [{"name": "PRH: реестр объединений (ry/rf)", "url": ASSOCIATIONS},
                                   {"name": "YTJ: данные организаций", "url": YTJ}],
           "documentation_url": SCHEMA}
    if matched:
        out.update(exact[0])
    else:
        out["reason"] = ("Нет единственной записи Торгового реестра с точным совпадением "
                         "Y-tunnus/текущего юридического имени. Объединения ry/rf требуют "
                         "отдельной проверки в реестре объединений PRH; автоматический доступ "
                         "к нему требует разрешения/договора PRH.")
    return out


async def collect(query: str, business_id: str = "") -> dict:
    query = (query or "").strip()
    business_id = (business_id or "").strip()
    if business_id and not valid_business_id(business_id):
        return {"matched": False, "official_registry_verified": False, "jurisdiction": "FI",
                "error": "Y-tunnus должен иметь формат 1234567-8 и правильную контрольную цифру", "scope": SCOPE}
    if not business_id and not query:
        return {"matched": False, "error": "Укажите юридическое имя или Y-tunnus", "scope": SCOPE}
    params = {"businessId": business_id} if business_id else {"name": query}
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            async with client.stream("GET", API, params=params, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 2_000_000:
                        raise ValueError("ResponseTooLarge")
                    chunks.append(chunk)
        import json
        payload = json.loads(b"".join(chunks))
        if not isinstance(payload, dict) or not isinstance(payload.get("companies"), list):
            raise ValueError("UnexpectedSchema")
        return reconcile(payload, query, business_id)
    except Exception as exc:
        reason = "HTTP " + str(exc.response.status_code) if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__
        return {"matched": False, "official_registry_verified": False, "jurisdiction": "FI",
                "query": query, "requested_business_id": business_id, "error": reason,
                "source_url": API, "scope": SCOPE,
                "retrieved_at": datetime.now(timezone.utc).isoformat()}
