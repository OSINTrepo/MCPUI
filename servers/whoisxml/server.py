"""WhoisXML MCP — текущие и исторические регистрационные сведения домена."""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Локальный запуск из servers/ и образ с /app/common используют один модуль.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.whois_history_cache import canonical_domain, get_history

mcp = FastMCP("WhoisXML")

WHOISXML_KEY = os.getenv("WHOISXML_API_KEY", "").strip()
WHOXY_KEY = os.getenv("WHOXY_API_KEY", "").strip()
_UA = "osint-mcp/1.0"
_HDRS = {"User-Agent": _UA, "Accept": "application/json"}


async def _get_json(url: str, *, params: dict | None = None, timeout: float = 25.0
                   ) -> tuple[dict | list | None, str | None]:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     headers=_HDRS) as c:
            r = await c.get(url, params=params)
            if r.status_code >= 400:
                # Тело ошибки нужно для кода провайдера; URL с ключом не выводим.
                try:
                    data = r.json()
                except ValueError:
                    data = None
                return data, f"HTTP {r.status_code}"
            return r.json(), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def _provider_failure(provider: str, data: object = None,
                      transport_error: str | None = None) -> dict | None:
    """Типизированный отказ без текста/URL, способных содержать API-ключ."""
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
    # HTTP 403 неоднозначен: квота, ключ и IP allowlist проверяются отдельно.
    http_code = re.search(r"HTTP (\d{3})", transport_error or "")
    status = int(http_code.group(1)) if http_code else None
    if status is None and str(code).isdigit():
        numeric = int(code)
        status = numeric if 400 <= numeric <= 599 else None
    low = f"{code} {message}".lower()
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
    # Сохраняем только короткий код, а не произвольное сообщение с секретами.
    safe_code = str(code) if code is not None else ""
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", safe_code) and safe_code not in (WHOISXML_KEY, WHOXY_KEY):
        result["provider_code"] = safe_code
    if status is not None:
        result["http_status"] = status
    return result


def _history_record(record: dict) -> dict:
    """Не теряем даты снимка и отличающиеся сведения купленной истории."""
    contact = record.get("registrantContact")
    if not isinstance(contact, dict):
        contact = record.get("registrant")
    if not isinstance(contact, dict):
        contact = {}
    audit = record.get("audit") if isinstance(record.get("audit"), dict) else {}
    return {
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
    }


def normalize_history_records(records: list) -> list[dict]:
    """Чистая нормализация всех полученных снимков для повторной сборки."""
    return [_history_record(record) for record in records if isinstance(record, dict)]


async def _wx_whoisxml(domain: str) -> tuple[list | None, dict | None]:
    if not WHOISXML_KEY:
        return None, {"provider": "WhoisXML", "error_type": "missing_key", "error": "нет ключа WHOISXML_API_KEY"}
    data, err = await _get_json(
        "https://whois-history.whoisxmlapi.com/api/v1",
        params={"apiKey": WHOISXML_KEY, "domainName": domain, "mode": "purchase"})
    failure = _provider_failure("WhoisXML", data, err)
    if failure:
        return None, failure
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        return None, {"provider": "WhoisXML", "error_type": "invalid_response", "error": "WhoisXML: ответ истории WHOIS не содержит список records"}
    # mode=purchase уже оплачен за весь набор; срез терял старые регистранты.
    out = normalize_history_records(data["records"])
    if len(out) != len(data["records"]) or (type(data.get("recordsCount")) is int and data["recordsCount"] != len(out)):
        return None, {"provider": "WhoisXML", "error_type": "invalid_response", "error": "WhoisXML: неполный или некорректный набор истории WHOIS"}
    return out, None


async def _wx_whoxy(domain: str) -> tuple[list | None, dict | None]:
    if not WHOXY_KEY:
        return None, {"provider": "Whoxy", "error_type": "missing_key", "error": "нет ключа WHOXY_API_KEY"}
    data, err = await _get_json("https://api.whoxy.com/",
                                params={"key": WHOXY_KEY, "history": domain})
    if err:
        return None, _provider_failure("Whoxy", data, err)
    if not isinstance(data, dict) or data.get("status") == 0:
        reason = data.get("status_reason", "ошибка") if isinstance(data, dict) else "ошибка"
        return None, _provider_failure("Whoxy", {"error": reason})
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
    """История регистрации домена: записанные регистранты, регистраторы, даты создания/
    обновления/истечения. Пробует WhoisXML (WHOISXML_API_KEY), при недоступности —
    резервный Whoxy (WHOXY_API_KEY). Полный набор хранится в общем кэше до суток;
    force_refresh=True повторно запрашивает платную историю. Текущий WHOIS проверяется отдельно."""
    try:
        domain = canonical_domain(domain)
    except ValueError:
        return json.dumps({"error": "укажите корректный домен", "error_type": "invalid_input"}, ensure_ascii=False)
    if not WHOISXML_KEY and not WHOXY_KEY:
        return json.dumps({"error": "нужен ключ WHOISXML_API_KEY или WHOXY_API_KEY. "
                           "Вставьте в ⚙ у сервера WhoisXML.", "error_type": "missing_key"}, ensure_ascii=False)
    reasons = []
    for provider, fn in (("WhoisXML", _wx_whoisxml), ("Whoxy", _wx_whoxy)):
        # Не маскируем отказ настроенного провайдера отсутствующим резервным ключом.
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


@mcp.tool()
async def whois_current(domain: str) -> str:
    """Текущие WHOIS-данные домена (владелец, регистратор, NS, даты) через WhoisXML API.
    Требует WHOISXML_API_KEY. Передай домен."""
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "укажите домен"}, ensure_ascii=False)
    if not WHOISXML_KEY:
        return json.dumps({"error": "нужен WHOISXML_API_KEY. Вставьте в ⚙ у сервера.", "error_type": "missing_key"},
                          ensure_ascii=False)
    data, err = await _get_json(
        "https://www.whoisxmlapi.com/whoisserver/WhoisService",
        params={"apiKey": WHOISXML_KEY, "domainName": domain, "outputFormat": "JSON"})
    failure = _provider_failure("WhoisXML", data, err)
    if failure:
        return json.dumps({**failure, "domain": domain}, ensure_ascii=False)
    if not isinstance(data, dict) or not isinstance(data.get("WhoisRecord"), dict):
        return json.dumps({"error": "WhoisXML: ответ не содержит WhoisRecord", "error_type": "invalid_response", "domain": domain}, ensure_ascii=False)
    rec = data["WhoisRecord"]
    reg = rec.get("registryData") if isinstance(rec.get("registryData"), dict) else {}
    registrant = rec.get("registrant") if isinstance(rec.get("registrant"), dict) else {}
    registry_registrant = reg.get("registrant") if isinstance(reg.get("registrant"), dict) else {}
    nameservers = rec.get("nameServers") if isinstance(rec.get("nameServers"), dict) else {}
    registry_nameservers = reg.get("nameServers") if isinstance(reg.get("nameServers"), dict) else {}
    return json.dumps({
        "domain": domain,
        "registrarName": rec.get("registrarName") or reg.get("registrarName"),
        "registrant": registrant.get("organization") or registrant.get("name") or registry_registrant.get("organization") or registry_registrant.get("name"),
        "createdDate": reg.get("createdDateNormalized") or reg.get("createdDate") or rec.get("createdDateNormalized") or rec.get("createdDate"),
        "updatedDate": reg.get("updatedDateNormalized") or reg.get("updatedDate") or rec.get("updatedDateNormalized") or rec.get("updatedDate"),
        "expiresDate": reg.get("expiresDateNormalized") or reg.get("expiresDate") or rec.get("expiresDateNormalized") or rec.get("expiresDate"),
        "status": rec.get("status") or reg.get("status"),
        # Отсутствие записи — результат поиска, а не ошибка оплаты/авторизации.
        "dataError": rec.get("dataError") or reg.get("dataError"),
        "parseCode": rec.get("parseCode", reg.get("parseCode")),
        "domainAvailability": rec.get("domainAvailability") or reg.get("domainAvailability"),
        "nameServers": nameservers.get("hostNames") or registry_nameservers.get("hostNames") or [],
    }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
