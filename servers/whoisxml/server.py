"""WhoisXML MCP — история регистрации домена (прошлые владельцы/даты/регистраторы)."""
from __future__ import annotations

import asyncio
import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

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
                return None, f"HTTP {r.status_code}"
            return r.json(), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


async def _wx_whoisxml(domain: str) -> tuple[list | None, str | None]:
    if not WHOISXML_KEY:
        return None, "нет ключа WHOISXML_API_KEY"
    data, err = await _get_json(
        "https://whois-history.whoisxmlapi.com/api/v1",
        params={"apiKey": WHOISXML_KEY, "domainName": domain, "mode": "purchase"})
    if err:
        return None, f"WhoisXML недоступен ({err})"
    if isinstance(data, dict) and data.get("code") and data.get("messages"):
        return None, f"WhoisXML: {str(data.get('messages'))[:80]}"
    recs = (data or {}).get("records", []) if isinstance(data, dict) else []
    out = [{
        "createdDate": r.get("createdDateISO8601") or r.get("createdDateRaw"),
        "updatedDate": r.get("updatedDateISO8601") or r.get("updatedDateRaw"),
        "expiresDate": r.get("expiresDateISO8601") or r.get("expiresDateRaw"),
        "registrarName": r.get("registrarName"),
        "registrant": (r.get("registrantContact") or {}).get("organization")
                      or (r.get("registrantContact") or {}).get("name")
                      or (r.get("registrant") or {}).get("organization"),
    } for r in recs[:20]]
    return out, None


async def _wx_whoxy(domain: str) -> tuple[list | None, str | None]:
    if not WHOXY_KEY:
        return None, "нет ключа WHOXY_API_KEY"
    data, err = await _get_json("https://api.whoxy.com/",
                                params={"key": WHOXY_KEY, "history": domain})
    if err:
        return None, f"Whoxy недоступен ({err})"
    if not isinstance(data, dict) or data.get("status") == 0:
        return None, f"Whoxy: {str((data or {}).get('status_reason', 'ошибка'))[:80]}"
    out = []
    for r in (data.get("whois_records") or [])[:15]:
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
async def whois_history(domain: str) -> str:
    """История регистрации домена: прошлые владельцы, регистраторы, даты создания/
    обновления/истечения. Пробует WhoisXML (WHOISXML_API_KEY), при недоступности —
    резервный Whoxy (WHOXY_API_KEY). Передай домен."""
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "укажите домен"}, ensure_ascii=False)
    if not WHOISXML_KEY and not WHOXY_KEY:
        return json.dumps({"error": "нужен ключ WHOISXML_API_KEY или WHOXY_API_KEY. "
                           "Вставьте в ⚙ у сервера WhoisXML."}, ensure_ascii=False)
    reasons = []
    for provider, fn in (("WhoisXML", _wx_whoisxml), ("Whoxy", _wx_whoxy)):
        recs, why = await fn(domain)
        if recs is not None:
            return json.dumps({"domain": domain, "source": provider,
                               "records_count": len(recs), "records": recs},
                              ensure_ascii=False)
        if why:
            reasons.append(why)
    return json.dumps({"error": "история WHOIS недоступна",
                       "detail": "; ".join(reasons), "domain": domain},
                      ensure_ascii=False)


@mcp.tool()
async def whois_current(domain: str) -> str:
    """Текущие WHOIS-данные домена (владелец, регистратор, NS, даты) через WhoisXML API.
    Требует WHOISXML_API_KEY. Передай домен."""
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "укажите домен"}, ensure_ascii=False)
    if not WHOISXML_KEY:
        return json.dumps({"error": "нужен WHOISXML_API_KEY. Вставьте в ⚙ у сервера."},
                          ensure_ascii=False)
    data, err = await _get_json(
        "https://www.whoisxmlapi.com/whoisserver/WhoisService",
        params={"apiKey": WHOISXML_KEY, "domainName": domain, "outputFormat": "JSON"})
    if err:
        return json.dumps({"error": f"WhoisXML недоступен ({err})", "domain": domain},
                          ensure_ascii=False)
    rec = (data or {}).get("WhoisRecord") or data or {}
    reg = rec.get("registryData") or rec
    return json.dumps({
        "domain": domain,
        "registrarName": rec.get("registrarName"),
        "registrant": (rec.get("registrant") or {}).get("organization")
                      or (rec.get("registrant") or {}).get("name"),
        "createdDate": reg.get("createdDateNormalized") or reg.get("createdDate"),
        "updatedDate": reg.get("updatedDateNormalized") or reg.get("updatedDate"),
        "expiresDate": reg.get("expiresDateNormalized") or reg.get("expiresDate"),
        "status": rec.get("status"),
        "nameServers": (rec.get("nameServers") or {}).get("hostNames") or [],
    }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
