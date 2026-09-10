"""Censys Platform MCP — host lookup и domain search через Censys v3 API."""
from __future__ import annotations

import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Censys")

CENSYS_PAT = os.getenv("CENSYS_PAT", "")
CENSYS_ORG = os.getenv("CENSYS_ORG_ID", "")
_UA = "osint-mcp/1.0"


def _headers(accept: str) -> dict:
    h = {"Authorization": f"Bearer {CENSYS_PAT}", "Accept": accept, "User-Agent": _UA}
    if CENSYS_ORG:
        h["X-Organization-ID"] = CENSYS_ORG
    return h


def _no_key(tool: str) -> str:
    return json.dumps({"error": f"нужен CENSYS_PAT для {tool}. "
                       "Вставьте Personal Access Token Censys: ⚙ у сервера → поле Censys PAT."},
                      ensure_ascii=False)


@mcp.tool()
async def censys_host(ip: str) -> str:
    """Censys: детальная карточка хоста по IP — открытые порты, сервисы, баннеры,
    сертификаты, ASN, геолокация. Работает с одним CENSYS_PAT (lookup доступен
    и на free/research-аккаунте)."""
    if not CENSYS_PAT:
        return _no_key("censys_host")
    ip = (ip or "").strip()
    if not ip:
        return json.dumps({"error": "укажите IP-адрес"}, ensure_ascii=False)
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.get(url, headers=_headers(
                "application/vnd.censys.api.v3.host.v1+json"))
            if r.status_code in (401, 403):
                return json.dumps({"error": "Censys 401/403 — проверьте CENSYS_PAT"},
                                  ensure_ascii=False)
            r.raise_for_status()
            res = ((r.json() or {}).get("result") or {}).get("resource") or r.json()
            asn = res.get("autonomous_system") or {}
            loc = res.get("location") or {}
            svcs = []
            for s in (res.get("services") or [])[:25]:
                soft = s.get("software") or []
                svcs.append({
                    "port": s.get("port"),
                    "protocol": s.get("protocol") or s.get("service_name"),
                    "software": [x.get("product") for x in soft if isinstance(x, dict)][:3],
                    "tls": bool(s.get("tls") or s.get("certificate")),
                })
            return json.dumps({
                "ip": res.get("ip") or ip,
                "asn": asn.get("asn"), "as_name": asn.get("name") or asn.get("description"),
                "country": loc.get("country"), "city": loc.get("city"),
                "os": (res.get("operating_system") or {}).get("product"),
                "service_count": len(res.get("services") or []),
                "services": svcs,
            }, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})", "ip": ip},
                          ensure_ascii=False)


@mcp.tool()
async def censys_domain(domain: str) -> str:
    """Censys: поиск хостов и сертификатов, привязанных к домену.
    Search-эндпоинт требует CENSYS_ORG_ID (free-аккаунт: только lookup).
    Нужны CENSYS_PAT + CENSYS_ORG_ID."""
    if not CENSYS_PAT:
        return _no_key("censys_domain")
    if not CENSYS_ORG:
        return json.dumps({"error": "нужен CENSYS_ORG_ID: search Censys недоступен "
                           "на free-аккаунте (только lookup). Задайте в ⚙ у сервера."},
                          ensure_ascii=False)
    domain = (domain or "").strip().lower().split("/")[0]
    if not domain:
        return json.dumps({"error": "укажите домен"}, ensure_ascii=False)
    url = "https://api.platform.censys.io/v3/global/search/query"
    # Ищем хосты, упоминающие домен в сертификатах или DNS (bare-text поиск v3)
    body = {"query": f'host.dns.names: "{domain}"', "page_size": 25}
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.post(url,
                             headers={**_headers("application/json"),
                                      "Content-Type": "application/json"},
                             json=body)
            if r.status_code in (401, 403):
                return json.dumps({"error": "Censys 401/403 — проверьте CENSYS_PAT/ORG_ID"},
                                  ensure_ascii=False)
            r.raise_for_status()
            data = r.json() or {}
            raw_hits = (data.get("result") or {}).get("hits") or data.get("hits") or []
            slim = []
            for h in raw_hits[:25]:
                # v3 Platform API оборачивает ресурс в {"host_v1": {"resource": {...}}}
                res = ((h.get("host_v1") or {}).get("resource")
                       or h.get("resource") or h)
                if not res.get("ip"):
                    continue  # сертификатный hit не является хостом
                asn_info = res.get("autonomous_system") or {}
                loc = res.get("location") or {}
                svcs = res.get("services") or []
                slim.append({
                    "ip": res.get("ip"),
                    "asn": asn_info.get("asn"),
                    "as_name": asn_info.get("name") or asn_info.get("description"),
                    "country": loc.get("country_code") or loc.get("country"),
                    "city": loc.get("city"),
                    "services": [s.get("port") for s in svcs[:8] if s.get("port")],
                })
            total = (data.get("result") or {}).get("total_hits") or len(slim)
            return json.dumps({"domain": domain, "hits": slim, "total": total},
                              ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})", "domain": domain},
                          ensure_ascii=False)


@mcp.tool()
async def censys_cert(fingerprint: str) -> str:
    """Censys: карточка TLS-сертификата по SHA-256 fingerprint — subject, SAN,
    issuer, validity. Работает с одним CENSYS_PAT."""
    if not CENSYS_PAT:
        return _no_key("censys_cert")
    fp = (fingerprint or "").strip().lower().replace(":", "")
    if not fp:
        return json.dumps({"error": "укажите SHA-256 fingerprint сертификата"},
                          ensure_ascii=False)
    url = f"https://api.platform.censys.io/v3/global/asset/cert/{fp}"
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.get(url, headers=_headers("application/json"))
            if r.status_code in (401, 403):
                return json.dumps({"error": "Censys 401/403 — проверьте CENSYS_PAT"},
                                  ensure_ascii=False)
            if r.status_code == 404:
                return json.dumps({"error": "сертификат не найден в Censys"}, ensure_ascii=False)
            r.raise_for_status()
            data = (r.json() or {}).get("result") or r.json()
            data = data.get("resource") or data
            parsed = data.get("parsed") or data
            subject = parsed.get("subject") or {}
            issuer = parsed.get("issuer") or {}
            val = parsed.get("validity") or {}
            return json.dumps({
                "fingerprint": fp,
                "subject_cn": subject.get("common_name"),
                "subject_org": subject.get("organization"),
                "san_dns": (parsed.get("extensions") or {}).get(
                    "subject_alt_name", {}).get("dns_names") or [],
                "issuer_cn": issuer.get("common_name"),
                "issuer_org": issuer.get("organization"),
                "not_before": val.get("start"),
                "not_after": val.get("end"),
                "expired": val.get("expired"),
            }, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"Censys недоступен ({type(e).__name__})"},
                          ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
