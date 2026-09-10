"""OpenCorporates MCP — поиск юрлиц и должностных лиц в национальных реестрах."""
from __future__ import annotations

import json
import os
import re

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("OpenCorporates")

OC_KEY = os.getenv("OPENCORPORATES_API_KEY", "").strip()
_OC_BASE = "https://api.opencorporates.com/v0.4"
_UA = "osint-mcp/1.0"
_HDRS = {"User-Agent": _UA, "Accept": "application/json"}


async def _get_json(url: str, *, params: dict | None = None, timeout: float = 20.0
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


def _oc_params(extra: dict | None = None) -> dict:
    p = dict(extra or {})
    if OC_KEY:
        p["api_token"] = OC_KEY
    return p


_LEGAL = re.compile(
    r"\b(aktiengesellschaft|gesellschaft mbh|gesellschaft|limited|incorporated|"
    r"corporation|gmbh|co\s*kg|ltd|inc|corp|plc|sa\b|sl\b|ag\b|nv\b|bv\b|"
    r"ab\b|oy\b|as\b|srl|spa|and\s+co|cie|llc|lp\b)\b",
    re.I,
)


def _norm(name: str) -> str:
    name = _LEGAL.sub("", (name or "").lower())
    return re.sub(r"[^a-z0-9]", "", name).strip()


async def _best_match(query: str, jurisdiction: str = "") -> tuple[dict | None, str | None, list]:
    data, err = await _get_json(f"{_OC_BASE}/companies/search",
                                params=_oc_params({"q": query, "per_page": 20,
                                                   "order": "score"}))
    if err:
        return None, err, []
    comps = [c.get("company") or {} for c in
             (((data or {}).get("results") or {}).get("companies") or [])]
    if not comps:
        return None, "нет совпадений в OpenCorporates", []
    hints = [f"{c.get('name')} ({c.get('jurisdiction_code')})" for c in comps[:6]]
    qn = _norm(query)
    named = [c for c in comps if _norm(c.get("name") or "") == qn]
    if not named:
        return None, "нет точного совпадения по названию", hints
    if jurisdiction:
        exact = [c for c in named
                 if (c.get("jurisdiction_code") or "").lower().startswith(jurisdiction.lower())]
        if exact:
            return exact[0], None, hints
        return None, f"название найдено, но не в юрисдикции {jurisdiction}", hints
    active = [c for c in named if not c.get("inactive")]
    return (active or named)[0], None, hints


@mcp.tool()
async def opencorporates_search(query: str) -> str:
    """OpenCorporates: поиск юрлиц по названию в множестве национальных реестров.
    Возвращает совпадения: название, номер, юрисдикция, статус. Полный доступ —
    с ключом OPENCORPORATES_API_KEY. Передай название компании."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "укажите название компании"}, ensure_ascii=False)
    data, err = await _get_json(f"{_OC_BASE}/companies/search",
                                params=_oc_params({"q": query, "per_page": 8,
                                                   "order": "score"}))
    if err:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OC_KEY else ""
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
    имена, должности, даты. Требует OPENCORPORATES_API_KEY. Передай ЮРИДИЧЕСКОЕ
    название; jurisdiction (код страны: 'es', 'de', 'us_de') сужает выборку если
    компания зарегистрирована в нескольких странах."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "укажите название компании"}, ensure_ascii=False)
    best, err, hints = await _best_match(query, (jurisdiction or "").strip())
    if err or not best:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OC_KEY else ""
        return json.dumps({"error": (err or "не найдено") + hint, "query": query,
                           "did_you_mean": hints}, ensure_ascii=False)
    jur, num = best.get("jurisdiction_code"), best.get("company_number")
    if not (jur and num):
        return json.dumps({"error": "нет идентификатора компании", "query": query,
                           "match": best.get("name")}, ensure_ascii=False)
    data, err = await _get_json(f"{_OC_BASE}/companies/{jur}/{num}",
                                params=_oc_params())
    if err:
        hint = " (нужен ключ OPENCORPORATES_API_KEY)" if not OC_KEY else ""
        return json.dumps({"error": err + hint, "company": best.get("name")},
                          ensure_ascii=False)
    company = ((data or {}).get("results") or {}).get("company") or {}
    officers = []
    for o in (company.get("officers") or [])[:40]:
        off = o.get("officer") or {}
        officers.append({"name": off.get("name"), "position": off.get("position"),
                         "start_date": off.get("start_date"),
                         "end_date": off.get("end_date")})
    return json.dumps({
        "company": company.get("name"),
        "jurisdiction": jur,
        "company_number": num,
        "opencorporates_url": company.get("opencorporates_url"),
        "officers_count": len(officers),
        "officers": officers,
    }, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
