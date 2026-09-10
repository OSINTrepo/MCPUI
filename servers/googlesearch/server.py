"""Google Search MCP — тематический веб-поиск через Serper (Google-результаты)."""
from __future__ import annotations

import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Google Search")

SERPER_KEY = os.getenv("SERPER_API_KEY", "").strip()
GOOGLE_CSE_KEY = os.getenv("GOOGLE_CSE_API_KEY", "").strip()
GOOGLE_CSE_DEFAULT_CX = os.getenv("GOOGLE_CSE_DEFAULT_CX", "").strip()
_UA = "osint-mcp/1.0"

# Конкретные CX-идентификаторы Google Custom Search Engine по теме.
# Когда задан GOOGLE_CSE_API_KEY и движок есть в этом словаре — используется
# реальный тематический индекс Google CSE вместо site:/filetype:-дорков Serper.
CSE_CX_MAP: dict[str, str] = {
    "pastebin":         "000905274576528531678:zdstbilawf0",
    "raw_git":          "007791543817084091905:vmwkk8ksx9k",
    "docs":             "001580308195336108602:hx9tv6r_od4",
    "docs_formats":     "009462381166450434430:nudphlkt3p4",
    "people":           "009305272063906253811:0xqjdapfzsk",
    "sites_social_gov": "011373762844405469335:vl3rlrf7ziy",
    "social_community": "016621447308871563343:0p9cd3f8p-k",
    "social":           "012209864558240645678:orirysy9yqk",
    "us_federal":       "006636090781133203169:o9hlckv9egm",
    "docs_orgs":        "006748068166572874491:55ez0c3j3ey",
    "wiki":             "006775555251158006122:nxp0gaipa40",
    "gpo_gov":          "002733260306582994232:6gsdjfrruge",
    "edu":              "009267560011000861900:vaap19gqdq8",
    "jobs":             "009305272063906253811:wool_g5jew4",
    "hybrid_analysis":  "003089153695915392663:yi7j3xmja0w",
}

# Тематические движки: шаблон → site:/filetype:-фильтр для Serper
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
    "edu": "{q} site:.edu",
    "jobs": "{q} (site:linkedin.com/jobs OR site:hh.ru OR site:indeed.com OR site:glassdoor.com)",
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
    "hybrid_analysis": "{q} site:hybrid-analysis.com",
}

_ENGINE_DESCS = {
    "pastebin": "паст-сайты (утечки текста)",
    "raw_git": "raw git / код (секреты)",
    "docs": "офисные документы (PDF/DOC/XLS)",
    "docs_formats": "документы по форматам",
    "docs_orgs": "корпоративные документы / отчёты",
    "people": "общий поиск людей",
    "sites_social_gov": "сайты, соцмедиа, gov",
    "social_community": "соцсети, комьюнити (reddit/quora)",
    "social": "соцсети (FB/X/IG/LinkedIn/VK)",
    "us_federal": "US federal gov (.gov)",
    "wiki": "Wikipedia",
    "edu": "EDU-сайты",
    "jobs": "вакансии (LinkedIn/hh/Indeed)",
    "linkedin": "LinkedIn (люди/компании)",
    "telegram": "Telegram-каналы/чаты",
    "twitter_x": "X/Twitter",
    "github": "репозитории кода (GitHub/GitLab)",
    "pastes": "паст-сайты (расширенный список)",
    "leaks": "утечки / пробивы",
    "files": "офисные файлы (PDF/XLSX/DOCX)",
    "code_secrets": "конфиги / секреты в коде",
    "reddit": "Reddit",
    "forums": "форумы",
    "vk_ru": "ВКонтакте / Одноклассники",
    "news": "деловые СМИ (Reuters/Bloomberg/RBC)",
    "hybrid_analysis": "Hybrid Analysis (malware)",
}


def _host(url: str) -> str:
    import re
    m = re.search(r"https?://([^/]+)", url or "")
    return m.group(1).lower().replace("www.", "") if m else ""


async def _serper(q: str, num: int) -> tuple[dict | None, str | None]:
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.post("https://google.serper.dev/search",
                             headers={"X-API-KEY": SERPER_KEY,
                                      "Content-Type": "application/json"},
                             json={"q": q, "num": max(1, min(10, num))})
            if r.status_code == 401:
                return None, "неверный SERPER_API_KEY"
            if r.status_code == 429:
                return None, "лимит Serper исчерпан"
            r.raise_for_status()
            return r.json(), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


async def _google_cse(query: str, cx: str, num: int) -> tuple[dict | None, str | None]:
    """Google Custom Search API с конкретным CX."""
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            r = await c.get("https://www.googleapis.com/customsearch/v1",
                            params={"key": GOOGLE_CSE_KEY, "cx": cx,
                                    "q": query, "num": max(1, min(10, num))})
            if r.status_code == 401:
                return None, "неверный GOOGLE_CSE_API_KEY"
            if r.status_code == 429:
                return None, "лимит Google CSE исчерпан"
            r.raise_for_status()
            return r.json(), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


@mcp.tool()
async def web_search(query: str, engine: str = "", num: int = 10) -> str:
    """Тематический веб-поиск (Google-результаты через Serper или Google CSE).
    Укажи engine из web_search_engines (pastebin, docs, people, social, wiki,
    linkedin, telegram, github, leaks, files, news…) — он добавит site:/filetype:-фильтр
    или использует конкретный CSE-индекс (если задан GOOGLE_CSE_API_KEY).
    Без engine — обычный Google-поиск. Требует SERPER_API_KEY или GOOGLE_CSE_API_KEY."""
    query = (query or "").strip()
    if not query:
        return json.dumps({"error": "укажите поисковый запрос"}, ensure_ascii=False)
    if not SERPER_KEY and not GOOGLE_CSE_KEY:
        return json.dumps({"error": "нужен SERPER_API_KEY или GOOGLE_CSE_API_KEY. "
                           "Вставьте в ⚙ у сервера Google Search."}, ensure_ascii=False)
    eng_label = engine or "web"
    q = WEB_ENGINES[engine].format(q=query) if engine in WEB_ENGINES else query

    # Если есть CSE-ключ и для движка есть конкретный CX — используем тематический индекс.
    # Serper не имеет CX-индексов, поэтому при наличии обоих ключей:
    # • для движков из CSE_CX_MAP — Google CSE (точный индекс) имеет приоритет
    # • для остальных — Serper (лучшее качество и больше результатов)
    if GOOGLE_CSE_KEY and engine in CSE_CX_MAP:
        cx = CSE_CX_MAP[engine]
        search_page_url = (
            f"https://cse.google.com/cse?cx={cx}"
            f"&q={httpx.QueryParams({'q': query})}"
        )
        data, err = await _google_cse(query, cx, num)
        if err:
            # fallback → Serper если CSE отвалился
            if not SERPER_KEY:
                return json.dumps({"error": f"Google CSE недоступен ({err})",
                                   "engine": eng_label, "query": query,
                                   "search_url": search_page_url}, ensure_ascii=False)
        else:
            items = (data or {}).get("items") or []
            total = int(((data or {}).get("searchInformation") or {})
                        .get("totalResults", 0) or 0)
            results = [{"title": it.get("title"), "link": it.get("link"),
                        "snippet": " ".join((it.get("snippet") or "").split())[:300],
                        "source": it.get("displayLink")} for it in items[:num]]
            return json.dumps({"engine": eng_label, "query": query,
                               "backend": "google_cse", "cx": cx,
                               "search_url": search_page_url,
                               "total_results": total,
                               "count": len(results), "results": results},
                              ensure_ascii=False)

    if SERPER_KEY:
        data, err = await _serper(q, num)
        if err:
            return json.dumps({"error": f"поиск недоступен ({err})",
                               "engine": eng_label, "query": query}, ensure_ascii=False)
        items = (data or {}).get("organic") or []
        results = [{"title": it.get("title"), "link": it.get("link"),
                    "snippet": " ".join((it.get("snippet") or "").split())[:300],
                    "source": _host(it.get("link", ""))} for it in items[:num]]
        return json.dumps({"engine": eng_label, "query": q, "backend": "serper",
                           "total_results": len(results),
                           "count": len(results), "results": results}, ensure_ascii=False)

    # Fallback: Google CSE без конкретного CX (использует GOOGLE_CSE_DEFAULT_CX)
    if GOOGLE_CSE_KEY:
        use_cx = GOOGLE_CSE_DEFAULT_CX or CSE_CX_MAP.get(engine, "")
        if not use_cx:
            return json.dumps({"error": "нужен GOOGLE_CSE_DEFAULT_CX или SERPER_API_KEY"},
                              ensure_ascii=False)
        data, err = await _google_cse(q, use_cx, num)
        if err:
            return json.dumps({"error": f"Google CSE недоступен ({err})"},
                              ensure_ascii=False)
        items = (data or {}).get("items") or []
        results = [{"title": it.get("title"), "link": it.get("link"),
                    "snippet": " ".join((it.get("snippet") or "").split())[:300],
                    "source": it.get("displayLink")} for it in items[:num]]
        return json.dumps({"engine": eng_label, "query": q, "backend": "google_cse",
                           "count": len(results), "results": results}, ensure_ascii=False)

    return json.dumps({"error": "нет ключа поиска"}, ensure_ascii=False)


@mcp.tool()
async def web_search_engines() -> str:
    """Список тематических движков для web_search(engine=…) с описанием каждого.
    Движки из CSE_CX_MAP используют тематический Google CSE-индекс (если задан
    GOOGLE_CSE_API_KEY); остальные — site:/filetype:-дорк через Serper."""
    backend = "serper" if SERPER_KEY else ("google_cse" if GOOGLE_CSE_KEY else "none")
    descs = {k: v + (" [CSE-индекс]" if k in CSE_CX_MAP else "") for k, v in _ENGINE_DESCS.items()}
    return json.dumps({"backend": backend, "cse_cx_count": len(CSE_CX_MAP),
                       "engines": descs}, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run(transport="stdio")
