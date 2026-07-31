#!/usr/bin/env python3
"""Сквозной прогон рабочих сценариев OSINT-платформы.

Запускается ВНУТРИ контейнера orchestrator (он на osint_net, у него есть httpx
и mcp_client). Фазы:
  health  — tools/list по всем серверам реестра (матрица доступности)
  tools   — поверхность оркестратора: catalog / plan / call_server
  invest  — investigate() по разным типам целей (медленно, ~1 мин на цель)
"""
import asyncio
import json
import os
import re
import sys
import time

sys.path.insert(0, "/app")
from mcp_client import MCPClient  # noqa: E402

ORCH = "http://orchestrator:8000/mcp"
CATALOG = json.load(open("/app/catalog.json", encoding="utf-8"))


def sub_env(url: str) -> str:
    """Подставить ${VAR} из окружения (remote-серверы с ключом в URL)."""
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), url or "")


async def probe(entry: dict) -> dict:
    sid, ep = entry["id"], sub_env(entry.get("endpoint") or "")
    if not ep:
        return {"id": sid, "ok": False, "note": "нет endpoint"}
    t0 = time.time()
    try:
        tools = await asyncio.wait_for(MCPClient(ep, timeout=30).list_tools(), timeout=45)
        return {"id": sid, "ok": bool(tools), "tools": len(tools),
                "dt": round(time.time() - t0, 1), "tier": entry["cost_tier"],
                "note": "" if tools else "0 инструментов"}
    except Exception as e:
        return {"id": sid, "ok": False, "dt": round(time.time() - t0, 1),
                "tier": entry["cost_tier"], "note": f"{type(e).__name__}: {str(e)[:60]}"}


async def phase_health():
    print("=" * 72)
    print("ФАЗА 1 — доступность MCP-серверов (initialize + tools/list)")
    print("=" * 72)
    res = await asyncio.gather(*(probe(e) for e in CATALOG))
    ok = [r for r in res if r["ok"]]
    for r in sorted(res, key=lambda x: (not x["ok"], x["id"])):
        mark = "✅" if r["ok"] else "❌"
        extra = f"{r.get('tools', 0):>3} инстр." if r["ok"] else r["note"]
        print(f"  {mark} {r['id']:<16} {r.get('tier',''):<8} {extra}  ({r.get('dt','?')}s)")
    print(f"\n  ИТОГО: {len(ok)}/{len(res)} серверов отвечают, "
          f"инструментов суммарно: {sum(r.get('tools',0) for r in ok)}")
    return res


async def call_orch(tool: str, args: dict, timeout: float = 180) -> str:
    r = await asyncio.wait_for(MCPClient(ORCH, timeout=timeout).call(tool, args),
                               timeout=timeout + 15)
    return r.get("text", "") if isinstance(r, dict) else str(r)


async def phase_tools():
    print("\n" + "=" * 72)
    print("ФАЗА 2 — поверхность оркестратора (catalog / plan / call_server)")
    print("=" * 72)

    cat = await call_orch("catalog", {}, 60)
    n_lines = len(re.findall(r"^\s*[-•]", cat, re.M))
    print(f"\n  catalog()      -> {len(cat)} симв.; серверов в тексте: {n_lines}")
    print("    " + " / ".join(cat.splitlines()[:2])[:150])

    pl = await call_orch("plan", {"task": "проверь домен github.com"}, 90)
    print(f"\n  plan(домен)    -> {len(pl)} симв.")
    print("    " + " ⏎ ".join(pl.splitlines()[:4])[:220])

    cs = await call_orch("call_server", {
        "server_id": "shodan", "tool": "dns_lookup",
        "arguments": {"hostnames": ["github.com"]}}, 90)
    print(f"\n  call_server()  -> {len(cs)} симв.")
    print("    " + " ⏎ ".join(cs.splitlines()[:3])[:220])


SCENARIOS = [
    ("username", "проверь username durov"),
    ("домен", "собери досье по домену github.com"),
    ("IP", "проверь ip 8.8.8.8"),
    ("email", "проверь email test@example.com"),
    ("хеш/IOC", "проверь хеш 44d88612fea8a8f36de82e1278abb02f"),
    ("компания/ИНН", "проверь компанию по ИНН 7707083893"),
]


async def phase_invest(only: str | None = None):
    print("\n" + "=" * 72)
    print("ФАЗА 3 — investigate() по типам целей (полный цикл + отчёт)")
    print("=" * 72)
    for label, task in SCENARIOS:
        if only and only != label:
            continue
        t0 = time.time()
        try:
            out = await call_orch("investigate", {"task": task}, 200)
        except Exception as e:
            print(f"\n  ❌ {label:<14} ИСКЛЮЧЕНИЕ {type(e).__name__}: {str(e)[:80]}")
            continue
        dt = round(time.time() - t0, 1)
        md = re.findall(r"http://localhost:8899/(\S+?\.md)", out)
        pdf = re.findall(r"http://localhost:8899/(\S+?\.pdf)", out)
        links = len(re.findall(r"https?://", out))
        srcs = len(re.findall(r"^\s*[-•]\s", out, re.M))
        bad = re.findall(r"jsdelivr|drive\.google", out)
        n_md, n_pdf = (md[0] if md else "—"), (pdf[0] if pdf else "—")
        mark = "✅" if (md and pdf) else "⚠️"
        print(f"\n  {mark} {label:<14} {dt}s | {len(out)} симв. | ссылок: {links} | "
              f"строк-находок: {srcs}")
        print(f"       отчёт: MD={n_md}  PDF={n_pdf}")
        if bad:
            print(f"       ❌ ВЫДУМАННЫЕ ДОМЕНЫ: {set(bad)}")
        print("       " + " ⏎ ".join(out.splitlines()[:3])[:200])


async def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    if phase in ("health", "all"):
        await phase_health()
    if phase in ("tools", "all"):
        await phase_tools()
    if phase in ("invest", "all"):
        await phase_invest(sys.argv[2] if len(sys.argv) > 2 else None)


asyncio.run(main())
