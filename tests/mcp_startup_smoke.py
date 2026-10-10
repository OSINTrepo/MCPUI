#!/usr/bin/env python3
"""Проверка запуска MCP без .env, LLM и запросов к OSINT-провайдерам.

Запуск в образе оркестратора с репозиторием в /workspace (read-only):
  CATALOG_PATH=/workspace/config/catalog.json python /workspace/tests/mcp_startup_smoke.py
Проверка работающего шлюза:
  python /app/mcp_startup_smoke.py --url http://127.0.0.1:8000/mcp
"""
from __future__ import annotations

import argparse
from datetime import timedelta
from importlib.metadata import version
import os
from pathlib import Path
import sys
import traceback

EXPECTED_TOOLS = {"investigate", "plan", "catalog", "call_server"}


async def check(args: argparse.Namespace) -> None:
    # Импорты внутри проверки: несовместимый SDK тоже даёт явный FAIL.
    import anyio
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamablehttp_client

    if args.url:
        transport = streamablehttp_client(
            args.url, timeout=args.timeout, sse_read_timeout=args.timeout)
    else:
        server = Path(args.server).resolve()
        if not server.is_file():
            raise RuntimeError(f"MCP server not found: {server}")
        repository_catalog = Path(__file__).resolve().parent.parent / "config/catalog.json"
        catalog_path = os.environ.get("CATALOG_PATH") or str(
            repository_catalog if repository_catalog.is_file() else Path("/app/catalog.json"))
        if not Path(catalog_path).is_file():
            raise RuntimeError(f"Catalog not found: {catalog_path}; set CATALOG_PATH")
        # SDK наследует только базовые системные переменные. Ключи хоста и .env
        # не нужны; сервер не должен писать __pycache__ в read-only checkout.
        transport = stdio_client(StdioServerParameters(
            command=sys.executable, args=[str(server)], cwd=str(server.parent),
            env={"CATALOG_PATH": str(Path(catalog_path).resolve()),
                 "PYTHONDONTWRITEBYTECODE": "1", "LITELLM_MASTER_KEY": "",
                 "ORCHESTRATOR_PAID_SOURCES": "0"}))

    with anyio.fail_after(args.timeout):
        async with transport as streams:
            async with ClientSession(
                    streams[0], streams[1],
                    read_timeout_seconds=timedelta(seconds=args.timeout)) as session:
                initialized = await session.initialize()
                if initialized.serverInfo.name != "orchestrator":
                    raise RuntimeError("initialize returned a different MCP server")
                tools = (await session.list_tools()).tools
                if {tool.name for tool in tools} != EXPECTED_TOOLS:
                    raise RuntimeError(f"Unexpected tools: {sorted(tool.name for tool in tools)}")
                schema = next(tool.inputSchema for tool in tools if tool.name == "catalog")
                if schema.get("type") != "object" or schema.get("required"):
                    raise RuntimeError("catalog must accept an empty object")
                result = await session.call_tool("catalog", {})
                text = "\n".join(block.text for block in result.content if block.type == "text")
                source_count = sum(line.startswith("  - ") for line in text.splitlines())
                if result.isError or not text.startswith("Доступные источники:") or not source_count:
                    raise RuntimeError("catalog returned an error or no configured sources")
    print(f"MCP startup OK: initialize; tools/list ({len(tools)} tools); catalog ({source_count} sources); "
          f"mcp={version('mcp')}, pydantic={version('pydantic')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    default_server = Path("/app/server.py")
    if not default_server.is_file():
        default_server = Path(__file__).resolve().parent.parent / "servers/orchestrator/server.py"
    target.add_argument("--server", default=str(default_server), help="stdio server.py path")
    target.add_argument("--url", help="Streamable HTTP MCP endpoint")
    parser.add_argument("--timeout", type=float, default=30, help="total timeout in seconds (default: 30)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        import anyio
        anyio.run(check, args)
    except Exception:
        print("FAIL: MCP startup smoke test", file=sys.stderr)
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
