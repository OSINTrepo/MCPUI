"""Минимальный асинхронный MCP-клиент (Streamable HTTP + SSE-ответы).

Оркестратор — MCP-клиент к остальным серверам. Каждый вызов = свежая сессия:
initialize -> notifications/initialized -> tools/list | tools/call.
Ответ может быть application/json или SSE (text/event-stream) — разбираем оба.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

_ACCEPT = "application/json, text/event-stream"
_UA = "osint-orchestrator/1.0"


def _parse(body: str, want_id: Any) -> dict | None:
    body = body.strip()
    # 1) целиком JSON
    try:
        return json.loads(body)
    except Exception:
        pass
    # 2) SSE: собрать data:-строки в блоки по событиям
    data, blobs, cur = None, [], []
    for line in body.splitlines():
        if line.startswith("data:"):
            cur.append(line[5:].strip())
        elif not line.strip() and cur:
            blobs.append("\n".join(cur))
            cur = []
    if cur:
        blobs.append("\n".join(cur))
    for blob in blobs:
        try:
            obj = json.loads(blob)
        except Exception:
            continue
        if isinstance(obj, dict) and (obj.get("id") == want_id or "result" in obj or "error" in obj):
            data = obj
    return data


class MCPClient:
    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 60.0):
        self.url = url
        self.headers = {"Content-Type": "application/json", "Accept": _ACCEPT,
                        "User-Agent": _UA, **(headers or {})}
        self.timeout = timeout
        self.sid: str | None = None

    async def _post(self, client: httpx.AsyncClient, payload: dict) -> dict | None:
        h = dict(self.headers)
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        r = await client.post(self.url, content=json.dumps(payload), headers=h,
                              timeout=self.timeout)
        got = r.headers.get("Mcp-Session-Id")
        if got:
            self.sid = got
        return _parse(r.text, payload.get("id"))

    async def _open(self, client: httpx.AsyncClient) -> None:
        await self._post(client, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "orchestrator", "version": "1"}}})
        try:
            h = dict(self.headers)
            if self.sid:
                h["Mcp-Session-Id"] = self.sid
            await client.post(self.url, content=json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}),
                headers=h, timeout=15)
        except Exception:
            pass

    async def list_tools(self) -> list[dict]:
        async with httpx.AsyncClient() as client:
            await self._open(client)
            data = await self._post(client, {"jsonrpc": "2.0", "id": 2,
                                             "method": "tools/list", "params": {}})
        return (data or {}).get("result", {}).get("tools", []) if data else []

    async def call(self, tool: str, arguments: dict) -> dict:
        """Вернёт {'ok': bool, 'text': str, 'raw': obj}."""
        async with httpx.AsyncClient() as client:
            await self._open(client)
            data = await self._post(client, {"jsonrpc": "2.0", "id": 3,
                "method": "tools/call", "params": {"name": tool, "arguments": arguments}})
        if not data:
            return {"ok": False, "text": "нет ответа от сервера", "raw": None}
        if data.get("error"):
            return {"ok": False, "text": json.dumps(data["error"], ensure_ascii=False)[:500], "raw": data}
        res = data.get("result", {})
        text = " ".join(c.get("text", "") for c in res.get("content", [])
                        if isinstance(c, dict) and c.get("type") == "text")
        return {"ok": not res.get("isError", False), "text": text[:4000], "raw": res}
