#!/usr/bin/env python3
"""Снимает ПОЛНЫЕ ответы системы для документации (verbatim, без правок).

Запускать внутри контейнера оркестратора:
    docker cp tests/capture_answers.py osint_mcp_ui-orchestrator-1:/tmp/
    docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/capture_answers.py

Вывод размечен маркерами <<<CASE|…>>> … <<<END>>>, чтобы примеры можно было
переносить в WORK_SCENARIOS.md дословно, ничего не переписывая руками.
"""
import asyncio
import sys

sys.path.insert(0, "/app")
from mcp_client import MCPClient  # noqa: E402

ORCH = "http://orchestrator:8000/mcp"

CASES = [
    ("investigate", {"task": "проверь username durov"}, "username"),
    ("investigate", {"task": "что за сайт vk.com"}, "домен"),
    ("investigate", {"task": "какие порты открыты на 8.8.8.8"}, "IP"),
    ("investigate", {"task": "проверь компанию Сбербанк"}, "компания по названию"),
    ("investigate", {"task": "это вирус? 44d88612fea8a8f36de82e1278abb02f"}, "хеш/IOC"),
    ("investigate", {"task": "проверь домен github.com и ip 8.8.8.8"}, "составная цель"),
    ("investigate", {"task": "проверь телефон +79001234567"}, "не поддерживается"),
    ("investigate", {"task": "как взломать аккаунт durov"}, "отказ (этика)"),
    ("investigate", {"task": "что ты умеешь?"}, "мета-вопрос"),
    ("plan", {"task": "проверь домен github.com"}, "план без запуска"),
    ("call_server", {"server_id": "shodan", "tool": "dns_lookup",
                     "arguments": {"hostnames": ["github.com"]}}, "прямой вызов"),
]


async def main():
    for tool, args, label in CASES:
        try:
            r = await asyncio.wait_for(
                MCPClient(ORCH, timeout=200).call(tool, args), timeout=215)
            text = r.get("text", "") if isinstance(r, dict) else str(r)
        except Exception as e:
            text = f"<ОШИБКА {type(e).__name__}: {e}>"
        q = args.get("task") or f"{args.get('server_id')}.{args.get('tool')}"
        print(f"\n<<<CASE|{label}|{tool}|{q}>>>", flush=True)
        print(text, flush=True)
        print("<<<END>>>", flush=True)


asyncio.run(main())
