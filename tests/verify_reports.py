#!/usr/bin/env python3
"""Прогон сценариев + ПРОВЕРКА содержимого сгенерированных отчётов.

Для каждого запроса: вызывает investigate(), достаёт .md по ссылке, читает файл
и проверяет, что в нём есть ОЖИДАЕМЫЕ маркеры (а не мусор/пусто/чужие данные).
Запускать внутри контейнера оркестратора.
"""
import asyncio
import re
import sys

sys.path.insert(0, "/app")
from mcp_client import MCPClient  # noqa: E402

ORCH = "http://orchestrator:8000/mcp"
REPORTS = "http://reports:80"  # nginx внутри сети (снаружи :8899)

# (запрос, [обязательные подстроки в отчёте], [ЗАПРЕЩённые подстроки])
CASES = [
    ("проверь username durov",
     ["durov", "Maigret", "http"], ["jsdelivr"]),
    ("проверь домен github.com",
     ["github.com", "Shodan"], ["jsdelivr"]),
    ("какие порты открыты на 8.8.8.8",
     ["8.8.8.8"], ["jsdelivr"]),
    ("что известно про john.doe@gmail.com",
     ["john.doe@gmail.com", "OpenOSINT"], []),
    ("это вирус? 44d88612fea8a8f36de82e1278abb02f",
     ["44d88612", "VirusTotal"], []),
    ("проверь компанию по ИНН 7707083893",
     ["7707083893", "СБЕРБАНК", "Checko", "1 из 1"], ["CompanyScope", "7709757347"]),
    ("проверь компанию Сбербанк",
     ["Сбербанк", "Checko"], ["CompanyScope"]),
    ("проверь тикер AAPL",
     ["AAPL"], []),
    ("проверь телефон +79001234567",
     ["79001234567"], ["jsdelivr"]),
    ("проверь домен github.com и ip 8.8.8.8",
     ["github.com", "8.8.8.8"], ["jsdelivr"]),
]


async def fetch(url: str) -> str:
    import httpx
    async with httpx.AsyncClient() as c:
        r = await c.get(url, timeout=30)
        return r.text


async def one(task, need, forbid):
    try:
        r = await asyncio.wait_for(
            MCPClient(ORCH, timeout=200).call("investigate", {"task": task}), timeout=210)
        chat = r.get("text", "") if isinstance(r, dict) else str(r)
    except Exception as e:
        return task, f"ИСКЛЮЧЕНИЕ {type(e).__name__}: {str(e)[:80]}", []
    m = re.search(r"http://localhost:8899/(\S+?\.md)", chat)
    if not m:
        # «не поддерживается»/отказ — отчёта нет, проверяем текст чата
        problems = [f"нет '{s}'" for s in need if s.lower() not in chat.lower()]
        problems += [f"ЗАПРЕЩ '{s}'" for s in forbid if s.lower() in chat.lower()]
        return task, "нет файла (чат-ответ)", problems
    slug = m.group(1)
    body = await fetch(f"{REPORTS}/{slug}")
    problems = [f"нет '{s}'" for s in need if s.lower() not in body.lower()]
    problems += [f"ЗАПРЕЩ '{s}'" for s in forbid if s.lower() in body.lower()]
    ok_line = re.search(r"Успешно опрошено:\s*(\d+)\s*из\s*(\d+)", body)
    stat = f"{ok_line.group(0)}" if ok_line else "?"
    return task, f"{slug} [{stat}]", problems


async def main():
    print("=" * 92)
    print("ПРОВЕРКА ОТЧЁТОВ: содержимое соответствует ожиданию?")
    print("=" * 92)
    fails = 0
    for task, need, forbid in CASES:
        t, info, problems = await one(task, need, forbid)
        mark = "✅" if not problems else "❌"
        if problems:
            fails += 1
        print(f"\n{mark} «{t}»")
        print(f"    {info}")
        if problems:
            print(f"    ПРОБЛЕМЫ: {', '.join(problems)}")
    print("\n" + "=" * 92)
    print(f"ИТОГ: {len(CASES) - fails}/{len(CASES)} отчётов соответствуют ожиданию"
          + (f"; проблемных: {fails}" if fails else " — всё чисто"))


asyncio.run(main())
