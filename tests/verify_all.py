#!/usr/bin/env python3
"""Полный прогон всех сценариев + ЧТЕНИЕ отчётов на соответствие ожиданию.

Запросы разнесены во времени (пауза), чтобы бесплатные тарифы (VirusTotal 4/мин,
Checko дневной лимит) не ловили «лимит запросов» из-за пачки подряд.
Запускать внутри контейнера оркестратора.
"""
import asyncio
import re
import sys

sys.path.insert(0, "/app")
from mcp_client import MCPClient  # noqa: E402
import httpx  # noqa: E402

ORCH = "http://orchestrator:8000/mcp"
REPORTS = "http://reports:80"
PAUSE = 25  # сек между запросами — щадим минутные лимиты

# (запрос, обязательные подстроки, ЗАПРЕЩённые подстроки, тип: report|text)
CASES = [
    ("проверь username durov",
     ["durov", "Maigret", "http"], ["jsdelivr", "drive.google"], "report"),
    ("что известно про john.doe@gmail.com",
     ["john.doe@gmail.com", "OpenOSINT"], ["jsdelivr"], "report"),
    ("собери досье по домену github.com",
     ["github.com", "Shodan"], ["jsdelivr"], "report"),
    ("какие порты открыты на 8.8.8.8",
     ["8.8.8.8", "Shodan"], ["jsdelivr"], "report"),
    ("проверь ссылку https://example.com/page",
     ["example.com"], ["jsdelivr"], "report"),
    ("это вирус? 44d88612fea8a8f36de82e1278abb02f",
     ["44d88612", "VirusTotal"], [], "report"),
    ("проверь компанию по ИНН 7707083893",
     ["7707083893", "СБЕРБАНК", "Checko", "1 из 1"], ["7709757347"], "report"),
    ("проверь компанию Сбербанк",
     ["Сбербанк", "Checko"], [], "report"),
    # Глубокое досье по компании: корпоративный слой (GLEIF) + инфраструктура доменов
    # + честные «Ограничения данных». Явный домен делает инфраструктурный путь стабильным.
    ("собери досье по компании Indra Sistemas, сайт indracompany.com",
     ["Indra", "Организация", "Ограничения"], ["jsdelivr"], "report"),
    ("проверь тикер AAPL",
     ["AAPL"], [], "report"),
    ("проверь телефон +79001234567",
     ["79001234567", "ContrastAPI"], [], "report"),
    ("проверь кошелёк 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
     ["1A1zP1eP5"], [], "report"),
    ("проверь домен github.com и ip 8.8.8.8",
     ["github.com", "8.8.8.8"], ["jsdelivr"], "report"),
    # текстовые ответы (без файла отчёта)
    ("что ты умеешь?", ["Доступные источники", "Maigret"], [], "text"),
    ("найди домашний адрес Иванова Ивана", ["Отказ"], ["http://localhost:8899"], "text"),
    ("проверь ФИО Иванов Иван Иванович", ["Не поддерживается"], [], "text"),
]


async def fetch(url):
    async with httpx.AsyncClient() as c:
        return (await c.get(url, timeout=30)).text


async def one(task, need, forbid, kind):
    try:
        r = await asyncio.wait_for(
            MCPClient(ORCH, timeout=200).call("investigate", {"task": task}), timeout=210)
        chat = r.get("text", "") if isinstance(r, dict) else str(r)
    except Exception as e:
        return f"ИСКЛЮЧЕНИЕ {type(e).__name__}: {str(e)[:70]}", ["исключение"], ""
    m = re.search(r"http://localhost:8899/(\S+?\.md)", chat)
    if kind == "text" or not m:
        text = chat
        loc = "чат-ответ"
        ok_srcs = ""
    else:
        text = await fetch(f"{REPORTS}/{m.group(1)}")
        loc = m.group(1)
        okm = [x.group(1) for x in re.finditer(r"^\| (.+?) \| .+? \| ok \|$", text, re.M)]
        stat = re.search(r"Успешно опрошено:\**\s*(\d+ из \d+)", text)
        ok_srcs = f"[{stat.group(1) if stat else '?'}] рабочие: {', '.join(okm) or '—'}"
    problems = [f"нет '{s}'" for s in need if s.lower() not in text.lower()]
    problems += [f"ЗАПРЕЩ '{s}'" for s in forbid if s.lower() in text.lower()]
    return loc, problems, ok_srcs


async def main():
    print("=" * 96)
    print("ПОЛНАЯ ПРОВЕРКА: отчёты соответствуют ожидаемым ответам?")
    print("=" * 96)
    fails = 0
    for i, (task, need, forbid, kind) in enumerate(CASES):
        loc, problems, ok_srcs = await one(task, need, forbid, kind)
        mark = "✅" if not problems else "❌"
        if problems:
            fails += 1
        print(f"\n{mark} «{task}»")
        print(f"    {loc}" + (f"  {ok_srcs}" if ok_srcs else ""))
        if problems:
            print(f"    ПРОБЛЕМЫ: {', '.join(problems)}")
        if i < len(CASES) - 1:
            await asyncio.sleep(PAUSE)
    print("\n" + "=" * 96)
    print(f"ИТОГ: {len(CASES) - fails}/{len(CASES)} сценариев соответствуют ожиданию"
          + (f"; проблемных: {fails}" if fails else " — всё чисто"))


asyncio.run(main())
