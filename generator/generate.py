#!/usr/bin/env python3
"""Генератор конфигов из реестра серверов (спец. §3).

Читает registry/servers.yaml и собирает:
  - config/librechat.yaml   (эндпоинты LLM + блок mcpServers)
  - docker-compose.mcp.yml  (по одному сервису на stdio-сервер)
  - config/catalog.json     (метаданные каталога для UI)

Добавить сервер = правка реестра + запуск этого скрипта. Ручные правки
сгенерированных файлов затираются — единственный источник правды это реестр.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "registry" / "servers.yaml"
TEMPLATES = ROOT / "generator" / "templates"
OUT_LIBRECHAT = ROOT / "config" / "librechat.yaml"
OUT_COMPOSE = ROOT / "docker-compose.mcp.yml"
OUT_CATALOG = ROOT / "config" / "catalog.json"

VALID_TRANSPORT = {"stdio", "http", "sse"}
VALID_TIER = {"free", "freemium", "paid"}
VALID_AUTH = {"none", "api_key", "oauth"}

# Эмодзи-«иконка» по категории (LibreChat title не принимает эмодзи из-за regex,
# поэтому эмодзи идёт в начало description — там свободный текст).
CATEGORY_EMOJI = {
    "socmint": "🕵️",
    "network": "🌐",
    "scraping": "🕸️",
    "company": "🏢",
    "records": "📑",
    "threat": "🛡️",
    "research": "🔬",
    "blockchain": "⛓️",
    "meta": "🧭",
    "market": "📈",
}
CATEGORY_LABEL = {
    "socmint": "Соцсети/username",
    "network": "Сеть/домены",
    "scraping": "Веб-скрейпинг",
    "company": "Компании",
    "records": "Публичные записи",
    "threat": "Угрозы/IOC",
    "research": "Исследования",
    "blockchain": "Блокчейн",
    "meta": "Оркестрация",
    "market": "Рынок/новости",
}

# Типы целей → человекочитаемое имя (для авто-таблицы маршрутизации в промпте).
INPUT_LABEL = {
    "username": "username", "email": "email", "domain": "домен", "ip": "IP",
    "company": "компания", "inn": "ИНН", "ticker": "тикер", "hash": "хеш файла",
    "url": "URL", "query": "произвольный запрос",
}


def sanitize_title(name: str) -> str:
    """LibreChat title допускает только ^[a-zA-Z0-9 ]+$ — чистим остальное."""
    cleaned = "".join(ch if (ch.isascii() and (ch.isalnum() or ch == " ")) else " "
                      for ch in name)
    return " ".join(cleaned.split()) or "MCP"


def load_registry() -> dict:
    with REGISTRY.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not data or "servers" not in data:
        sys.exit("registry/servers.yaml: нет ключа 'servers'")
    return data


def validate(server: dict) -> list[str]:
    """Возвращает список проблем записи (пустой = ок)."""
    problems: list[str] = []
    sid = server.get("id", "<без id>")
    for field in ("id", "category", "display_name", "transport",
                  "install", "auth", "cost_tier", "inputs"):
        if field not in server:
            problems.append(f"{sid}: нет обязательного поля '{field}'")
    if server.get("transport") not in VALID_TRANSPORT:
        problems.append(f"{sid}: transport '{server.get('transport')}' невалиден")
    if server.get("cost_tier") not in VALID_TIER:
        problems.append(f"{sid}: cost_tier '{server.get('cost_tier')}' невалиден")
    auth = server.get("auth") or {}
    if auth.get("type") not in VALID_AUTH:
        problems.append(f"{sid}: auth.type '{auth.get('type')}' невалиден")
    if auth.get("type") == "api_key" and not auth.get("user_var"):
        problems.append(f"{sid}: auth.type=api_key требует auth.user_var")
    if server.get("transport") == "stdio":
        if not server.get("stdio_command"):
            problems.append(f"{sid}: transport=stdio требует stdio_command")
        if not server.get("build"):
            problems.append(f"{sid}: transport=stdio требует build (контекст Dockerfile)")
    if server.get("install") == "remote" and not server.get("url"):
        problems.append(f"{sid}: install=remote требует url")
    return problems


def resolve(server: dict, defaults: dict) -> dict:
    """Подставляет значения по умолчанию в запись."""
    merged = dict(server)
    merged.setdefault("sse_port", defaults.get("sse_port", 8000))
    merged.setdefault("base_image", defaults.get("base_image", "osint-mcp-base:latest"))
    merged.setdefault("repo", None)
    merged.setdefault("env", {})
    merged.setdefault("volumes", [])
    merged.setdefault("server_instructions", None)
    # UI-метаданные для LibreChat mcpServers:
    #   title — дружелюбное имя (ASCII, буквы/цифры/пробелы)
    #   ui_description — эмодзи-категория + плейн-описание из реестра
    # Статус ключа — самый частый вопрос в UI («почему сервер молчит?»), поэтому
    # он идёт ПЕРВЫМ в описании и (для платных) в заголовке. Три состояния:
    #   🔑 без ключа не работает вообще (paid + api_key)
    #   🟡 работает анонимно, ключ поднимает лимиты (freemium + api_key)
    #   🟢 ключ не нужен
    # ВАЖНО: cost_tier=freemium НЕ значит «работает без ключа» (у VirusTotal
    # бесплатный тариф, но ключ обязателен). Анонимный доступ отмечаем явным
    # полем anonymous_ok — только там, где это реально проверено запросом.
    raw_auth = server.get("auth") or {}
    has_key_field = raw_auth.get("type") in {"api_key", "oauth"}
    anon_ok = bool(server.get("anonymous_ok"))
    if has_key_field and not anon_ok:
        key_badge = "🔑 НУЖЕН КЛЮЧ"
    elif has_key_field:
        key_badge = "🟡 работает без ключа, ключ поднимает лимиты"
    elif merged["cost_tier"] == "paid":
        # платный, но ключа в UI нет — оплата на стороне сервиса (x402/Stripe)
        key_badge = "💳 ПЛАТНЫЙ (оплата на стороне сервиса)"
    else:
        key_badge = "🟢 без ключа"
    needs_key = has_key_field and not anon_ok
    merged["needs_key"] = needs_key
    merged["key_badge"] = key_badge
    # LibreChat строго валидирует title: только «letters, numbers, spaces»
    # (ZodError на эмодзи/пунктуацию). Поэтому весь визуальный бейдж (эмодзи +
    # статус ключа) идёт в description — там свободный текст, Cyrillic/эмодзи ок,
    # и он виден в списке серверов прямо под именем.
    merged["title"] = sanitize_title(merged["display_name"])
    emoji = CATEGORY_EMOJI.get(merged["category"], "•")
    merged["ui_description"] = f"{key_badge} · {emoji} {merged['description']}"
    # env_var — имя переменной, которую читает сам сервер внутри контейнера.
    # По умолчанию совпадает с user_var (именем ключа в .env). Отличается, когда
    # сервер ждёт другое имя (напр. Bright Data читает API_TOKEN).
    auth = dict(merged.get("auth") or {})
    if auth.get("type") == "api_key":
        auth.setdefault("env_var", auth.get("user_var"))
        # Как передавать ключ на remote-сервер:
        #  - header (по умолчанию Authorization) + scheme (по умолчанию Bearer), либо
        #  - query_param — ключ уходит в URL как ?param=... (тогда header не эмитится).
        auth.setdefault("header", "Authorization")
        auth.setdefault("scheme", "Bearer")
        auth.setdefault("query_param", None)
    merged["auth"] = auth
    # Метаданные для нативной формы ключей LibreChat (customUserVars):
    # заголовок поля и подсказка «как получить ключ» (можно переопределить в
    # реестре полем key_help).
    if auth.get("type") == "api_key" and auth.get("user_var"):
        merged["key_title"] = f"{merged['display_name']} — API-ключ"
        merged.setdefault(
            "key_help",
            f"Вставьте ваш API-ключ для «{merged['display_name']}». "
            "Хранится в вашем зашифрованном хранилище. Если не задать — "
            "используется общий ключ развёртывания (если он есть в .env).")
    return merged


def render(template_name: str, **ctx) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(template_name).render(**ctx)


def build_routing_table(servers: list[dict]) -> str:
    """Markdown-таблица «тип цели → серверы» из включённых серверов (поле inputs).

    Заменяет ручную (устаревавшую) таблицу — источник правды это реестр.
    """
    order = ["username", "email", "domain", "ip", "company", "inn", "ticker",
             "hash", "url", "query"]
    seen = {i for s in servers for i in s.get("inputs", [])}
    rows = ["| Тип цели | Серверы |", "|---|---|"]
    for inp in order:
        if inp not in seen:
            continue
        names = [s["display_name"] for s in servers if inp in s.get("inputs", [])
                 and s["id"] != "orchestrator"]
        if names:
            rows.append(f"| {INPUT_LABEL.get(inp, inp)} | {', '.join(names)} |")
    return "\n".join(rows)


def build_catalog(servers: list[dict]) -> list[dict]:
    """Метаданные для UI: что подключено, статус, бейдж стоимости, входы."""
    catalog = []
    for s in servers:
        auth = s.get("auth") or {}
        needs_key = auth.get("type") in {"api_key", "oauth"}
        # MCP-эндпоинт, по которому оркестратор зовёт сервер:
        #   stdio -> внутренний http://<id>:8000/mcp; remote -> публичный url.
        if s["transport"] == "stdio":
            endpoint = f"http://{s['id']}:{s['sse_port']}/mcp"
        else:
            endpoint = s.get("url")
            if auth.get("type") == "api_key" and auth.get("query_param") and auth.get("user_var"):
                endpoint = f"{endpoint}?{auth['query_param']}=${{{auth['user_var']}}}"
        catalog.append({
            "id": s["id"],
            "display_name": s["display_name"],
            "category": s["category"],
            "description": s["description"],
            "cost_tier": s["cost_tier"],
            "transport": s["transport"],
            "endpoint": endpoint,
            "inputs": s["inputs"],
            "requires_key": needs_key,
            "key_var": auth.get("user_var"),
            # Статус конфигурации, а не живой пинг: paid без ключа = требует ключ.
            "status": "needs_key" if needs_key else "ready",
            "repo": s.get("repo"),
        })
    return catalog


def main() -> None:
    data = load_registry()
    defaults = data.get("defaults") or {}
    all_servers = data["servers"]

    # Валидация всех записей (включая выключенные — чтобы ловить ошибки заранее).
    problems: list[str] = []
    seen_ids: set[str] = set()
    for s in all_servers:
        problems += validate(s)
        sid = s.get("id")
        if sid in seen_ids:
            problems.append(f"дубликат id: {sid}")
        seen_ids.add(sid)
    if problems:
        print("Ошибки в реестре:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)

    enabled = [resolve(s, defaults) for s in all_servers if s.get("enabled")]
    stdio_servers = [s for s in enabled if s["transport"] == "stdio"]

    # allowedDomains для mcpSettings: указание непустого списка отключает
    # SSRF-защиту LibreChat, которая иначе блокирует внутренние docker-хосты
    # (приватные IP). Список ДОЛЖЕН включать все серверы — и внутренние, и remote,
    # иначе не входящие в него будут отклонены.
    allowed_domains = []
    for s in enabled:
        if s["transport"] == "stdio":
            allowed_domains.append(s["id"])            # docker-имя сервиса
        elif s.get("url"):
            host = urlparse(s["url"]).hostname
            if host:
                allowed_domains.append(host)
    allowed_domains = sorted(set(allowed_domains))

    # Системный промпт с рецептами — вшивается в modelSpec-пресет (promptPrefix),
    # чтобы пресет «GigaChat · OSINT» сразу имел рецепты и большой контекст.
    prompt_path = ROOT / "config" / "system_prompt.md"
    system_prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""
    # Подставляем свежую таблицу маршрутизации (из реестра) на место маркера.
    system_prompt = system_prompt.replace(
        "<!-- ROUTING_TABLE -->", build_routing_table(enabled))
    # Короткий промпт для агентного пресета (вызывает orchestrator.investigate).
    auto_path = ROOT / "config" / "system_prompt_auto.md"
    system_prompt_auto = auto_path.read_text(encoding="utf-8") if auto_path.exists() else ""

    OUT_LIBRECHAT.parent.mkdir(parents=True, exist_ok=True)

    OUT_LIBRECHAT.write_text(
        render("librechat.yaml.j2", servers=enabled,
               allowed_domains=allowed_domains,
               system_prompt=system_prompt,
               system_prompt_auto=system_prompt_auto), encoding="utf-8")
    OUT_COMPOSE.write_text(
        render("compose.mcp.yml.j2", servers=stdio_servers), encoding="utf-8")
    OUT_CATALOG.write_text(
        json.dumps(build_catalog(enabled), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    print(f"Готово. Включённых серверов: {len(enabled)} "
          f"(stdio-контейнеров: {len(stdio_servers)}, "
          f"remote: {len(enabled) - len(stdio_servers)}).")
    print(f"  -> {OUT_LIBRECHAT.relative_to(ROOT)}")
    print(f"  -> {OUT_COMPOSE.relative_to(ROOT)}")
    print(f"  -> {OUT_CATALOG.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
