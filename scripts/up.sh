#!/usr/bin/env bash
# Поднять весь стек: базовый + сгенерированные MCP-серверы.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Нет .env — скопируйте: cp .env.example .env и заполните ключи." >&2
  exit 1
fi

# 1. Общий базовый образ для stdio-серверов.
docker build -t osint-mcp-base:latest servers/base

# 2. Актуализировать конфиги из реестра.
python generator/generate.py

# 3. Поднять стек (базовый + MCP). Добавьте --profile ratelimit для Redis.
docker compose -f docker-compose.yml -f docker-compose.mcp.yml up -d --build

echo
echo "UI: http://localhost:3080   LiteLLM: http://localhost:4000"
