#!/usr/bin/env bash
# Остановить стек. С аргументом --wipe удалить тома (Mongo/Meili).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--wipe" ]; then
  docker compose -f docker-compose.yml -f docker-compose.mcp.yml down -v
else
  docker compose -f docker-compose.yml -f docker-compose.mcp.yml down
fi
