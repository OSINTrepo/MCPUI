# OpenOSINT — openosint (PyPI). MCP-режим отдаёт 18 инструментов без LLM-ключа.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}
# search_username использует sherlock, search_email — holehe. Ставим оба,
# иначе инструмент отвечает «not installed or not in PATH».
RUN pip install --no-cache-dir --break-system-packages sherlock-project holehe
# Прогрев кэша uv: скачивает пакет и проверяет имя на этапе сборки.
RUN uvx openosint --help || true
