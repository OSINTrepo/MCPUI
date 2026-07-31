# =============================================================================
# osint-mcp-base — общий образ для stdio MCP-серверов.
# Содержит node, python, uv и supergateway (stdio -> SSE).
# Собирается один раз:
#   docker build -t osint-mcp-base:latest servers/base
# Остальные серверы наследуются от него (ARG BASE_IMAGE).
# =============================================================================
FROM node:20-bookworm-slim

# Python + инструменты сборки для серверов на pip/uvx (Maigret, dnstwist, ...).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv git ca-certificates wget nmap whois \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

# uv / uvx для python-серверов (zoomeye, checko).
RUN pip install --no-cache-dir --break-system-packages uv

# supergateway оборачивает stdio-сервер в Streamable HTTP. Версия закреплена —
# от неё зависит патч ниже (проброс per-user ключа из заголовка X-Mcp-Env в env).
RUN npm install -g supergateway@3.4.3
COPY patch_supergateway.js /tmp/patch_supergateway.js
RUN node /tmp/patch_supergateway.js

WORKDIR /app
