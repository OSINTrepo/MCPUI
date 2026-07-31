# OSINT Orchestrator — свой MCP-сервер-фронт над остальными серверами.
# Build context = корень репозитория (см. compose.mcp.yml.j2), поэтому COPY
# берёт файлы по пути servers/orchestrator/.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

# Системные библиотеки для weasyprint (Markdown → PDF) + шрифты с кириллицей.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libffi8 shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY servers/orchestrator/ /app/
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

# Запуск задаётся stdio_command в реестре (python /app/server.py); supergateway
# оборачивает stdio в Streamable HTTP на :8000/mcp.
