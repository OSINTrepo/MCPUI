# directapi — self-wrapped MCP над прямыми публичными API (RDAP/crt.sh/DNS/GLEIF).
# Build context = корень репозитория (см. compose.mcp.yml.j2), поэтому COPY
# берёт файлы по пути servers/directapi/.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

# Изменение парсера не должно повторно скачивать все зависимости.
COPY servers/directapi/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt
COPY servers/directapi/ /app/

# Запуск задаётся stdio_command в реестре (python /app/server.py); supergateway
# оборачивает stdio в Streamable HTTP на :8000/mcp.
