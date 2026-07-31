# Checko MCP — checko-mcp (PyPI, python). Требует CHECKO_API_KEY (env).
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}
# Прогрев кэша uv: скачивает пакет и проверяет имя на этапе сборки.
RUN uvx checko-mcp --help || true
