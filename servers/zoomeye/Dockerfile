# ZoomEye MCP — mcp-server-zoomeye (PyPI, python). Требует ZOOMEYE_API_KEY (env).
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}
# Прогрев кэша uv: скачивает пакет и проверяет имя на этапе сборки.
RUN uvx mcp-server-zoomeye --help || true
