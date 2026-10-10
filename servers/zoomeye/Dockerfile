# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN uvx --from mcp-server-zoomeye --with httpx --with 'mcp==1.15.0' --with 'pydantic==2.13.5' python -c "from mcp.server.fastmcp import FastMCP"
