# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

# Прогреваем то же окружение, что используется при запуске, и проверяем импорты.
RUN uvx --from checko-mcp --with 'mcp==1.15.0' --with 'pydantic==2.13.5' python -c "from mcp.server.fastmcp import FastMCP"
