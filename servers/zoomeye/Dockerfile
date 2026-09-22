# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN uvx --with httpx --with 'mcp==1.15.0' mcp-server-zoomeye --help || true
