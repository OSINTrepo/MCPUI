# VulneraMCP — telmon95/VulneraMCP (git). TypeScript, сборка tsc -> dist/index.js.
# Ядро recon работает без ключей; Caido/ZAP/PostgreSQL — опциональные интеграции.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN git clone --depth 1 https://github.com/telmon95/VulneraMCP.git /app \
    && cd /app && npm install && npm run build
