# Maigret MCP — mcp-maigret (npm). Обёртка запускает maigret через `docker run`,
# поэтому в образе нужен docker-CLI, а сокет хоста монтируется в compose.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

# docker-CLI (клиент) для вызова sibling-контейнеров через сокет хоста.
RUN apt-get update && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g mcp-maigret
# Каталог отчётов (тот же путь монтируется с хоста — см. volumes в реестре).
RUN mkdir -p /tmp/maigret-reports

# Запуск: npx -y mcp-maigret (stdio_command в реестре), обёрнут supergateway в SSE.
