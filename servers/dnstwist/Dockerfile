# DNSTwist MCP — @burtthecoder/mcp-dnstwist (npm). Обёртка запускает dnstwist
# через `docker run`, поэтому в образе нужен docker-CLI, а сокет монтируется в compose.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @burtthecoder/mcp-dnstwist
