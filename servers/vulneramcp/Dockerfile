# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

ARG SUBFINDER_VERSION=2.6.6

RUN apt-get update && apt-get install -y --no-install-recommends unzip     && rm -rf /var/lib/apt/lists/*     && ARCH="$(dpkg --print-architecture)"     && case "$ARCH" in          amd64) SF_ARCH=amd64 ;;          arm64) SF_ARCH=arm64 ;;          *) SF_ARCH=amd64 ;;        esac     && wget -qO /tmp/subfinder.zip         "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${SF_ARCH}.zip"     && unzip -q -o /tmp/subfinder.zip -d /usr/local/bin subfinder     && chmod +x /usr/local/bin/subfinder     && rm -f /tmp/subfinder.zip     && subfinder -version

RUN git clone --depth 1 https://github.com/telmon95/VulneraMCP.git /app     && cd /app && npm install && npm run build

COPY servers/vulneramcp/patch-postgres.js /app/dist/integrations/postgres.js
