# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN npm install -g @burtthecoder/mcp-shodan     && sed -i 's/timeout: 10000/timeout: 30000/'        /usr/local/lib/node_modules/@burtthecoder/mcp-shodan/build/helpers.js
