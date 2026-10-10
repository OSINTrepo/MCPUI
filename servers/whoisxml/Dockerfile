ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}
RUN pip install --no-cache-dir --break-system-packages "mcp<2" httpx
COPY servers/common/ /app/common/
# Build context = корень репозитория.
COPY servers/whoisxml/server.py /app/server.py
