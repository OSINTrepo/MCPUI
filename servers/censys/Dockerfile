ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN pip install --no-cache-dir --break-system-packages "mcp<2" httpx

# Build context = корень репозитория (compose.mcp.yml.j2).
COPY servers/censys/server.py /app/server.py
