# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends         libpango-1.0-0 libpangoft2-1.0-0 libffi8 shared-mime-info         fonts-dejavu-core     && rm -rf /var/lib/apt/lists/*

COPY servers/orchestrator/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --break-system-packages --timeout 90 --retries 3 -r /app/requirements.txt
# Проверка импортов обязательна: /healthz шлюза не проверяет дочерний MCP-процесс.
RUN pip check && python -c "from mcp.server.fastmcp import Context, FastMCP"

COPY servers/orchestrator/ /app/
COPY tests/mcp_startup_smoke.py /app/mcp_startup_smoke.py
