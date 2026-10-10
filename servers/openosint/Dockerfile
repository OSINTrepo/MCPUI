# Восстановлены шаги ранее проверенного образа. Контекст сборки — корень репозитория.
ARG BASE_IMAGE=osint-mcp-base:latest
FROM ${BASE_IMAGE}

RUN pip install --no-cache-dir --break-system-packages sherlock-project holehe sublist3r

RUN uvx --from openosint --with 'mcp==1.15.0' --with 'pydantic==2.13.5' --with sublist3r python -c "from mcp.server.fastmcp import FastMCP"

RUN find /root/.cache/uv -name 'mcp_server.py' -path '*/openosint/*'     -exec sed -i       -e 's|return CallToolResult(content=\[TextContent(type="text", text=text)\], isError=False)|return [TextContent(type="text", text=text)]|g'       -e 's|return CallToolResult(content=\[TextContent(type="text", text=str(exc))\], isError=True)|raise Exception(str(exc))|g'       -e 's|return CallToolResult(content=\[TextContent(type="text", text=f"Internal error: {exc}")\],|raise Exception(f"Internal error: {exc}") #|g'     {} \;
