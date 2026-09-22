"""Проверка восстановленного стека: MCP discovery, маршруты LLM и публичный DNS.

Запуск внутри orchestrator. Два коротких LLM-запроса расходуют баланс провайдеров.
Не запускает массовый OSINT-сбор; результаты пишет в /reports/recovery-checks.json.
"""
import asyncio
import json
import logging
from pathlib import Path
import sys
import time
sys.path.insert(0, '/app')
import httpx
import server
from mcp_client import MCPClient

async def main():
    logging.getLogger('httpx').setLevel(logging.WARNING)
    retry = "--retry-failed" in sys.argv
    output = Path("/reports/recovery-checks.json")
    results = json.loads(output.read_text()) if retry else []
    limit = asyncio.Semaphore(4)
    async def discovery(sid, item):
        async with limit:
            start = time.monotonic()
            try:
                timeout = 90 if item['transport'] == 'stdio' else 12
                found = await asyncio.wait_for(MCPClient(item['endpoint'], timeout=timeout).list_tools(), timeout + 20)
                row = dict(check='mcp', server=sid, transport=item['transport'], ok=bool(found), tools=len(found))
            except Exception as exc:
                row = dict(check='mcp', server=sid, transport=item['transport'], ok=False, error=type(exc).__name__)
            row['seconds'] = round(time.monotonic() - start, 2)
            results[:] = [r for r in results if not (r['check'] == 'mcp' and r.get('server') == sid)]
            results.append(row)
            print(json.dumps(row), flush=True)
    catalog = dict(server.CATALOG)
    catalog['orchestrator'] = dict(endpoint='http://orchestrator:8000/mcp', transport='stdio')
    if retry:
        failed = {r['server'] for r in results if r['check'] == 'mcp' and not r['ok']}
        catalog = {k: v for k, v in catalog.items() if k in failed}
    await asyncio.gather(*(discovery(k, v) for k, v in catalog.items()))
    if retry:
        output.write_text(json.dumps(results, ensure_ascii=False, indent=2))
        assert all(r['ok'] for r in results if r.get('transport') == 'stdio'), 'Local discovery failed'
        return
    for alias in ['deepseek-flash', 'qwen-plan-report']:
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                response = await client.post(server.LITELLM_BASE+'/chat/completions',
                    headers={'Authorization': 'Bearer '+server.LITELLM_KEY}, json={
                    'model': alias, 'messages': [{'role': 'user', 'content': 'Use investigate for INDRA SISTEMAS SA, CIF A28599033.'}],
                    'tools': [{'type': 'function', 'function': {'name': 'investigate', 'description': 'Collect a company dossier',
                              'parameters': {'type': 'object', 'properties': {'task': {'type': 'string'}}, 'required': ['task']}}}],
                    'max_tokens': 160, 'temperature': 0})
                calls = response.json().get('choices', [{}])[0].get('message', {}).get('tool_calls', [])
                passed = bool(calls) and calls[0]['function']['name'] == 'investigate' and 'INDRA' in json.loads(calls[0]['function']['arguments']).get('task', '').upper()
                row = dict(check='llm_tool_call', model=alias, status=response.status_code, ok=passed)
        except Exception as exc:
            row = dict(check='llm_tool_call', model=alias, ok=False, error=type(exc).__name__)
        results.append(row); print(json.dumps(row), flush=True)
    for tool, args in [('plan', {'task': 'Собери досье INDRA SISTEMAS SA, CIF A28599033, indracompany.com'})]:
        response = await MCPClient('http://orchestrator:8000/mcp', timeout=30).call(tool, args)
        row = dict(check='orchestrator_'+tool, ok=response['ok'] and 'indra' in response['text'].lower())
        results.append(row); print(json.dumps(row), flush=True)
    response = await MCPClient('http://directapi:8000/mcp', timeout=40).call('dns_records', {'domain': 'indracompany.com'})
    try:
        payload = json.loads(response['text'])
        valid = bool(payload.get('A') or payload.get('NS'))
    except (ValueError, TypeError):
        valid = False
    row = dict(check='public_dns', ok=response['ok'] and valid)
    results.append(row); print(json.dumps(row), flush=True)
    Path('/reports/recovery-checks.json').write_text(json.dumps(results, ensure_ascii=False, indent=2))
    # Внешние сервисы могут быть недоступны независимо от исправности локального стека.
    failures = [r for r in results if not r['ok'] and r.get('transport') != 'http' and r.get('transport') != 'sse']
    if failures:
        raise SystemExit('Не прошли локальные/API проверки: '+json.dumps(failures))

if __name__ == '__main__':
    asyncio.run(main())
