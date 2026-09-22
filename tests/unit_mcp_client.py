"""HTTP-ошибки не превращаются в пустой каталог; сессия закрывается при сбое initialize."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'orchestrator'))
import httpx
from mcp_client import MCPClient, MCPProtocolError

class MCPClientTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, handler, operation='list_tools', tool='tool'):
        original = httpx.AsyncClient
        with patch('mcp_client.httpx.AsyncClient', side_effect=lambda **kw: original(transport=httpx.MockTransport(handler), **kw)):
            return await getattr(MCPClient('https://example.org/mcp?api_key=DO-NOT-EXPOSE'), operation)(*([tool, {}] if operation == 'call' else []))

    async def test_financial_history_is_not_cut_before_recent_years(self):
        payload = json.dumps({'data': {'history': 'x' * 25000, '2025': {'2110': 412062000}}})
        def handler(req):
            if req.method == 'DELETE':
                return httpx.Response(200)
            body = json.loads(req.content)
            if body['method'] == 'initialize':
                return httpx.Response(200, headers={'Mcp-Session-Id': 's'}, json={'result': {}})
            if body['method'] == 'notifications/initialized':
                return httpx.Response(202)
            return httpx.Response(200, json={'result': {'content': [{'type': 'text', 'text': payload}]}})
        result = await self.exercise(handler, 'call', 'get_finances')
        self.assertEqual(json.loads(result['text'])['data']['2025']['2110'], 412062000)

    async def test_http_error_is_explicit_and_secret_free(self):
        def handler(req): return httpx.Response(403, text='private provider body')
        with self.assertRaisesRegex(MCPProtocolError, '^MCP HTTP 403$'):
            await self.exercise(handler)

    async def test_initialization_error_closes_allocated_session(self):
        methods = []
        def handler(req):
            methods.append(req.method)
            if req.method == 'DELETE':
                self.assertEqual(req.headers['mcp-session-id'], 'allocated')
                return httpx.Response(200)
            return httpx.Response(200, headers={'Mcp-Session-Id': 'allocated'}, json={'error': {'code': -1}})
        for operation in ['list_tools', 'call']:
            methods.clear()
            with self.assertRaises(MCPProtocolError): await self.exercise(handler, operation)
            self.assertEqual(methods, ['POST', 'DELETE'])

    async def test_valid_empty_catalog_and_list_errors_are_distinct(self):
        for failed in [False, True]:
            methods=[]
            def handler(req):
                methods.append(req.method)
                if req.method == 'DELETE': return httpx.Response(200)
                body=json.loads(req.content)
                if body['method']=='initialize': return httpx.Response(200,headers={'Mcp-Session-Id':'s'},json={'result':{}})
                if body['method']=='notifications/initialized': return httpx.Response(202)
                return httpx.Response(200,json={'error':{'code':-1}} if failed else {'result':{'tools':[]}})
            if failed:
                with self.assertRaises(MCPProtocolError): await self.exercise(handler)
            else: self.assertEqual(await self.exercise(handler), [])
            self.assertEqual(methods[-1], 'DELETE')

if __name__=='__main__':unittest.main()
