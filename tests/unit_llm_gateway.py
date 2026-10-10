"""Проверка wire-протокола новых моделей без ключей и внешних запросов.

Запуск в контейнере LiteLLM: python /tmp/unit_llm_gateway.py /app/config.yaml
"""
import asyncio
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading

import litellm
import yaml

received = []


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        received.append(data)
        message = {'role': 'assistant', 'content': '{"company":"INDRA SISTEMAS SA"}'}
        finish = 'stop'
        if data.get('tools'):
            message = {'role': 'assistant', 'content': None, 'tool_calls': [{
                'id': 'call_test', 'type': 'function', 'function': {
                    'name': 'investigate', 'arguments': '{"task":"INDRA SISTEMAS SA"}'}}]}
            finish = 'tool_calls'
        response = {'id': 'chatcmpl-test', 'object': 'chat.completion', 'created': 1,
                    'model': data['model'], 'choices': [{'index': 0, 'message': message,
                    'finish_reason': finish}], 'usage': {'prompt_tokens': 20,
                    'completion_tokens': 8, 'total_tokens': 28}}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def main():
    config = yaml.safe_load(Path(sys.argv[1]).read_text())
    names = {'qwen-osint-fast', 'qwen-osint-report', 'deepseek-flash', 'qwen-plan-report', 'qwen3-8b-api'}
    models = [copy.deepcopy(m) for m in config['model_list'] if m['model_name'] in names]
    assert len(models) == len(names)
    stub = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=stub.serve_forever, daemon=True)
    thread.start()
    try:
        for m in models:
            params = m['litellm_params']
            params['api_key'] = 'test-not-a-real-key'
            params['api_base'] = f'http://127.0.0.1:{stub.server_port}/v1'
        router = litellm.Router(model_list=models, num_retries=0)
        for alias in sorted(names):
            for tool_call in (False, True):
                extra = {'tools': [{'type': 'function', 'function': {'name': 'investigate',
                         'description': 'Собрать досье', 'parameters': {'type': 'object',
                         'properties': {'task': {'type': 'string'}}, 'required': ['task']}}}]} if tool_call else {}
                response = await router.acompletion(model=alias, messages=[{
                    'role': 'user', 'content': 'Исследуй компанию INDRA SISTEMAS SA. Верни JSON.'}],
                    max_tokens=300, temperature=0.2, **extra)
                data = received[-1]
                expected = next(m['litellm_params']['model'].removeprefix('openai/')
                                for m in models if m['model_name'] == alias)
                assert data['model'] == expected
                assert data['max_tokens'] == 300
                assert 'extra_body' not in data
                if alias.startswith('qwen'):
                    assert data['enable_thinking'] is False
                else:
                    assert data['thinking'] == {'type': 'disabled'}
                msg = response.choices[0].message
                if tool_call:
                    assert msg.tool_calls[0].function.name == 'investigate'
                else:
                    assert json.loads(msg.content)['company'] == 'INDRA SISTEMAS SA'
            print(alias + ': JSON/content, tool_calls, лимит и отключение thinking — OK')
    finally:
        stub.shutdown()
        stub.server_close()


if __name__ == '__main__':
    asyncio.run(main())
