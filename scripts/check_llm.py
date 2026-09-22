#!/usr/bin/env python3
"""Проверка tool calling и JSON через шлюз; запуск внутри orchestrator.

Не выполняет investigate и не обращается к OSINT-источникам.
Два запроса к выбранной модели: для облачной модели расходуют баланс API.
"""
import json
import os
import sys
import urllib.request


def completion(model, messages, **kwargs):
    base = os.environ.get('LITELLM_BASE_URL', 'http://litellm:4000/v1').rstrip('/')
    body = json.dumps(dict(model=model, messages=messages, temperature=0,
                           max_tokens=256, **kwargs)).encode()
    request = urllib.request.Request(base + '/chat/completions', body, headers={
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + os.environ.get('LITELLM_MASTER_KEY', '')})
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)['choices'][0]['message']


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('ORCHESTRATOR_MODEL')
    if not model:
        raise SystemExit('Укажите alias модели из litellm/config.yaml.')
    message = completion(model, [{'role': 'user', 'content':
        'Call investigate with task="Example Corporation". Do not answer from memory.'}], tools=[{
        'type': 'function', 'function': {'name': 'investigate', 'description': 'Create a company report',
        'parameters': {'type': 'object', 'properties': {'task': {'type': 'string'}},
                       'required': ['task']}}}])
    calls = message.get('tool_calls') or []
    if not any(c.get('function', {}).get('name') == 'investigate'
               and json.loads(c['function']['arguments']).get('task') == 'Example Corporation'
               for c in calls):
        raise SystemExit('FAIL: модель не вернула корректный вызов investigate.')
    message = completion(model, [{'role': 'user', 'content':
        'Return only this JSON object, without markdown: {"company":"Example Corporation"}'}])
    data = json.loads(message.get('content') or '')
    if data.get('company') != 'Example Corporation':
        raise SystemExit('FAIL: модель не вернула ожидаемый JSON.')
    print('OK: ' + model + ' — вызов investigate и JSON работают. Качество полного досье проверяется отдельно.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Ответы провайдера могут содержать настройки: печатаем только тип ошибки.
        raise SystemExit('FAIL: ' + type(exc).__name__ + '. Проверьте модель, шлюз и журнал сервиса.') from None
