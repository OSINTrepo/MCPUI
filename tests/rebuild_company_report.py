#!/usr/bin/env python3
"""Пересборка досье из сохранённых источников и ответов LLM; сеть не используется."""
import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path
import sys
sys.path.insert(0, '/app')
import server


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    for name in ('weasyprint', 'fontTools', 'httpx'):
        logging.getLogger(name).setLevel(logging.ERROR)
    record = json.loads((args.source / 'evidence.json').read_text())
    calls = json.loads((args.source / 'llm_calls.json').read_text())
    pending = list(calls)

    async def recorded_llm(messages, **kwargs):
        if not pending:
            raise RuntimeError('Не хватает сохранённых ответов LLM')
        call = pending.pop(0)
        if call.get('status') != 200 or call.get('max_tokens') != kwargs.get('max_tokens'):
            raise RuntimeError('Сохранённый ответ не соответствует этапу конвейера')
        return call['choices'][0]['message']['content']

    server.llm = recorded_llm
    identity = record['identity']
    body = await server.build_company_dossier(identity.get('legal_name') or record['task'],
        identity.get('domains', []), record['results'], identity)
    if pending:
        raise RuntimeError('Не все сохранённые ответы использованы: этапы конвейера изменились')
    previous = record.get('synthesis') or ''
    provenance = previous.split('\n\n', 1)[0] if previous.startswith('> **Повторная сборка') else (
        f"> **Повторная сборка отчёта:** использованы сохранённые ответы источников от {record['when']}; новые источники не опрашивались.")
    record['synthesis'] = provenance + '\n\n' + (body or '')
    args.destination.mkdir(parents=True, exist_ok=True)
    url = server.REPORTS_URL_BASE + '/' + args.destination.relative_to('/reports').as_posix()
    info = server.report.save_report(record['task'], record['results'], record['when'],
        str(args.destination), url, record['synthesis'], identity)
    (args.destination / 'evidence.json').write_text(json.dumps(record, ensure_ascii=False, indent=2))
    (args.destination / 'llm_calls.json').write_text(json.dumps(calls, ensure_ascii=False, indent=2))
    manifest = json.loads((args.source / 'run.json').read_text())
    manifest.update(rebuild_source=str(args.source), network_calls_during_rebuild=0,
        llm_responses_reused=len(calls),
        source_evidence_sha256=hashlib.sha256((args.source / 'evidence.json').read_bytes()).hexdigest())
    (args.destination / 'run.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    public = {k: v for k, v in info.items() if k.endswith('_url') or k == 'slug'}
    for key in ('html_dl_url', 'pdf_dl_url', 'md_dl_url'):
        if public.get(key):
            public[key] = public[key].replace(url + '/download/', server.REPORTS_URL_BASE + '/download/' + args.destination.relative_to('/reports').as_posix() + '/')
    (args.destination / 'artifacts.json').write_text(json.dumps(public, ensure_ascii=False, indent=2))
    print(json.dumps(public, ensure_ascii=False))


if __name__ == '__main__':
    asyncio.run(main())
