#!/usr/bin/env python3
"""Воспроизводимый прогон досье с сохранением исходных ответов для сравнения.

Запуск внутри orchestrator: python /app/tests/indra_pipeline.py baseline
Сетевой прогон использует тот же investigate, что и MCP; replay не опрашивает OSINT-источники (LLM-синтез повторяется).
"""
import argparse
import asyncio
import json
import logging
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, '/app')
import server

TASK = 'собери подробное досье по компании INDRA SISTEMAS SA, CIF A28599033, сайт indracompany.com'


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('label')
    parser.add_argument('--replay', type=Path)
    parser.add_argument('--supplement', type=Path, help='JSON дополнительных ответов с явным происхождением')
    parser.add_argument('--refresh', action='store_true', help='Повторить неполные новые источники перед replay')
    parser.add_argument('--model', help='Модель маршрутизации только для этого прогона')
    parser.add_argument('--report-model', help='Модель синтеза только для этого прогона')
    args = parser.parse_args()
    out = Path('/reports/indra-comparison') / args.label
    out.mkdir(parents=True, exist_ok=True)
    if args.model:
        server.MODEL = args.model
    if args.report_model:
        server.REPORT_MODEL = args.report_model
    # Graceful fallback не должен скрывать отказ LLM при сравнении моделей.
    calls = []
    send = server.httpx.AsyncClient.send
    async def measured_send(client, request, *pos, **kw):
        if str(request.url) != server.LITELLM_BASE + '/chat/completions':
            return await send(client, request, *pos, **kw)
        payload = json.loads(request.content)
        entry = {'model': payload.get('model'), 'max_tokens': payload.get('max_tokens'),
                 'messages': payload.get('messages')}
        began = time.monotonic()
        try:
            response = await send(client, request, *pos, **kw)
            entry['status'] = response.status_code
            if response.is_success:
                data = response.json()
                entry.update(upstream_model=data.get('model'), usage=data.get('usage'),
                             choices=data.get('choices'))
            # Тексты ошибок провайдера могут содержать секреты: только статус.
            return response
        except Exception as exc:
            entry['error_type'] = type(exc).__name__
            raise
        finally:
            entry['elapsed_seconds'] = round(time.monotonic() - began, 3)
            calls.append(entry)
            (out / 'llm_calls.json').write_text(json.dumps(calls, ensure_ascii=False, indent=2))
            print(f"LLM {entry['model']}: status={entry.get('status', entry.get('error_type'))}, "
                  f"{entry['elapsed_seconds']}s, usage={entry.get('usage')}", flush=True)
    server.httpx.AsyncClient.send = measured_send
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('weasyprint').setLevel(logging.ERROR)
    logging.getLogger('fontTools').setLevel(logging.ERROR)
    save = server.report.save_report

    def capture(task, results, when, reports_dir, url_base, synthesis=None, identity=None):
        (out / 'evidence.json').write_text(json.dumps(
            dict(task=task, results=results, when=when, synthesis=synthesis, identity=identity),
            ensure_ascii=False, indent=2))
        info = save(task, results, when, str(out),
                    server.REPORTS_URL_BASE + '/indra-comparison/' + args.label,
                    synthesis, identity)
        for key in ("html_dl_url", "pdf_dl_url", "md_dl_url"):
            if info.get(key):
                info[key] = info[key].replace("/indra-comparison/" + args.label + "/download/",
                                              "/download/indra-comparison/" + args.label + "/")
        return info

    server.report.save_report = capture
    build = server.build_company_dossier

    async def checkpoint(name, domains, results, identity=None):
        from datetime import datetime, timezone
        (out / 'evidence.json').write_text(json.dumps(dict(
            task=TASK, results=results, identity=identity, synthesis=None,
            when=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')),
            ensure_ascii=False, indent=2))
        return await build(name, domains, results, identity)
    server.build_company_dossier = checkpoint


    class Progress:
        async def report_progress(self, step, total, message):
            print(f'{time.monotonic() - started:.0f}s [{step}/{total}] {message}', flush=True)

    started = time.monotonic()
    if args.replay:
        record = json.loads(args.replay.read_text())
        ident, results = record['identity'], record['results']
        if args.refresh:
            selected = {}
            for r in results:
                if r.get('tool') in ('corporate_website', 'borme_publications', 'resolve_hosts'):
                    selected[r['tool']] = r
            for tool, previous in selected.items():
                target = {"type": previous.get("target_type") or "company",
                          "value": previous.get("target_value") or ident.get("query")}
                print("Refreshing", tool, flush=True)
                fresh = await server.run_one(previous['server'], target, tool, previous.get('args', {}))
                fresh.update(target_type=target["type"], target_value=target["value"], phase="refresh")
                results.append(fresh)
            server.reclassify(results)

        if args.supplement:
            results.extend(json.loads(args.supplement.read_text()))
        synthesis = await server.build_company_dossier(
            ident.get('legal_name') or 'INDRA SISTEMAS SA', ident.get('domains', []), results, ident)
        from datetime import datetime, timezone
        when = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        info = capture(record['task'], results, when, '', '', synthesis, ident)
        result = server.render_chat_summary(record['task'], results, info, ident)
    else:
        result = await server.investigate(TASK, Progress())
    (out / 'chat.md').write_text(result)
    print(result, flush=True)
    print(f'Elapsed: {time.monotonic() - started:.1f}s', flush=True)
    manifest = {'routing_model': server.MODEL, 'report_model': server.REPORT_MODEL,
                'elapsed_seconds': round(time.monotonic() - started, 3),
                'calls': len(calls), 'failed_calls': sum(c.get('status') != 200 for c in calls),
                'replay': str(args.replay) if args.replay else None,
                'replay_sha256': hashlib.sha256(args.replay.read_bytes()).hexdigest() if args.replay else None}
    (out / 'run.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
