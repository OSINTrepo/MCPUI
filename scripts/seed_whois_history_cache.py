#!/usr/bin/env python3
"""Импорт уже оплаченных ответов истории без сетевого запроса и смены даты."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers'))
from common.whois_history_cache import seed_history


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path, help='evidence.json с results или список WHOIS-ответов')
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    rows = evidence.get('results', []) if isinstance(evidence, dict) else evidence
    imported, skipped = [], 0
    for row in rows:
        if row.get('tool') != 'whois_history' or not row.get('ok'):
            continue
        try:
            payload = json.loads(row['text'])
            provider = payload['source']
            key = os.environ.get({'WhoisXML': 'WHOISXML_API_KEY', 'Whoxy': 'WHOXY_API_KEY'}[provider], '').strip()
            fetched_at = (payload.get('cache') or {}).get('fetched_at') or row['retrieved_at']
            metadata = await seed_history(payload['domain'], provider, key,
                                          fetched_at=fetched_at, payload=payload)
        except (KeyError, TypeError, ValueError):
            metadata = None
        if metadata:
            imported.append({'domain': payload['domain'], 'records_count': payload['records_count'],
                             'fetched_at': metadata['fetched_at']})
        else:
            skipped += 1
    print(json.dumps({'imported': imported, 'skipped': skipped, 'paid_requests': 0}, ensure_ascii=False))


if __name__ == '__main__':
    asyncio.run(main())
