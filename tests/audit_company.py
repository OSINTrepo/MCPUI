#!/usr/bin/env python3
"""Сравнение двух прогонов компании по сохранённым данным, не процент полноты OSINT."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def inspect(folder):
    record = json.loads((folder / 'evidence.json').read_text())
    path = next(folder.glob('soberi*.md'))
    body = path.read_text().split('## Приложение:')[0]
    results = record['results']
    official, borme, financials = {}, {}, {}
    for r in results:
        if not r.get('ok'):
            continue
        try:
            data = json.loads(r.get('text', ''))
        except (ValueError, TypeError):
            continue
        if r.get('tool') == 'corporate_website':
            official = data
        elif r.get('tool') == 'borme_publications':
            borme = data
        elif r.get('tool') == 'sec_financials' and data.get('metrics'):
            financials = {'source': 'SEC', 'currency': data.get('currency'), 'periods': data.get('years'),
                          'metrics': list(data.get('metrics', {}))}
        elif r.get('tool') == 'get_finances' and data.get('company'):
            financials = {'source': 'Checko', 'scope': 'РСБУ отдельного юридического лица',
                          'periods': sorted(data.get('data', {}))[-5:],
                          'inn': data['company'].get('ИНН')}
    groups = Counter(p['group'] for p in official.get('people', []))
    counts = {}
    for name, pattern in {
        'subdomains': r'^## Поддомены — (\d+)',
        'ips': r'^## IP-адреса и сети .*? — (\d+)',
        'certificates': r'^## SSL-сертификаты — (\d+)',
        'hosts_with_ip': r'^## Поддомены → IP \((\d+)\)',
    }.items():
        match = re.search(pattern, body, re.M)
        counts[name] = int(match.group(1)) if match else None
    return dict(
        report=str(path), when=record['when'],
        identity={k: (record.get('identity') or {}).get(k) for k in
                  ('legal_name', 'jurisdiction', 'confidence', 'inn', 'ogrn', 'cik', 'tickers')},
        financials=financials,
        calls=len(results), successful_calls=sum(bool(r.get('ok')) for r in results),
        failed_calls=[{'server': r['server'], 'tool': r.get('tool')} for r in results if not r.get('ok')],
        tables=len(re.findall(r'^\*\*Таблица \d+\.', body, re.M)),
        sections=re.findall(r'^## (.+)', body, re.M),
        official_pages=[{'category': p['category'], 'url': p['url'], 'truncated': p.get('truncated', False)}
                        for p in official.get('pages', [])],
        governance_profiles=dict(groups),
        projects=[p['title'] for p in official.get('projects', [])],
        linked_publications=len(official.get('publications', [])),
        borme_announcements=len(borme.get('announcements', [])),
        borme_events=len(borme.get('officer_events', [])),
        borme_scope=borme.get('scope'),
        counts=counts,
        caution='Числа описывают собранную выборку; это не процент всех доступных данных и не проверка всех утверждений LLM.',
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('baseline', type=Path)
    parser.add_argument('final', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = {k: inspect(getattr(args, k)) for k in ('baseline', 'final')}
    args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    for label, report in data.items():
        print(label, json.dumps({k: report[k] for k in ('calls', 'successful_calls', 'tables',
              'governance_profiles', 'projects', 'linked_publications', 'borme_announcements',
              'borme_events', 'counts')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
