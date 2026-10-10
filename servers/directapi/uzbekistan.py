"""Публичные справочники Узбекистана: точные реквизиты, даты и расхождения.
Поисковые фрагменты используются только для обнаружения карточек.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import re
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

PATHS = {'orginfo.uz': r'/ru/organization/[a-zA-Z0-9]+/?',
         'ihamkor.uz': r'/ru/subject/[a-zA-Z0-9]+/?',
         'myorg.uz': r'/ru/company/uz/\d+/?'}


def allowed(url: str) -> bool:
    u = urlparse(url)
    return (u.scheme == 'https' and u.netloc in PATHS
            and bool(re.fullmatch(PATHS[u.netloc], u.path)))


def canonical_url(url: str) -> str:
    """Поиск может вернуть английскую/узбекскую версию; парсер читает русскую."""
    u = urlparse(url)
    if u.scheme != 'https' or u.netloc not in PATHS:
        return ''
    path = re.sub(r'^/(?:en|uz)/', '/ru/', u.path)
    result = 'https://' + u.netloc + path
    return result if allowed(result) else ''


def norm(name: str) -> str:
    name = (name or '').lower().replace(chr(96), "'").replace('’', "'")
    name = re.sub(r"mas['‘]?uliyati\s+cheklangan\s+jamiyat[i]?", ' ', name)
    name = re.sub(r'общество\s+с\s+ограниченной\s+ответственностью', ' ', name)
    return ' '.join(w for w in re.findall(r'\w+', name)
                    if w not in {'ооо', 'ooo', 'mchj', 'llc'})


LABELS = {
    'name': ('Официальное название организации', 'Полное наименование'),
    'short_name': ('Краткое название организации',),
    'tax_id': ('ИНН', 'STIR'),
    'registration_number': ('Регистрационный номер', 'Номер регистрации'),
    'registered': ('Дата регистрации',), 'status': ('Статус', 'Состояние'),
    'address': ('Юридический адрес', 'Адрес'), 'director': ('Руководитель',),
    'activity': ('ОКЭД', 'Отрасль (ОКЭД)'),
    'capital': ('Уставный фонд', 'Размер уставного фонда'),
}
ALL_LABELS = {v.lower() for vals in LABELS.values() for v in vals}


def parse_card(html: str, url: str) -> dict | None:
    if not allowed(url):
        return None
    soup = BeautifulSoup(html, 'html.parser')
    for node in soup(['script', 'style', 'nav', 'footer']):
        node.decompose()
    text = soup.get_text('\n', strip=True)
    if urlparse(url).hostname == 'orginfo.uz':
        start = text.find('Официальное название организации')
        if start < 0:
            return None
        text = text[start:].split('Похожие организации')[0]
    lines = [' '.join(x.split()) for x in text.splitlines() if x.strip()]

    def field(key):
        for label in LABELS[key]:
            for i, line in enumerate(lines[:-1]):
                if line.rstrip(':').lower() == label.lower():
                    value = lines[i + 1]
                    if value.rstrip(':').lower() not in ALL_LABELS and value not in ('Нет данных', '░░░'):
                        return value
        return None

    card = {key: field(key) for key in LABELS}
    if not card['name'] or not re.fullmatch(r'\d{9}', card['tax_id'] or ''):
        return None
    if card.get('activity') and card['activity'].endswith('-'):
        i = lines.index(card['activity'])
        if i + 1 < len(lines) and lines[i + 1].rstrip(':').lower() not in ALL_LABELS:
            card['activity'] += ' ' + lines[i + 1]
    if card['address']:
        index = lines.index(card['address'])
        if index + 1 < len(lines) and re.search(r'\b(?:MFY|UY|KO.CHASI|улиц|дом)', lines[index + 1], re.I):
            card['address'] += ', ' + lines[index + 1]
    founders = []
    for i, line in enumerate(lines):
        if line.rstrip(':') != 'Учредители':
            continue
        for j in range(i + 1, min(i + 30, len(lines))):
            if lines[j] in ('Внимание', 'Регистрационные данные', 'Контактные данные'):
                break
            if re.fullmatch(r'\d+(?:[.,]\d+)?\s*%', lines[j]) and j > i + 1:
                name = lines[j - 1]
                if name == 'Физическое лицо' and j > i + 2:
                    name = lines[j - 2]
                share = float(lines[j].rstrip('% ').replace(',', '.'))
                if 0 < share <= 100:
                    founders.append({'name': name, 'share_percent': share})
        break
    card.update(founders=founders, source_url=url, source_kind='commercial_directory',
                retrieved_at=datetime.now(timezone.utc).isoformat(),
                source_dates=list(dict.fromkeys(re.findall(
                    r'(?:актуальна на|Обновлено:|Последнее обновление:)\s*(\d{2}\.\d{2}\.\d{4})', text))),
                evidence_text=text[:18000])
    return card


def reconcile(cards: list[dict], query: str, tax_id: str = '') -> dict:
    matched = [c for c in cards if (c['tax_id'] == tax_id if tax_id else
               norm(query) in {norm(c['name']), norm(c.get('short_name'))})]
    ids = {c['tax_id'] for c in matched}
    out = {'jurisdiction': 'UZ', 'records': matched, 'query': query,
           'source_kind': 'commercial_directory', 'official_registry_verified': False}
    if len(ids) != 1:
        return {**out, 'matched': False, 'reason': 'Нет единственной карточки с точным совпадением имени/ИНН'}
    conflicts, fields = {}, {}
    for key in ('registration_number', 'registered', 'status', 'address', 'director', 'activity', 'capital', 'founders'):
        vals = []
        for c in matched:
            if c.get(key) and c[key] not in vals:
                vals.append(c[key])
        if len(vals) == 1:
            fields[key] = vals[0]
        elif len(vals) > 1:
            conflicts[key] = vals
    return {**out, **fields, 'matched': True, 'tax_id': next(iter(ids)),
            'name': matched[0].get('short_name') or matched[0]['name'],
            'conflicts': conflicts,
            'scope': 'Публичные справочники; их первичные данные могут совпадать. '
                     'Не заменяет свежую государственную выписку. Даты указаны для каждой карточки.'}


async def collect(query: str, search, tax_id: str = '') -> dict:
    if tax_id and not re.fullmatch(r'\d{9}', tax_id):
        return {'error': 'Узбекский ИНН/STIR должен содержать 9 цифр'}
    search_queries = [(tax_id or norm(query)) + ' site:' + host for host in PATHS]
    async def discover(q):
        try:
            return json.loads(await search(q, num=3))
        except Exception as exc:
            return {"error": type(exc).__name__}
    responses = await asyncio.gather(*(discover(q) for q in search_queries))
    urls = list(dict.fromkeys(canonical_url(r.get('link') or '') for response in responses
                             for r in response.get('results', [])
                             if canonical_url(r.get('link') or '')))[:5]
    failures = [{'url': 'https://' + host, 'reason': 'Поиск не обнаружил доступную карточку'}
                for host in PATHS if not any(urlparse(u).netloc == host for u in urls)]
    cards = []
    async with httpx.AsyncClient(timeout=18, follow_redirects=False) as client:
        async def fetch(url):
            try:
                async with client.stream('GET', url) as r:
                    r.raise_for_status()
                    chunks, size = [], 0
                    async for chunk in r.aiter_bytes():
                        size += len(chunk)
                        if size > 2_000_000:
                            raise ValueError('Слишком большая страница')
                        chunks.append(chunk)
                card = parse_card(b''.join(chunks).decode('utf-8', errors='replace'), url)
                if card:
                    cards.append(card)
                else:
                    failures.append({'url': url, 'reason': 'Карточка не распознана; фрагмент поиска не используется как реквизиты'})
            except Exception as exc:
                failures.append({'url': url, 'reason': ('HTTP ' + str(exc.response.status_code))
                                 if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__})
        await asyncio.gather(*(fetch(url) for url in urls))
    cards.sort(key=lambda c: c['source_url'])
    return {**reconcile(cards, query, tax_id), 'search_queries': search_queries,
            'failures': failures, 'search_errors': [r['error'] for r in responses if r.get('error')]}
