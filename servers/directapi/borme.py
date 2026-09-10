"""BORME: поиск официальных бюллетеней BOE и точный отбор актов компании."""
import asyncio
import json
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup


def norm(s):
    s = ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))
    return re.sub(r'[^A-Z0-9]', '', s.upper())


def parse(html, query, url):
    soup = BeautifulSoup(html, 'html.parser')
    records, people = [], []
    for h in soup.find_all(re.compile('^h[3-6]$')):
        title = h.get_text(' ', strip=True)
        m = re.match(r'(\d+)\s*-\s*(.+)', title)
        if not m or norm(m.group(2)) != norm(query):
            continue
        body = []
        for e in h.next_siblings:
            if getattr(e, 'name', '') in ('h3', 'h4', 'h5', 'h6'):
                break
            if hasattr(e, 'get_text'):
                body.append(e.get_text(' ', strip=True))
        text = ' '.join(body)
        if not text:
            continue
        date = re.search(r'\(\s*(\d{1,2}\.\d{1,2}\.\d{2,4})\)', text)
        record = dict(number=m.group(1), company=m.group(2), text=text[:3500],
                      registry_date=date.group(1) if date else None, url=url)
        records.append(record)
        # Не смешиваем назначения и прекращение полномочий; это события, не текущий штат.
        chunks = re.split(r'(Nombramientos\.|Revocaciones\.|Ceses/Dimisiones\.|Reelecciones\.)', text)
        for i in range(1, len(chunks), 2):
            event = chunks[i].rstrip('.')
            block = re.split(r'Datos registrales\.|Otros conceptos\.', chunks[i+1])[0]
            roles = list(re.finditer(r'([A-Za-zÁÉÍÓÚÑáéíóúñ][A-Za-zÁÉÍÓÚÑáéíóúñ./ ]{0,35}):', block))
            for k, match in enumerate(roles):
                role = match.group(1).strip()
                names = block[match.end():roles[k+1].start() if k+1 < len(roles) else len(block)]
                for name in names.split(';'):
                    name = ' '.join(name.split()).strip(' .')
                    if 3 < len(name) < 120:
                        people.append(dict(name=name, role=role, event=event,
                                           date=record['registry_date'], url=url, act=record['number']))
    return records, people


async def collect(query, search):
    query = re.sub(r"[,.]", "", query).strip()
    year = datetime.now(timezone.utc).year
    searches = await asyncio.gather(*(
        search(f'site:boe.es "{query}" {year} {term}', num=8)
        for term in ('Nombramientos', 'Apoderado')))
    urls = []
    for raw in searches:
        for hit in json.loads(raw).get('results', []):
            u = hit.get('link') or ''
            if (urlsplit(u).hostname or '').removeprefix('www.') != 'boe.es':
                continue
            doc = re.search(r'BORME-A-\d{4}-\d+-\d+', u)
            if doc:
                url = 'https://www.boe.es/diario_borme/txt.php?id=' + doc.group(0)
                if url not in urls:
                    urls.append(url)
    records, people, failures = [], [], []
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=18, follow_redirects=True) as client:
        async def fetch(url):
            async with sem:
                try:
                    for attempt in range(3):
                        try:
                            r = await client.get(url); r.raise_for_status()
                            break
                        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
                            if attempt == 2:
                                raise
                            await asyncio.sleep(0.7 * (attempt + 1))
                    rr, pp = parse(r.text, query, url)
                    records.extend(rr); people.extend(pp)
                except Exception as e:
                    failures.append({'url': url, 'reason': type(e).__name__})
        await asyncio.gather(*(fetch(u) for u in urls[:8]))
    return {'name': query, 'source': 'BOE / BORME (официальные публикации)',
            'url': 'https://www.boe.es/diario_borme/', 'announcements': records,
            'officer_events': people[:160], 'num_announcements': len(records),
            'retrieved_at': datetime.now(timezone.utc).isoformat(), 'failures': failures,
            'documents_read': len(urls[:8])-len(failures),
            'scope': 'выборка найденных бюллетеней, не полный реестр и не список действующих полномочий'}
