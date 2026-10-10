"""Ограниченный поиск связей с РФ: публичные страницы, без догадок о гражданстве."""
from __future__ import annotations
import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urljoin
import httpx
from bs4 import BeautifulSoup

# Читаем только известные публичные реестры/справочники и публичные профили.
HOSTS = ('nalog.gov.ru', 'checko.ru', 'rusprofile.ru', 'list-org.com',
         'orginfo.uz', 'ihamkor.uz', 'myorg.uz', 'i2b-centre.ru',
         'opensanctions.org', 'linkedin.com')
RU = re.compile(r'\b(?:россия|российская федерация|russia|russian federation|ru|рф)\b', re.I)


def norm(s):
    return ' '.join(re.findall(r'\w+', str(s).casefold()))


def company_key(s):
    return ' '.join(w for w in norm(s).split() if w not in
                    {'ооо', 'оао', 'пао', 'ао', 'llc', 'ltd', 'inc', 'mchj', 'sa', 'the'})


def readable_url(url):
    try:
        p = urlsplit(url)
        host = (p.hostname or '').lower()
        return (p.scheme == 'https' and not p.username and not p.password
                and p.port in (None, 443)
                and any(host == h or host.endswith('.' + h) for h in HOSTS))
    except (TypeError, ValueError):
        return False


def queries(company, tax_id, people):
    name = company_key(company).replace('"', '')[:120]
    quoted = '"' + name + '"'
    out = [('company', quoted + ' site:i2b-centre.ru'),
           ('company', quoted + ' (Россия OR Russia) (поставщик OR партнер OR owner OR subsidiary)'),
           ('company', quoted + ' (учредитель OR владелец OR shareholder)'),
           ('registry', quoted + ' (site:egrul.nalog.ru OR site:pb.nalog.ru OR site:checko.ru OR site:rusprofile.ru)'),
           ('linkedin', 'site:linkedin.com/in/ ' + quoted)]
    if tax_id:
        out.append(('company', '"' + tax_id + '" (Россия OR Russia OR поставщик)'))
    for p in people[:3]:
        who = '"' + p['name'].replace('"', '')[:120] + '"'
        out += [('registry', who + ' (ЕГРЮЛ OR ЕГРИП OR учредитель OR ИП)'),
                ('linkedin', 'site:linkedin.com/in/ ' + who + ' (experience OR опыт OR ' + name + ')'),
                ('citizenship', who + ' (гражданство OR citizenship OR nationality)')]
    return out


def parse_page(html, url, company, tax_id):
    soup = BeautifulSoup(html, 'html.parser')
    for node in soup.select('script, style, nav, footer, form, noscript'):
        node.decompose()
    text = soup.get_text(' ', strip=True)
    key = company_key(company)
    name_match = bool(key and re.search(r'(?<!\w)' + re.escape(key) + r'(?!\w)', norm(text)))
    id_match = bool(tax_id and re.search(r'(?<!\d)' + re.escape(tax_id) + r'(?!\d)', text))
    matched = name_match and (id_match if tax_id else True)
    relations = []
    # Только явные строки таблиц отношений с отдельной колонкой страны.
    # Присутствие "Россия" в подвале страницы не является связью.
    if matched:
        for table in soup.find_all('table'):
            rows = table.find_all('tr')
            if not rows:
                continue
            # Перед шапкой бывает объединённая строка с названием раздела.
            header_index = None
            for i, row in enumerate(rows[:5]):
                headers = [norm(c.get_text(' ', strip=True)) for c in row.find_all(['th', 'td'])]
                def column(words):
                    return next((j for j,h in enumerate(headers) if any(w in h for w in words)), None)
                ni = column(('название компании', 'company name', 'контрагент'))
                ci = column(('страна', 'country', 'местонахождение', 'место жительства'))
                ri = column(('тип', 'отношение', 'relationship'))
                di = column(('дата', 'date'))
                if None not in (ni, ci, ri) and len({ni, ci, ri}) == 3:
                    header_index = i
                    break
            if header_index is None:
                continue
            for row in rows[header_index + 1:]:
                cells = [c.get_text(' ', strip=True) for c in row.find_all(['td','th'])]
                if len(cells) <= max(ni,ci,ri) or not RU.fullmatch(cells[ci].strip()):
                    continue
                if not re.search(r'поставщик|клиент|владелец|учредитель|дочерн|материн|supplier|customer|owner|parent|subsidiary', cells[ri], re.I):
                    continue
                relations.append({'entity':cells[ni][:200], 'relation':cells[ri][:80],
                    'country':cells[ci], 'date':cells[di] if di is not None and di < len(cells) else '',
                    'quote':' | '.join(cells)[:800], 'url':url,
                    'status':'source_reported' if id_match else 'candidate',
                    'identity_basis':'name_and_tax_id' if id_match else 'name_only'})
    return {'url':url, 'text':text[:8000], 'matched_company':matched,
            'relations':relations[:20], 'source_kind':'public_page',
            'retrieved_at':datetime.now(timezone.utc).isoformat()}


async def read_page(client, url, company, tax_id):
    # Редиректы перепроверяются, приватные адреса DNS не запрашиваются.
    for _ in range(3):
        if not readable_url(url):
            raise ValueError('URL вне списка публичных источников')
        host = urlsplit(url).hostname
        addresses = await asyncio.get_running_loop().getaddrinfo(host,443,type=__import__('socket').SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError('непубличный сетевой адрес')
        async with client.stream('GET',url) as response:
            if response.is_redirect:
                url = urljoin(url,response.headers.get('location',''))
                continue
            response.raise_for_status()
            if 'html' not in response.headers.get('content-type',''):
                raise ValueError('страница не HTML')
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body)>2_000_000:
                    raise ValueError('страница больше 2 MB')
            return parse_page(bytes(body).decode(response.encoding or 'utf-8',errors='replace'),url,company,tax_id)
    raise ValueError('слишком много перенаправлений')


async def collect(company, tax_id, people, search):
    people = [p for p in people if isinstance(p,dict) and isinstance(p.get('name'),str) and p['name'].strip()][:3]
    jobs = queries(company,tax_id,people)
    searches, hits, pages, failures = [], [], [], []
    sem = asyncio.Semaphore(3)
    async def lookup(kind,q):
        async with sem:
            try:
                data=json.loads(await asyncio.wait_for(search(q,num=5),timeout=25))
                if data.get('error'):
                    raise ValueError('поиск недоступен')
                searches.append({'kind':kind,'query':q,'count':len(data.get('results') or [])})
                for hit in data.get('results') or []:
                    url=hit.get('link') or ''
                    if url.startswith('https://'):
                        hits.append({'kind':kind,'query':q,'url':url,
                                     'title':hit.get('title') or '', 'snippet':hit.get('snippet') or '',
                                     'status':'search_lead'})
            except Exception as exc:
                failures.append({'source':q,'reason':type(exc).__name__})
    tasks={asyncio.create_task(lookup(k,q)):q for k,q in jobs}
    done,pending=await asyncio.wait(tasks,timeout=75)
    for task in pending:
        failures.append({'source':tasks[task],'reason':'search_budget_exceeded'})
        task.cancel()
    await asyncio.gather(*tasks,return_exceptions=True)
    # Порядок стабилен: отношения компании, реестры, профили; не зависит от сети.
    order={q:i for i,(_,q) in enumerate(jobs)}
    hits.sort(key=lambda h:(order[h['query']],h['url']))
    seen=set()
    hits=[h for h in hits if not (h['url'] in seen or seen.add(h['url']))]
    eligible=[h for h in hits if readable_url(h['url'])]
    # Даём каждой категории минимум один слот; остальные — компании и реестрам.
    selected=[]
    for kind in ('company','registry','linkedin','citizenship'):
        item=next((h for h in eligible if h['kind']==kind),None)
        if item: selected.append(item)
    selected += [h for h in eligible if h not in selected]
    async with httpx.AsyncClient(timeout=15,follow_redirects=False,
            headers={'User-Agent':'OSINT-MCP public corporate research/1.0'}) as client:
        async def fetch(hit):
            async with sem:
                try:
                    page=await asyncio.wait_for(read_page(client,hit['url'],company,tax_id),timeout=18)
                    page['kind']=hit['kind']; pages.append(page)
                except Exception as exc:
                    status=exc.response.status_code if isinstance(exc,httpx.HTTPStatusError) else None
                    failures.append({'source':hit['url'],'reason':f'HTTP {status}' if status else type(exc).__name__})
        await asyncio.gather(*(fetch(h) for h in selected[:6]))
    pages.sort(key=lambda p:p['url'])
    return {'company':company,'tax_id':tax_id,'people':people,'searches':searches,
            'hits':hits[:30],'pages':pages,'failures':failures,
            'relations':[r for p in pages for r in p['relations']],
            'retrieved_at':datetime.now(timezone.utc).isoformat(),
            'scope':'Целевой публичный поиск, до 3 лиц и 6 прочитанных страниц. '
                    'Поисковые совпадения не подтверждают личность, гражданство или отношения. '
                    'Полные выписки ЕГРЮЛ/ЕГРИП и полная история LinkedIn не гарантируются.'}
