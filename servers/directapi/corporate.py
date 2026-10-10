"""Обнаружение публичных корпоративных страниц; факты с URL и временем чтения."""
from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup, NavigableString

CATEGORIES = {
    'legal': ('informacion-legal', 'aviso-legal', 'legal-notice', 'imprint', 'requisites', 'rekvizity', 'contacts', 'yhteystiedot', 'yhteys', 'tietosuoja'),
    'governance': ('organos-gobierno', 'board-of-directors', 'consejo-de-administracion', 'board-members', 'management-board', 'leadership', 'corporate-governance', 'hallitus', 'our-team', '/team', 'tiimi', 'komanda', 'redaktsiya'),
    'executive': ('executive-team', 'executive-committee', 'equipo-directivo', 'equipo-ejecutivo', 'comite-de-direccion', 'management-board', 'executive-officers', 'senior-leadership', 'pravlenie'),
    'business': ('nuestros-negocios', 'our-business', 'business-areas', 'our-group', 'nuestro-grupo', 'what-we-do', 'main-data', 'principales-datos', 'about-company', 'about-us'),
    'locations': ('donde-estamos', 'where-we-are', 'locations', 'offices', 'global-presence', 'worldwide'),
    'financial': ('resultados', 'results', 'main-figures', 'informe-publico-trimestral', 'annual-report', 'informe-anual', 'quarterly-reports', 'financial-reports', 'results-and-reports'),
    'annual': ('annual-report', 'annualreports', '/reports/ar', 'informe-anual'),
    'ownership': ('estructura-accionarial', 'shareholding', 'shareholder-structure', 'participaciones-significativas', 'share-capital', 'ownership-structure'),
    'projects': ('innovation-projects', 'proyectos-innovacion', 'research-projects'),
}
GROUP = re.compile(r'^(?:Consejo de Administraci[oó]n|Comisi[oó]n .+|Comit[eé] de Direcci[oó]n|'
                   r'(?:.*\s)?Board of Directors|Board Members|Executive Team|Equipo Ejecutivo|Executive Committee|Management Board|Совет директоров|Правление|Hallitus|Tiimi|(?:Our )?Team|Команда|Редакция|Руководство|.+ Committee)$', re.I)
ROLE = re.compile(r'^(?:president[ea]?|chair(?:man|woman)?|vicepresident.+|consejer[oa] delegado|'
                  r'vocales|secretari[oa].*|vicesecretari[oa].*|responsables .+|CEO|CFO)$', re.I)


def clean_url(url: str) -> str | None:
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        return None
    host = p.hostname.lower()
    if '.' not in host or host.endswith(('.local', '.internal', '.localhost')):
        return None
    try:
        if not ipaddress.ip_address(host).is_global:
            return None
    except ValueError:
        pass
    return urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))


def parse_page(html: str, url: str, category: str) -> dict:
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for a in soup.find_all(href=True):
        u = clean_url(urljoin(url, a['href']))
        label = ' '.join(a.get_text(' ', strip=True).split())
        if u and (u, label) not in links:
            links.append((u, label))
    # Публичные Vue-компоненты могут хранить ссылки и содержимое в атрибутах.
    # Значения читаются как данные: JavaScript не исполняется.
    for node in soup.find_all(True):
        for key, value in node.attrs.items():
            if key.startswith(':') and isinstance(value, str):
                for ref in re.findall(r"(?:link|href|url)\s*:\s*['\"]([^'\"]+)['\"]", value):
                    u = clean_url(urljoin(url, ref))
                    if u and (u, '') not in links:
                        links.append((u, ''))
    title = soup.title.get_text(' ', strip=True) if soup.title else url
    # Реквизиты небольших организаций часто опубликованы только в footer.
    # Шаблонный подвал исключаем, но явно помеченные юридические/деловые
    # сведения сохраняем для извлечения фактов с исходным URL.
    legal_footers = []
    legal_marker = re.compile(r'Y[- ]?tunnus|Business\s+ID|\b(?:VAT|CIF|NIF|ИНН|ОГРН)\b|'
                              r'\b\d{7}-\d\b|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', re.I)
    for footer in soup.find_all('footer'):
        footer_text = footer.get_text('\n', strip=True)
        if legal_marker.search(footer_text):
            legal_footers.append(footer_text[:4000])
    for node in soup.select('script, style, svg, nav, footer, form, noscript'):
        node.decompose()
    # Заголовок статьи внутри main — данные; удаляем только общую шапку сайта.
    for node in soup.find_all('header'):
        if node.find_parent(['main', 'article']) is None:
            node.decompose()
    root = soup.find('main') or soup.body or soup
    heading = root.find('h1')
    started = heading is None
    lines = []
    for node in root.descendants:
        if node is heading:
            started = True
        if started and isinstance(node, NavigableString):
            value = ' '.join(str(node).split())
            if value:
                lines.append(value)
    for node in root.find_all(True):
        for key, value in node.attrs.items():
            if (key.startswith(':') and isinstance(value, str) and len(value) > 30
                    and value.lstrip().startswith(('[', '{'))):
                lines.append(value)
    people = []
    group, role = '', ''
    for h in root.find_all(re.compile('^h[1-6]$')):
        label = h.get_text(' ', strip=True)
        if h.name in ('h1', 'h2') and GROUP.match(label):
            group, role = label, ''
        elif ROLE.match(label):
            role = label
        elif h.name in ('h1', 'h2'):
            group, role = '', ''
        elif group and h.name == 'h3' and 1 < len(label.split()) < 8:
            if any(x in label.lower() for x in ('reglamento', 'conoce', 'transparencia', 'negocios')):
                group = ''
                continue
            tail = []
            for e in h.next_elements:
                if getattr(e, 'name', '') in ('h1','h2','h3','h4','h5','h6'):
                    break
                if isinstance(e, NavigableString) and not h in e.parents:
                    val = ' '.join(str(e).split())
                    if val and val not in ('Ver Curriculum', 'View CV'):
                        tail.append(val)
            detail = ' '.join(tail)[:500]
            date = re.search(r'(?:[Úú]ltimo nombramiento|Appointed)\s*:?\s*(.+)', detail)
            position = re.split(r'[Úú]ltimo nombramiento|Appointed', detail)[0].strip()
            people.append(dict(name=label, group=group, role=position or role or 'Vocal',
                               appointed=date.group(1) if date else None, source_url=url))
    # Карточки руководителей часто используют span/p вместо h3. Берём только
    # явную пару имя + должность на странице органа управления, без догадок по тексту.
    if category in ('governance', 'executive'):
        page_group = next((h.get_text(' ', strip=True) for h in root.find_all(['h1', 'h2'])
                           if GROUP.fullmatch(h.get_text(' ', strip=True))), '')
        if page_group:
            for name_node in root.select('.profile-box__name'):
                card = name_node.find_parent(class_='profile-box__head') or name_node.parent
                role_node = card.select_one('.profile-box__role')
                if role_node is None:
                    continue
                name = re.sub(r'^(?:Mr\.|Mrs\.|Ms\.|D\.|Dña\.)\s+', '',
                              name_node.get_text(' ', strip=True)).strip()
                detail = role_node.get_text(' ', strip=True)
                appointed = re.search(r'(?:Last appointment|Último nombramiento)\s*:\s*([\d./-]+)', detail, re.I)
                position = re.split(r'(?:First|Last) appointment|(?:Primer|Último) nombramiento',
                                    detail, flags=re.I)[0].strip()
                if name and position and not any(p['name'] == name and p['group'] == page_group for p in people):
                    people.append(dict(name=name, group=page_group, role=position,
                                       appointed=appointed.group(1) if appointed else None, source_url=url))
    text = "\n".join(lines)
    if legal_footers:
        text += '\n\n' + '\n'.join(legal_footers)
    businesses, projects, metrics = [], [], []
    start = next((i for i, line in enumerate(lines) if line.lower() in ("negocios", "our businesses", "our business")), None)
    if start is not None:
        for i in range(start + 1, len(lines) - 1):
            if lines[i].lower() in ("actualidad", "latest news", "news"):
                break
            if len(lines[i]) < 50 and len(lines[i + 1]) > 65:
                businesses.append({"name": lines[i], "description": lines[i + 1], "url": url})
    if category == "projects":
        projects = [{"title": line, "url": url} for line in lines
                    if ":" in line and 2 < len(line.split(":")[0]) < 30 and len(line) > 30]
    flat = " ".join(lines)
    revenue = re.search(r"(?:Ventas|Revenues?|Sales)\s+(20\d{2})\s+([\d.,]+)\s*M€", flat)
    if revenue:
        raw = revenue.group(2)
        millions = raw.replace(".", "").replace(",", ".") if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", raw) else raw.replace(",", "")
        try:
            value = float(millions) * 1_000_000
            metrics.append({"label": "Выручка / продажи", "year": revenue.group(1),
                            "value": value, "unit": "EUR", "source_value": revenue.group(0), "url": url})
        except ValueError:
            pass
    staff = re.search(r"(?:Profesionales|Professionals|Employees)\s+(20\d{2})\s*(>?)\s*([\d.,]+)", flat)
    if staff:
        metrics.append({"label": "Сотрудники", "year": staff.group(1), "operator": staff.group(2),
                        "value": int(re.sub(r"[.,]", "", staff.group(3))), "unit": "человек",
                        "source_value": staff.group(0), "url": url})
    countries = re.search(r"Presencia\s+comercial\s*(>?)\s*(\d+)\s*países", flat)
    if countries:
        metrics.append({"label": "Коммерческое присутствие", "year": "", "operator": countries.group(1),
                        "value": int(countries.group(2)), "unit": "стран",
                        "source_value": countries.group(0), "url": url})
    return dict(url=url, category=category, title=title, text=text, links=links, people=people,
                businesses=businesses, projects=projects, metrics=metrics)


def annual_document_year(url: str, label: str = "") -> int | None:
    """Год конкретного HTML-отчёта; общий индекс без года не считается документом."""
    path = urlsplit(url).path.lower()
    text = path + " " + label.lower()
    if not any(t in text for t in ("annual", "informe-anual", "годов", "/reports/ar")):
        return None
    years = re.findall(r"(?<!\d)(20\d{2})(?!\d)", text)
    if years:
        return max(map(int, years))
    short = re.search(r"/reports/ar(\d{2})(?:/|$)", path)
    return 2000 + int(short[1]) if short else None


async def collect(domain: str, query: str, search=None) -> dict:
    url = clean_url('https://' + domain.strip().lower().removeprefix('https://').rstrip('/'))
    if not url:
        return {'error': 'нужен публичный домен компании'}
    errors, pages, seen = [], [], set()
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=18, follow_redirects=True, max_redirects=5,
                                 headers={'User-Agent': 'OSINT-MCP-UI corporate research/1.0', 'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8'}) as client:
        async def fetch_once(u, cat):
            async with sem:
                try:
                    async with client.stream('GET', u) as r:
                        r.raise_for_status()
                        if 'html' not in r.headers.get('content-type', ''):
                            return None
                        chunks, length = [], 0
                        async for chunk in r.aiter_bytes():
                            chunks.append(chunk); length += len(chunk)
                            if length > 2_000_000:
                                raise ValueError('страница больше 2 MB')
                        page = parse_page(b''.join(chunks).decode('utf-8', 'replace'), str(r.url), cat)
                        page['retrieved_at'] = datetime.now(timezone.utc).isoformat()
                        return page
                except Exception as e:
                    errors.append({'url': u, 'reason': type(e).__name__})
                    return None
        async def fetch(u, cat):
            for attempt in range(3):
                page = await fetch_once(u, cat)
                if page:
                    errors[:] = [e for e in errors if e["url"] != u]
                    return page
                error = next((e for e in reversed(errors) if e["url"] == u), {})
                if error.get("reason") not in ("ConnectError", "ConnectTimeout", "ReadTimeout", "RemoteProtocolError"):
                    break
                await asyncio.sleep(0.7 * (attempt + 1))
            return None
        home = await fetch(url, 'overview')
        if not home:
            return {'error': 'корпоративный сайт недоступен', 'failures': errors}
        pages.append(home); seen.add(home['url'])
        root_host = urlsplit(home['url']).hostname.removeprefix('www.')
        def official(u):
            h = urlsplit(u).hostname or ''
            return h == root_host or h.endswith('.' + root_host)
        selected = {}
        for cat, terms in CATEGORIES.items():
            candidates = [(u, label) for u, label in home['links']
                          if official(u) and u not in seen and any(t in u.lower() for t in terms)
                          and not urlsplit(u).path.lower().endswith('.pdf')]
            if candidates:
                # Сначала профильный раздел; короткий URL блога не должен обгонять совет директоров.
                u, _ = min(candidates, key=lambda x: (
                    bool(re.search(r'/(?:tag|blog|noticias|news|press-room)/', x[0])),
                    next(i for i, term in enumerate(terms) if term in x[0].lower()), len(x[0])))
                selected[cat] = u; seen.add(u)
        if search:
            missing = [c for c in CATEGORIES if c not in selected]
            async def discover(cat):
                try:
                    import json
                    keywords = {'legal': 'contacts legal реквизиты', 'governance': 'board of directors совет директоров',
                                'executive': 'executive руководство', 'financial': 'financial results отчетность',
                                'annual': 'annual report годовой отчет'}.get(cat, cat)
                    result = json.loads(await search(f'site:{root_host} {query} {keywords}', num=5))
                    for hit in result.get('results', []):
                        u = clean_url(hit.get('link') or '')
                        if (u and official(u) and u not in seen
                                and not urlsplit(u).path.endswith('.pdf')
                                and any(term in u.lower() for term in CATEGORIES[cat])):
                            selected[cat] = u; seen.add(u); break
                except Exception:
                    pass
            await asyncio.gather(*(discover(c) for c in missing))
        fetched = await asyncio.gather(*(fetch(u, c) for c, u in selected.items()))
        pages += [p for p in fetched if p and len(p['text']) > 80]
        # Обзор управления часто ведёт на отдельную страницу состава совета.
        # Один дополнительный переход, только внутри официального домена.
        follow = {}
        for page in pages:
            if page['category'] not in ('governance', 'executive'):
                continue
            for u, _ in page['links']:
                if (official(u) and u not in seen and not urlsplit(u).path.lower().endswith('.pdf')
                        and any(t in u.lower() for t in ('board-of-directors', 'board-members',
                                                         'executive-officers', 'senior-leadership'))):
                    cat = 'executive' if any(t in u.lower() for t in ('executive-officers', 'senior-leadership')) else 'governance'
                    if cat not in follow:
                        follow[cat] = u
                        seen.add(u)
        # Индекс годовых отчётов часто находится на первом переходе.
        # Читаем один самый новый HTML-документ, не только список ссылок.
        have_annual = any(p['category'] in ('annual', 'financial')
                          and annual_document_year(p['url'], p['title']) for p in pages)
        if not have_annual:
            documents = []
            for page in pages:
                if page['category'] not in ('annual', 'financial'):
                    continue
                for u, label in page['links']:
                    year = annual_document_year(u, label)
                    if (year and official(u) and u not in seen
                            and not urlsplit(u).path.lower().endswith('.pdf')):
                        documents.append((year, u))
            if documents:
                _, u = max(documents, key=lambda item: (item[0], -len(item[1])))
                follow['annual'] = u
                seen.add(u)
        extra = await asyncio.gather(*(fetch(u, c) for c, u in follow.items()))
        pages += [p for p in extra if p and len(p['text']) > 80]
    people = [p for page in pages if page['category'] in ('governance', 'executive') for p in page['people']]
    businesses = [r for page in pages for r in page.pop("businesses", [])]
    projects = [r for page in pages for r in page.pop("projects", [])]
    metrics = [r for page in pages for r in page.pop("metrics", [])]
    publications = []
    for page in pages:
        for u, label in page['links']:
            if urlsplit(u).path.lower().endswith('.pdf') and label and page['category'] in ('financial', 'annual', 'projects'):
                publications.append({'title': label[:160], 'url': u, 'source_url': page['url']})
    for page in pages:
        original = len(page['text'])
        page['text'] = page['text'][:10000]
        page['truncated'] = original > 10000
        page['original_chars'] = original
        page.pop('people', None); page.pop('links', None)
    return {'query': query, 'requested_domain': domain, 'official_domain': root_host,
            'redirect_url': home['url'], 'retrieved_at': datetime.now(timezone.utc).isoformat(),
            'pages': pages, 'people': people, 'businesses': businesses, 'projects': projects, 'metrics': metrics, 'publications': publications[:25], 'failures': errors,
            'scope': 'выборка публичных страниц сайта; состав органов на дату чтения, не полная история назначений'}
