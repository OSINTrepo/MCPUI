"""Самодостаточные HTML: исходные веб-ссылки и материалы внутри документа."""
from __future__ import annotations

import base64
from collections import deque
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import mimetypes
from pathlib import Path
import re
from typing import Callable
from urllib.parse import urlsplit


_MATERIALS_CSS = '''
#portable-materials { margin-top:48px; min-width:0; max-width:100%; }
#portable-materials .materials-header { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
#portable-materials .materials-header h2 { margin:0; padding:0; border:0; }
#portable-materials .materials-count { padding:3px 9px; border-radius:20px; font-size:12px;
  color:var(--text,#334155); background:var(--raised,#eef2f6); }
#portable-materials .materials-intro { margin:10px 0 20px; color:var(--text,#334155); font-size:14px; }
#portable-materials .materials-list { display:grid; gap:12px; min-width:0; }
#portable-materials .material-card { min-width:0; padding:20px; border:1px solid var(--border,#d8e2f0);
  border-radius:12px; background:var(--surface,#fff); scroll-margin-top:24px; }
#portable-materials .material-row { display:grid; grid-template-columns:40px minmax(0,1fr) auto;
  align-items:start; gap:14px; }
#portable-materials .material-icon { width:40px; height:44px; display:grid; place-items:center;
  border-radius:9px; color:var(--accent,#0a9e82); background:var(--accent-dim,#effaf6); }
#portable-materials .material-icon svg { width:22px; height:22px; }
#portable-materials .material-info { min-width:0; }
#portable-materials .material-title { margin:0 0 4px; color:var(--strong,#0e1d30);
  font-size:16px; font-weight:650; line-height:1.4; overflow-wrap:anywhere; }
#portable-materials .material-description { margin:0; font-size:13px; line-height:1.6; color:var(--text,#334155); }
#portable-materials .material-meta { margin-top:7px; font-size:12px; color:var(--muted,#64748b); }
#portable-materials .material-download { display:inline-flex; align-items:center; justify-content:center;
  gap:7px; padding:7px 12px; border:1px solid var(--border,#d8e2f0); border-radius:7px;
  color:var(--accent,#0a9e82); background:var(--accent-dim,#effaf6); font-size:13px;
  line-height:1.6; white-space:nowrap; text-decoration:none; }
#portable-materials .material-download:hover { background:var(--raised,#eef2f6); text-decoration:none; }
#portable-materials .material-download:focus-visible, #portable-materials summary:focus-visible {
  outline:2px solid var(--accent,#0a9e82); outline-offset:3px; }
#portable-materials .material-download svg { width:15px; height:15px; }
#portable-materials .material-preview { margin:14px 0 0; border:0; border-top:1px solid var(--border,#d8e2f0);
  border-radius:0; overflow:hidden; }
#portable-materials .material-preview > summary { padding:12px 0 0; background:none;
  border:0; font-size:13px; color:var(--text,#334155); }
#portable-materials .material-preview[open] > summary { padding-bottom:8px; border:0; background:none; }
#portable-materials .material-filename { margin:8px 0; font-size:12px; color:var(--muted,#64748b); overflow-wrap:anywhere; }
#portable-materials .material-preview pre { margin:8px 0 0; padding:14px; max-width:100%; max-height:420px;
  overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; font-size:12px; line-height:1.6; }
#portable-materials img { display:block; max-width:100%; height:auto; margin-top:14px; }
@media (max-width:560px) {
  #portable-materials .material-card { padding:16px; }
  #portable-materials .material-row { grid-template-columns:32px minmax(0,1fr); gap:12px; }
  #portable-materials .material-icon { width:32px; height:38px; }
  #portable-materials .material-download { grid-column:2; justify-self:start; }
}
@media print {
  #portable-materials a[download]::after { content:none!important; }
  #portable-materials .material-preview pre { max-height:none; }
  #portable-materials .material-card { break-inside:avoid; }
}
'''
_FILE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h6"/></svg>'
_DOWNLOAD_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 16v4h14v-4"/></svg>'


def _material_label(path):
    if path.name.endswith('.organization.research.json'):
        return 'Источники и связи организации', 'Люди, партнёры, мероприятия и подтверждающие документы.'
    if path.name.endswith('.research.json'):
        return 'Корпоративная проверка', 'Реквизиты, источники и результаты проверки организации.'
    return path.stem.replace('_', ' ').replace('-', ' '), 'Материал, на который ссылается отчёт.'


def _file_size(size):
    if size >= 1024 * 1024:
        return f'{size / (1024 * 1024):.1f} МБ'
    return f'{max(1, round(size / 1024))} КБ'


def nonpublic_url(value: str) -> bool:
    """Служебные/локальные адреса нельзя выдавать за публичный источник."""
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() == 'file':
        return True
    host = (parsed.hostname or '').lower().rstrip('.')
    if host in {'localhost', '0.0.0.0'} or host.endswith(('.localhost', '.local', '.internal')):
        return True
    if host:
        try:
            return not ipaddress.ip_address(host).is_global
        except ValueError:
            return '.' not in host
    return False


class _Document(HTMLParser):
    """Позиции настоящих тегов; содержимое JS не переписывается как HTML."""
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.lines = [0]
        self.lines.extend(match.end() for match in re.finditer('\n', text))
        self.tags = []
        self.slices = []
        self.stack = []
        self.feed(text)

    def source_position(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self.source_position()
        raw = self.get_starttag_text()
        self.tags.append((start, raw, tag, dict(attrs)))
        if tag in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            return
        self.stack.append((tag, start + len(raw), dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((self.source_position(), self.get_starttag_text(), tag, dict(attrs)))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            opening, start, attrs = self.stack[index]
            if opening == tag:
                self.slices.append((opening, attrs, start, self.source_position()))
                del self.stack[index:]
                break


def _body(text: str) -> str:
    doc = _Document(text)
    candidates = [(0 if attrs.get('id') == 'content' else 1 if tag == 'body' else 2, start, stop)
                  for tag, attrs, start, stop in doc.slices
                  if attrs.get('id') == 'content' or tag == 'body']
    if candidates:
        _, start, stop = min(candidates)
        text = text[start:stop]
    text = re.sub(r'<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>', '', text, flags=re.S | re.I)
    return text


def _attribute(raw: str, name: str, value: str) -> str:
    pattern = re.compile(r'(\s' + re.escape(name) + r'\s*=\s*)(?:"[^"]*"|\x27[^\x27]*\x27|[^\s>]+)', re.I)
    return pattern.sub(lambda match: match.group(1) + '"' + html.escape(value, quote=True) + '"', raw, count=1)


def html_with_materials(text: str, origin: Path,
                        resolve: Callable[[str, Path], tuple[str, object]]) -> tuple[str, dict]:
    """resolve: public(URL), file(Path), unresolved. В HTML нет файловых запросов.

    Связанные HTML помещаются в приложение как разделы без повторного JS;
    циклические ссылки ведут к уже включённому разделу. JSON и файлы вложены
    в HTML, доступны для чтения/скачивания. Данные не загружаются с диска браузером.
    """
    origin = origin.resolve()
    identifiers = {origin: 'portable-root'}
    queue = deque()
    visited = set()
    stats = {'embedded_files': 0, 'embedded_reports': 0, 'public_sources_restored': 0,
             'unresolved_links_removed': 0, 'local_links_replaced': 0}

    def identifier(path):
        path = path.resolve()
        if path not in identifiers:
            identifiers[path] = 'material-' + hashlib.sha256(str(path).encode()).hexdigest()[:16]
            queue.append(path)
        return identifiers[path]

    def rewrite(document: str, current: Path, prefix: str = '') -> str:
        edits = []
        for start, raw, tag, attrs in _Document(document).tags:
            replaced = raw
            if prefix and attrs.get('id'):
                replaced = _attribute(replaced, 'id', prefix + attrs['id'])
            for field in ('href', 'src', 'data'):
                value = attrs.get(field)
                if not value:
                    continue
                if value.startswith('#'):
                    if prefix:
                        replaced = _attribute(replaced, field, '#' + prefix + value[1:])
                    continue
                if value.startswith(('data:', 'mailto:', 'tel:')):
                    continue
                kind, target = resolve(html.unescape(value), current)
                if kind == 'public':
                    if value != str(target):
                        stats['public_sources_restored'] += 1
                    replaced = _attribute(replaced, field, str(target))
                elif kind == 'file':
                    path = Path(target).resolve()
                    if field in ('src', 'data'):
                        mime = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
                        replaced = _attribute(replaced, field, 'data:' + mime + ';base64,' + base64.b64encode(path.read_bytes()).decode())
                    else:
                        replaced = _attribute(replaced, field, '#' + identifier(path))
                    stats['local_links_replaced'] += 1
                elif kind == 'unresolved':
                    # Не оставляем кнопку на несуществующий или служебный адрес.
                    replaced = re.sub(r'\s' + field + r'\s*=\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^\s>]+)', '', replaced, count=1, flags=re.I)
                    replaced = replaced[:-1] + ' title="Файл или служебный адрес отсутствует в сохранённых материалах">'
                    stats['unresolved_links_removed'] += 1
            if replaced != raw:
                edits.append((start, start + len(raw), replaced))
        for start, stop, replacement in reversed(edits):
            document = document[:start] + replacement + document[stop:]
        return document

    root = rewrite(text, origin)
    sections = []
    while queue:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        key = identifiers[path]
        data = path.read_bytes()
        title = html.escape(path.name)
        if path.suffix.lower() == '.html':
            contents = rewrite(_body(data.decode('utf-8')), path, key + '-')
            sections.append('<section id="' + key + '"><details><summary>Связанный отчёт: ' + title + '</summary>' + contents + '</details></section>')
            stats['embedded_reports'] += 1
        else:
            mime = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
            encoded = base64.b64encode(data).decode()
            label, description = _material_label(path)
            filetype = path.suffix.removeprefix('.').upper() or 'ФАЙЛ'
            metadata = filetype + ' · ' + _file_size(len(data))
            if path.suffix.lower() == '.json':
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, dict) and isinstance(parsed.get('pages'), list):
                        metadata += ' · источников: ' + str(len(parsed['pages']))
                except (ValueError, UnicodeDecodeError):
                    pass
            download = '<a class="material-download" download="' + html.escape(path.name, quote=True) + '" aria-label="Скачать: ' + html.escape(label, quote=True) + '" href="data:' + mime + ';base64,' + encoded + '">' + _DOWNLOAD_ICON + 'Скачать ' + html.escape(filetype) + '</a>'
            preview = ''
            if path.suffix.lower() in {'.json', '.txt', '.csv', '.md', '.py', '.yaml', '.yml'}:
                preview = '<details class="material-preview"><summary>Посмотреть данные</summary><p class="material-filename">Файл: ' + title + '</p><pre>' + html.escape(data.decode('utf-8', errors='replace')) + '</pre></details>'
            elif path.suffix.lower() in {'.jpg', '.jpeg', '.png', '.svg'}:
                preview = '<img alt="' + title + '" style="max-width:100%" src="data:' + mime + ';base64,' + encoded + '">'
            sections.append('<section class="material-card" id="' + key + '"><div class="material-row"><div class="material-icon">' + _FILE_ICON + '</div><div class="material-info"><p class="material-title">' + html.escape(label) + '</p><p class="material-description">' + html.escape(description) + '</p><p class="material-meta">' + html.escape(metadata) + '</p></div>' + download + '</div>' + preview + '</section>')
            stats['embedded_files'] += 1
    anchor = '<a id="portable-root"></a>'
    appendix = ''
    if sections:
        appendix = '<style>' + _MATERIALS_CSS + '</style><section id="portable-materials" aria-label="Материалы отчёта"><div class="materials-header"><h2>Материалы отчёта</h2><span class="materials-count">Файлов: ' + str(len(sections)) + '</span></div><p class="materials-intro">Вложены в отчёт и доступны при пересылке HTML-файла.</p><div class="materials-list">' + ''.join(sections) + '</div></section>'
    # JS-библиотеки содержат строки с <body> и </body>: выбираем настоящие
    # границы элемента через HTMLParser, иначе приложение попадёт внутрь JS.
    document = _Document(root)
    containers = [(0 if attrs.get('id') == 'content' else 1 if attrs.get('id') == 'main' else 2, stop)
                  for tag, attrs, start, stop in document.slices
                  if attrs.get('id') in {'content', 'main'} or tag == 'body']
    if containers:
        _, stop = min(containers)
        root = root[:stop] + appendix + root[stop:]
    else:
        root += appendix
    bodies = [(start, stop) for tag, attrs, start, stop in _Document(root).slices if tag == 'body']
    if bodies:
        start, stop = min(bodies)
        root = root[:start] + anchor + root[start:]
    else:
        root = anchor + root
    return root, stats
