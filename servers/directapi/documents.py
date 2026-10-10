"""Ограниченное чтение публичных документов с датой, URL и контрольной суммой."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import io
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
import httpx

import corporate


async def public_url(url):
    parsed = urlsplit(url)
    if not corporate.clean_url(url) or parsed.port not in (None, 80, 443):
        raise ValueError('нужен публичный HTTP(S) URL')
    addresses = await asyncio.get_running_loop().getaddrinfo(
        parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80),
        type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('непубличный адрес источника')


async def collect(url: str) -> dict:
    result = {'requested_url': url, 'retrieved_at': datetime.now(timezone.utc).isoformat(),
              'scope': 'прочитанный публичный документ; не поисковый сниппет'}
    try:
        current = url
        async with httpx.AsyncClient(timeout=22, follow_redirects=False,
                                     headers={'User-Agent': 'OSINT-MCP-UI document research/1.0'}) as client:
            for hop in range(5):
                await public_url(current)
                async with client.stream('GET', current) as response:
                    if response.is_redirect:
                        if hop == 4 or not response.headers.get('location'):
                            raise ValueError('слишком много редиректов')
                        current = urljoin(current, response.headers['location'])
                        continue
                    response.raise_for_status()
                    content_type = response.headers.get('content-type', '').split(';')[0]
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 5_000_000:
                            raise ValueError('документ больше 5 MB')
                    result.update(url=str(response.url), content_type=content_type,
                                  http_status=response.status_code, bytes=len(raw),
                                  document_sha256=hashlib.sha256(raw).hexdigest())
                    if content_type == 'application/pdf' or raw.startswith(b'%PDF-'):
                        from pypdf import PdfReader
                        reader = PdfReader(io.BytesIO(raw))
                        text = '\n'.join(page.extract_text() or '' for page in reader.pages[:30])
                        result.update(title=current.rsplit('/', 1)[-1], method='HTTP / PDF',
                                      total_pages=len(reader.pages), read_pages=min(30, len(reader.pages)),
                                      truncated=len(reader.pages) > 30)
                    elif 'html' in content_type or raw.lstrip().startswith((b'<!DOCTYPE', b'<html', b'<HTML')):
                        decoded = bytes(raw).decode(response.encoding or 'utf-8', 'replace')
                        page = corporate.parse_page(decoded, str(response.url), 'document')
                        soup = BeautifulSoup(decoded, 'html.parser')
                        published = soup.find('meta', attrs={'property': 'article:published_time'})
                        result.update(title=page['title'], method='HTTP / HTML', links=page['links'],
                                      published_at=published.get('content') if published else None)
                        text = page['text']
                    elif content_type.startswith('text/'):
                        text = bytes(raw).decode(response.encoding or 'utf-8', 'replace')
                        result.update(title=current.rsplit('/', 1)[-1], method='HTTP / text')
                    else:
                        raise ValueError('неподдерживаемый тип документа')
                    if len(text.strip()) < 40:
                        raise ValueError('доступный текст не получен')
                    if any(marker in text[:3500].casefold() for marker in
                           ('verify you are human', 'checking your browser', 'request is being verified', 'access denied',
                            'enable javascript and cookies to continue')):
                        raise ValueError('источник требует интерактивную проверку')
                    result.update(text=text[:40000], original_chars=len(text),
                                  truncated=result.get('truncated', False) or len(text) > 40000,
                                  text_sha256=hashlib.sha256(text[:40000].encode()).hexdigest(),
                                  extracted_text_sha256=hashlib.sha256(text.encode()).hexdigest())
                    return result
    except Exception as exc:
        result.update(error='публичный документ не прочитан', reason=type(exc).__name__)
    return result
