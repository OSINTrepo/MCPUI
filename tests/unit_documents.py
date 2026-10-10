"""Mocked public-document retrieval, SSRF rejection and evidence provenance."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'servers' / 'directapi'))
import documents
import httpx

PUBLIC_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
PRIVATE_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 443))]


class PublicDocumentTests(unittest.IsolatedAsyncioTestCase):
    async def fetch(self, url, reply, dns=PUBLIC_DNS):
        import asyncio
        original = httpx.AsyncClient
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'getaddrinfo', AsyncMock(return_value=dns)), \
             patch.object(documents.httpx, 'AsyncClient', lambda **kwargs: original(
                 transport=httpx.MockTransport(reply), **kwargs)):
            return await documents.collect(url)

    async def test_real_html_legal_footer_dates_links_and_hashes_survive(self):
        body = b'''<!DOCTYPE html><html><head><title>Tochka.fi official</title>
          <meta property="article:published_time" content="2024-03-14T09:00:00Z"></head>
          <body><nav>Navigation only</nav><main><h1>Tochka.fi</h1>
          <p>A nonprofit media and event association providing cultural activities.</p>
          <a href="/events">Events</a><script>UNTRUSTED_SCRIPT_TEXT</script></main>
          <footer>Tochka.fi rf Business ID: 3182491-8 <a href="mailto:info@tochka.fi">info@tochka.fi</a></footer>
          </body></html>'''
        before = datetime.now(timezone.utc)
        got = await self.fetch('https://tochka.fi/', lambda r: httpx.Response(200,
            content=body, headers={'content-type': 'text/html; charset=utf-8'}))
        after = datetime.now(timezone.utc)
        self.assertNotIn('error', got)
        self.assertIn('3182491-8', got['text'])
        self.assertIn('info@tochka.fi', got['text'])
        self.assertNotIn('UNTRUSTED_SCRIPT_TEXT', got['text'])
        self.assertNotIn('Navigation only', got['text'])
        self.assertEqual(got['published_at'], '2024-03-14T09:00:00Z')
        self.assertLessEqual(before, datetime.fromisoformat(got['retrieved_at']))
        self.assertLessEqual(datetime.fromisoformat(got['retrieved_at']), after)
        self.assertEqual(got['bytes'], len(body))
        self.assertEqual(got['document_sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(got['text_sha256'], hashlib.sha256(got['text'].encode()).hexdigest())
        self.assertEqual(got['original_chars'], len(got['text']))
        self.assertIn(('https://tochka.fi/events', 'Events'), got['links'])

    async def test_plain_text_limit_is_explicit_and_original_document_hash_is_preserved(self):
        body = ('Published source data. ' * 2200).encode()
        got = await self.fetch('https://source.example/report.txt', lambda r: httpx.Response(200,
            content=body, headers={'content-type': 'text/plain; charset=utf-8'}))
        self.assertNotIn('error', got)
        self.assertEqual(len(got['text']), 40000)
        self.assertTrue(got['truncated'])
        self.assertEqual(got['original_chars'], len(body.decode()))
        self.assertEqual(got['document_sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(got['text_sha256'], hashlib.sha256(got['text'].encode()).hexdigest())
        self.assertEqual(got['extracted_text_sha256'], hashlib.sha256(body.decode().encode()).hexdigest())

    async def test_private_userinfo_local_and_nonstandard_port_urls_never_reach_http(self):
        def must_not_fetch(request):
            self.fail('Private or malformed URL reached HTTP transport')

        for url in ('http://127.0.0.1/private', 'http://169.254.169.254/metadata',
                    'http://[::1]/', 'https://host.local/', 'file:///tmp/private',
                    'https://user:password@public.example/', 'https://public.example:9000/',
                    'https://public.example:bad/'):
            with self.subTest(url=url):
                got = await self.fetch(url, must_not_fetch)
                self.assertIn('error', got)
                self.assertNotIn('text', got)

    async def test_public_hostname_resolving_private_or_mixed_addresses_is_rejected(self):
        def must_not_fetch(request):
            self.fail('Non-public DNS answer reached HTTP transport')

        for records in (PRIVATE_DNS, PUBLIC_DNS + PRIVATE_DNS, []):
            got = await self.fetch('https://public.example/document', must_not_fetch, dns=records)
            self.assertIn('error', got)
            self.assertNotIn('text', got)

    async def test_redirect_is_revalidated_before_following_private_location(self):
        calls = []

        def reply(request):
            calls.append(str(request.url))
            return httpx.Response(302, headers={'location': 'http://127.0.0.1/admin'})

        got = await self.fetch('https://public.example/document', reply)
        self.assertEqual(calls, ['https://public.example/document'])
        self.assertIn('error', got)
        self.assertNotIn('text', got)

    async def test_public_redirect_preserves_requested_and_final_urls(self):
        calls = []

        def reply(request):
            calls.append(str(request.url))
            if request.url.path == '/start':
                return httpx.Response(302, headers={'location': '/final.txt'})
            return httpx.Response(200, text='A public source document with enough content to be useful.',
                                  headers={'content-type': 'text/plain'})

        got = await self.fetch('https://public.example/start', reply)
        self.assertEqual(len(calls), 2)
        self.assertEqual(got['requested_url'], 'https://public.example/start')
        self.assertEqual(got['url'], 'https://public.example/final.txt')
        self.assertNotIn('error', got)

    async def test_redirect_loop_oversized_binary_and_interactive_error_are_not_evidence(self):
        examples = [
            lambda r: httpx.Response(302, headers={'location': '/again'}),
            lambda r: httpx.Response(200, content=b'x' * 5_000_001,
                                    headers={'content-type': 'text/plain'}),
            lambda r: httpx.Response(200, content=b'binary data' * 100,
                                    headers={'content-type': 'application/octet-stream'}),
            lambda r: httpx.Response(200, text='Access denied. Please verify you are human to continue.',
                                    headers={'content-type': 'text/plain'}),
            lambda r: httpx.Response(200, text='Please wait while your request is being verified...',
                                    headers={'content-type': 'text/plain'}),
            lambda r: httpx.Response(503, text='Provider unavailable'),
            lambda r: httpx.Response(200, content=b'%PDF-this is not a real PDF',
                                    headers={'content-type': 'application/pdf'}),
        ]
        for reply in examples:
            got = await self.fetch('https://public.example/source', reply)
            self.assertIn('error', got)
            self.assertNotIn('text', got)


if __name__ == '__main__':
    unittest.main()
