"""Пересылка HTML/PDF без сервера, с сохранением ответов и публичных цитат."""
import base64
from html.parser import HTMLParser
import json
import logging
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'servers/orchestrator'))
import portable
import report

logging.getLogger('fontTools').setLevel(logging.ERROR)
logging.getLogger('weasyprint').setLevel(logging.ERROR)


class PortableReportTests(unittest.TestCase):
    def test_single_html_contains_exact_json_and_public_citations(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / 'evidence.json'
            expected = {'records': [{'date': '2020-01-02', 'name': 'Организация <script>'}]}
            evidence.write_text(json.dumps(expected, ensure_ascii=False))
            page = '<html><body><a href="http://localhost:8899/evidence.json">Материалы</a><a href="https://example.org/source">Источник</a></body></html>'
            def resolve(uri, origin):
                return ('file', evidence) if 'localhost' in uri else ('public', uri)
            converted, stats = portable.html_with_materials(page, root / 'report.html', resolve)
            self.assertNotIn('localhost', converted)
            self.assertIn('href="https://example.org/source"', converted)
            payload = re.search(r'href="data:application/json;base64,([^"]+)"', converted).group(1)
            self.assertEqual(json.loads(base64.b64decode(payload)), expected)
            self.assertIn('&lt;script&gt;', converted)
            self.assertEqual(stats['embedded_files'], 1)
            evidence.unlink()
            self.assertEqual(json.loads(base64.b64decode(payload)), expected)

    def test_cyclic_related_reports_embed_once_and_keep_sections(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first, second = root / 'first.html', root / 'second.html'
            first.write_text('<html><body><a href="second.html">Второй</a></body></html>')
            second.write_text('<html><body><div id="content"><h2 id="facts">Проверенный факт</h2><a href="#facts">Факт</a><a href="first.html">Первый</a></div><script>outsideSnapshot()</script></body></html>')
            converted, stats = portable.html_with_materials(first.read_text(), first,
                lambda value, origin: ('file', origin.parent / value))
            self.assertEqual(stats['embedded_reports'], 1)
            self.assertEqual(converted.count('Проверенный факт'), 1)
            self.assertIn('href="#portable-root"', converted)
            self.assertNotIn('outsideSnapshot()', converted)
            self.assertNotIn('href="second.html"', converted)

    def test_script_strings_are_not_treated_as_links(self):
        with tempfile.TemporaryDirectory() as folder:
            page = '<html><body><script>const s = \'<a href="http://localhost:8899/fake">\';</script><a href="https://example.org/">Real</a></body></html>'
            converted, _ = portable.html_with_materials(page, Path(folder) / 'r.html', lambda value, origin: ('public', value))
            self.assertIn('const s =', converted)
            self.assertIn('http://localhost:8899/fake', converted)

    def test_missing_file_is_not_a_clickable_broken_link(self):
        page = '<html><body><a href="http://localhost:8899/missing.json">Материал</a></body></html>'
        converted, stats = portable.html_with_materials(page, Path('/tmp/r.html'), lambda value, origin: ('unresolved', None))
        self.assertNotIn('href=', converted)
        self.assertNotIn('localhost', converted)
        self.assertIn('Материал', converted)
        self.assertEqual(stats['unresolved_links_removed'], 1)

    def test_materials_do_not_break_script_body_tag_strings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = root / 'evidence.json'
            evidence.write_text('{"records_count":38}')
            script = 'const template = "<body>" + "</body></html>";'
            page = '<html><head><script>' + script + '</script></head><body><a href="evidence.json">Evidence</a><script>' + script + '</script></body></html>'
            converted, stats = portable.html_with_materials(page, root / 'report.html',
                lambda uri, origin: ('file', evidence))
            document = portable._Document(converted)
            scripts = [converted[start:stop] for tag, attrs, start, stop in document.slices if tag == 'script']
            self.assertEqual(scripts, [script, script])
            self.assertEqual(converted.count('id="portable-root"'), 1)
            self.assertEqual(converted.count('id="portable-materials"'), 1)
            body_start, body_stop = next((start, stop) for tag, attrs, start, stop in document.slices if tag == 'body')
            self.assertTrue(converted[body_start:body_stop].startswith('<a id="portable-root">'))
            self.assertIn('id="portable-materials"', converted[body_start:body_stop])
            self.assertEqual(stats['embedded_files'], 1)

    def test_private_hosts_are_not_public_sources(self):
        for url in ['http://localhost:8899/a', 'http://127.0.0.1/a', 'http://10.0.0.1/a',
                    'http://[::1]/a', 'file:///tmp/report.pdf', 'http://reports/a']:
            self.assertTrue(portable.nonpublic_url(url), url)
        self.assertFalse(portable.nonpublic_url('https://bo.nalog.gov.ru/download/bfo/pdf/123'))

    def test_download_alias_precedes_nested_report_path(self):
        self.assertEqual(report._report_url('http://localhost:8899/group/Folder with spaces', 'r.html', True),
                         'http://localhost:8899/download/group/Folder%20with%20spaces/r.html')
        self.assertEqual(report._report_url('https://reports.example.org/group/%D0%A2%D0%B5%D1%81%D1%82', 'r.pdf'),
                         'https://reports.example.org/group/%D0%A2%D0%B5%D1%81%D1%82/r.pdf')

    def test_real_html_renderer_keeps_supporting_file_when_forwarded_alone(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = b'{"records_count": 38}'
            (root / 'r.research.json').write_bytes(evidence)
            output = root / 'r.html'
            self.assertTrue(report.write_html('# Report\n\n[Evidence](r.research.json)\n\n[Source](https://example.org/source)', str(output), attachments={'r.research.json': evidence}))
            page = output.read_text()
            self.assertNotIn('href="r.research.json"', page)
            self.assertIn('data:application/json;base64,' + base64.b64encode(evidence).decode(), page)
            self.assertIn('https://example.org/source', page)
            # Приложение не должно становиться третьей колонкой flex-body.
            document = portable._Document(page)
            content_start, content_stop = next((start, stop) for tag, attrs, start, stop in document.slices
                                               if attrs.get('id') == 'content')
            materials_start, materials_stop = next((start, stop) for tag, attrs, start, stop in document.slices
                                                   if attrs.get('id') == 'portable-materials')
            self.assertLess(content_start, materials_start)
            self.assertLess(materials_stop, content_stop)

    def test_real_pdf_renderer_embeds_evidence_instead_of_a_local_url(self):
        from pypdf import PdfReader
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'r.pdf'
            expected = b'{"records_count": 38}'
            self.assertTrue(report.write_pdf('# Report\n\n[Evidence](r.research.json)', str(output), attachments={'r.research.json': expected}))
            reader = PdfReader(output)
            self.assertEqual(reader.attachments['r.research.json'][0], expected)
            for page in reader.pages:
                for annotation in page.get('/Annots', []):
                    uri = annotation.get_object().get('/A', {}).get('/URI')
                    self.assertFalse(uri and ('localhost' in uri or str(uri).endswith('.research.json')))


if __name__ == '__main__':
    unittest.main()
