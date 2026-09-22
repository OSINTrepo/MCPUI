"""Офлайн-регрессии HTML парсеров официальных корпоративных источников."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'directapi'))
import corporate
import borme


class CorporateTests(unittest.TestCase):
    def test_spanish_financial_units_and_business_cards(self):
        html = "<h1>Group</h1><p>Ventas</p><p>2025</p><p>5.457 M€</p><p>Profesionales</p><p>2025</p><p>&gt;62.000</p>"
        html += "<p>negocios</p><p>Traffic</p><p>" + ("Descripción del producto. " * 5) + "</p><p>Actualidad</p>"
        p = corporate.parse_page(html, "https://example.org", "overview")
        self.assertEqual(p["metrics"][0]["value"], 5457000000)
        self.assertEqual(p["metrics"][1]["value"], 62000)
        self.assertEqual(p["businesses"][0]["name"], "Traffic")

    def test_board_roles_dates_and_committees(self):
        html = '''<html><title>Governance</title><nav>Ignore</nav><main><h1>Gobierno</h1>
          <h2>Consejo de Administración</h2><h5>Presidente</h5><h3>Persona Ejemplo</h3>
          <p>Último nombramiento: 30 de junio de 2026</p>
          <h2>Comisión de Auditoría</h2><h5>Vocales</h5><h3>Otra Persona</h3>
          </main><footer>Noise</footer></html>'''
        p = corporate.parse_page(html, 'https://example.org/board', 'governance')
        self.assertNotIn('Ignore', p['text'])
        self.assertNotIn('Noise', p['text'])
        self.assertEqual(p['people'][0]['name'], 'Persona Ejemplo')
        self.assertEqual(p['people'][0]['role'], 'Presidente')
        self.assertEqual(p['people'][0]['appointed'], '30 de junio de 2026')
        self.assertEqual(p['people'][1]['group'], 'Comisión de Auditoría')

    def test_profile_cards_keep_roles_and_last_appointment(self):
        html = """<main><article><header><h1>Board of Directors</h1></header><a class="profile-box__head">
        <span class="profile-box__name">Ms. Example Director</span>
        <p class="profile-box__role">Chairwoman<br>Executive Director<br>
        First appointment: <strong>18-01-2025</strong><br>
        Last appointment: <strong>10-04-2025</strong></p></a></article></main>"""
        p = corporate.parse_page(html, 'https://example.org/board', 'governance')
        self.assertEqual(len(p['people']), 1)
        self.assertEqual(p['people'][0]['name'], 'Example Director')
        self.assertEqual(p['people'][0]['role'], 'Chairwoman Executive Director')
        self.assertEqual(p['people'][0]['appointed'], '10-04-2025')
        self.assertEqual(corporate.parse_page(html, 'https://example.org/news', 'overview')['people'], [])

    def test_borme_repeated_roles_do_not_consume_hyphenated_names(self):
        html = ("<h5>123 - EXAMPLE SA.</h5><p>Revocaciones. "
                "Apo.Man.Soli.: GARCIA-MON EJEMPLO ANTONIO. "
                "Apo.Sol.: GARCIA-MON EJEMPLO ANTONIO. "
                "Datos registrales. H M 42 (15.05.26).</p>")
        _, people = borme.parse(html, 'EXAMPLE SA', 'https://www.boe.es/record')
        self.assertEqual([p['name'] for p in people], ['GARCIA-MON EJEMPLO ANTONIO'] * 2)
        self.assertEqual([p['role'] for p in people], ['Apo.Man.Soli.', 'Apo.Sol.'])

    def test_public_component_attributes_are_data_not_executed_code(self):
        html = """<main><h1>Компания</h1><main-page :indicators="[{value: '42', text: 'магазина', link: '/ru/about-company/'}]"></main-page>
        <z-link href="/ru/contacts/">Реквизиты</z-link></main>"""
        page = corporate.parse_page(html, 'https://example.org/ru/', 'overview')
        self.assertIn("value: '42'", page['text'])
        self.assertIn(('https://example.org/ru/about-company/', ''), page['links'])
        self.assertIn(('https://example.org/ru/contacts/', 'Реквизиты'), page['links'])

    def test_borme_exact_company_and_historical_events(self):
        html = '''<h5>123 - EXAMPLE SA.</h5><p>Nombramientos. Apo.Sol.: PERSONA UNO;PERSONA DOS.
          Revocaciones. Apoderado: PERSONA TRES. Datos registrales. H M 42 (15.05.26).</p>
          <h5>124 - EXAMPLE SOLUCIONES SA.</h5><p>Nombramientos. Apoderado: OTRA PERSONA.</p>'''
        acts, people = borme.parse(html, 'EXAMPLE, S.A.', 'https://www.boe.es/record')
        self.assertEqual(len(acts), 1)
        self.assertEqual([p['name'] for p in people], ['PERSONA UNO','PERSONA DOS','PERSONA TRES'])
        self.assertEqual(people[-1]['event'], 'Revocaciones')
        self.assertEqual(people[-1]['date'], '15.05.26')


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_annual_index_follows_latest_official_html_report(self):
        body = '<main><p>' + 'Public company facts. ' * 10 + '</p></main>'
        requested = []
        def handler(req):
            requested.append(str(req.url))
            if req.url.path == '/':
                extra = '<a href="/annual-reports/">Annual reports</a>'
            elif req.url.path == '/annual-reports/':
                extra = ('<a href="/reports/ar24/index.html">2024 Annual report</a>'
                         '<a href="/reports/ar25/index.html">2025 Annual report</a>'
                         '<a href="https://other.org/annual-report-2026.html">2026 Annual report</a>'
                         '<a href="/annual-report-2026.pdf">2026 Annual report PDF</a>')
            else:
                extra = '<title>2025 Annual Report</title>'
            return httpx.Response(200, headers={'content-type':'text/html'}, text=body+extra)
        client = httpx.AsyncClient
        with patch('corporate.httpx.AsyncClient', side_effect=lambda **kw: client(transport=httpx.MockTransport(handler), **kw)):
            result = await corporate.collect('example.org', 'Example Corp')
        self.assertIn('https://example.org/reports/ar25/index.html', requested)
        self.assertNotIn('https://example.org/reports/ar24/index.html', requested)
        self.assertFalse(any('other.org' in u or u.endswith('.pdf') for u in requested))
        self.assertEqual(sum(p['url'].endswith('/ar25/index.html') for p in result['pages']), 1)

    async def test_governance_overview_follows_official_board_link(self):
        body = '<main><h1>Company</h1><p>' + 'Information. ' * 10 + '</p></main>'
        def handler(req):
            if req.url.path == '/':
                extra = '<a href="/corporate-governance/">Governance</a>'
            elif req.url.path == '/corporate-governance/':
                extra = '<a href="/board-of-directors/">Board</a><a href="https://other.org/board-members/">Other</a>'
            else:
                extra = ''
            return httpx.Response(200, headers={'content-type': 'text/html'}, text=body + extra)
        client = httpx.AsyncClient
        with patch('corporate.httpx.AsyncClient', side_effect=lambda **kw: client(transport=httpx.MockTransport(handler), **kw)):
            result = await corporate.collect('example.org', 'Example Corp')
        urls = [p['url'] for p in result['pages']]
        self.assertIn('https://example.org/board-of-directors/', urls)
        self.assertFalse(any('other.org' in u for u in urls))

    async def test_board_beats_blog_and_search_home_is_not_project(self):
        home = ('<main><h1>Company</h1><p>' + 'Public company information. ' * 5 + '</p></main>'
                '<a href="/tag/leadership/">Leadership</a>'
                '<a href="/investors/governance/board-of-directors/">Board</a>')
        board = '<main><h1>Board of Directors</h1><p>' + 'Board information. ' * 8 + '</p></main>'
        requests = []
        def handler(req):
            requests.append(req.url.path)
            return httpx.Response(200, headers={'content-type': 'text/html'},
                                  text=home if req.url.path == '/' else board)
        async def search(*args, **kwargs):
            return '{"results":[{"link":"https://example.org/","title":"Company: home"}]}'
        client = httpx.AsyncClient
        with patch('corporate.httpx.AsyncClient', side_effect=lambda **kw: client(transport=httpx.MockTransport(handler), **kw)):
            result = await corporate.collect('example.org', 'Example SA', search)
        self.assertIn('/investors/governance/board-of-directors/', requests)
        self.assertNotIn('/tag/leadership/', requests)
        self.assertFalse(any(p['category'] == 'projects' for p in result['pages']))


if __name__ == '__main__':
    unittest.main()
