"""Офлайн-регрессии HTML парсеров официальных корпоративных источников."""
from pathlib import Path
import sys
import unittest
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

    def test_borme_exact_company_and_historical_events(self):
        html = '''<h5>123 - EXAMPLE SA.</h5><p>Nombramientos. Apo.Sol.: PERSONA UNO;PERSONA DOS.
          Revocaciones. Apoderado: PERSONA TRES. Datos registrales. H M 42 (15.05.26).</p>
          <h5>124 - EXAMPLE SOLUCIONES SA.</h5><p>Nombramientos. Apoderado: OTRA PERSONA.</p>'''
        acts, people = borme.parse(html, 'EXAMPLE, S.A.', 'https://www.boe.es/record')
        self.assertEqual(len(acts), 1)
        self.assertEqual([p['name'] for p in people], ['PERSONA UNO','PERSONA DOS','PERSONA TRES'])
        self.assertEqual(people[-1]['event'], 'Revocaciones')
        self.assertEqual(people[-1]['date'], '15.05.26')


if __name__ == '__main__':
    unittest.main()
