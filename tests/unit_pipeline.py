"""Регрессии сравнения INDRA: форма API, идентичность и провенанс корпоративных фактов."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'servers' / 'orchestrator'))
import dossier
import entity
import official
import recipes


class PipelineTests(unittest.TestCase):
    def test_borme_events_reach_narrative_without_current_officers(self):
        event = {'name': 'Example Person', 'event': 'Revocaciones', 'date': '2026-07-30'}
        borme = {'announcements': [{'number': '123'}], 'officer_events': [event],
                 'scope': 'Историческая выборка, не действующие полномочия'}
        compact = dossier.company_data_for_llm('Example SA', {'borme': borme}, [])
        self.assertEqual(compact['borme']['announcements_count'], 1)
        self.assertEqual(compact['borme']['officer_events_sample'], [event])
        self.assertEqual(compact['borme']['officers'], [])
        self.assertEqual(compact['borme']['scope'], borme['scope'])

    def test_numeric_registry_values_render_without_crashing(self):
        import sections
        data = {"borme": {"name": "Example SA", "num_announcements": 12}}
        result = "\n".join(sections.render_target("company", data))
        self.assertIn("| Число актов BORME | 12 |", result)
        self.assertIn("| 0 |", "\n".join(dossier._md_table(["Count"], [[0]])))

    def test_table_html_cannot_swallow_report_scripts(self):
        table = "\n".join(dossier._md_table(["Заголовок <title>", "Значение"],
                              [["<script>alert(1)</script>", "Компания & партнёры\nофис"]]))
        self.assertNotIn("<title>", table)
        self.assertNotIn("<script>", table)
        self.assertIn("&lt;title&gt;", table)
        self.assertIn("&amp; партнёры<br>офис", table)

    def test_nested_subfinder_payload(self):
        result = {'server': 'vulneramcp', 'tool': 'recon.subfinder', 'ok': True,
                  'text': json.dumps({'success': True, 'data': {
                      'subdomains': ['mail.example.org', 'vpn.example.org']}})}
        data = dossier.extract_domain_data([result])
        self.assertEqual(data['subdomains'], {'mail.example.org', 'vpn.example.org'})

    def test_company_not_duplicated_by_legal_suffix(self):
        targets = recipes.detect_targets('собери подробное досье по компании INDRA SISTEMAS SA, CIF A28599033, сайт indracompany.com')
        self.assertEqual([t['value'] for t in targets if t['type'] == 'company'], ['INDRA SISTEMAS SA'])

    def test_probe_entity_requires_resolution(self):
        row = {'server': 'directapi', 'tool': 'gleif_entity', 'ok': True, 'phase': 'resolve',
               'text': json.dumps({'legal_name': 'Example SA', 'lei': 'valid-lei'})}
        self.assertIsNone(dossier.extract_company_data([row])['gleif'])
        self.assertIsNone(dossier.extract_company_data([row], {'legal_name': 'Other SA', 'lei': 'other'})['gleif'])
        self.assertEqual(dossier.extract_company_data([row], {'legal_name': 'Example SA', 'lei': 'valid-lei'})['gleif']['lei'], 'valid-lei')

    def test_quote_validation_rejects_fabricated_numbers_and_sources(self):
        url = 'https://example.org/about'
        pages = [{'url': url, 'text': 'Revenue in 2025 was EUR 500 million.'}]
        good = dict(section='financial', text='Выручка 2025: EUR 500 million.',
                    quote=pages[0]['text'], url=url)
        bad = dict(good, text='Выручка 2025: EUR 900 million.')
        foreign = dict(good, url='https://other.org/')
        self.assertEqual(official.verified_claims({'claims': [good,bad,foreign]}, pages), [good])

    def test_subdomain_ips_enter_network_enrichment(self):
        row = {'server': 'directapi', 'tool': 'resolve_hosts', 'ok': True,
               'text': json.dumps({'map': {'vpn.example.org': '203.0.113.10'},
                                   'unresolved': ['old.example.org']})}
        data = dossier.extract_domain_data([row])
        self.assertIn('203.0.113.10', data['ips'])
        self.assertEqual(data['dns_unresolved'], ['old.example.org'])
        failed_retry = dict(row, text=json.dumps({'map': {}, 'unresolved': [],
                           'failures': [{'host': 'old.example.org', 'reason': 'Timeout'}]}))
        data = dossier.extract_domain_data([row, failed_retry])
        self.assertEqual(data['dns_unresolved'], ['old.example.org'])
        self.assertEqual(data['subdomain_ips']['vpn.example.org'], '203.0.113.10')
        resolved_retry = dict(row, text=json.dumps({'map': {'old.example.org': '203.0.113.20'}}))
        data = dossier.extract_domain_data([row, failed_retry, resolved_retry])
        self.assertEqual(data['dns_unresolved'], [])


if __name__ == '__main__':
    unittest.main()
