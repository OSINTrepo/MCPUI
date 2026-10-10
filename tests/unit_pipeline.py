"""Регрессии сравнения INDRA: форма API, идентичность и провенанс корпоративных фактов."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'servers' / 'orchestrator'))
import dossier
import entity
import official
import recipes


class PipelineTests(unittest.TestCase):
    def test_explicit_history_refresh_is_scoped_to_one_investigation(self):
        import server
        observed = []

        async def fake_investigate(task, ctx):
            await asyncio.sleep(0)
            observed.append((task, server._FORCE_HISTORY_REFRESH.get()))
            return task

        async def run():
            with patch.object(server, '_investigate', fake_investigate):
                await asyncio.gather(server.investigate('ordinary report'),
                                     server.investigate('forced report', refresh_history=True),
                                     server.investigate('Обнови историю WHOIS без кэша'))

        asyncio.run(run())
        self.assertEqual(dict(observed), {'ordinary report': False, 'forced report': True,
                                         'Обнови историю WHOIS без кэша': True})
        self.assertFalse(server._FORCE_HISTORY_REFRESH.get())
        self.assertFalse(server._history_refresh_requested('Собери новый отчёт на BBG'))

    def test_untagged_history_stays_with_its_actual_domain(self):
        import server
        row = {'server': 'whoisxml', 'tool': 'whois_history',
               'args': {'domain': 'other.example'}, 'text': '{}'}
        self.assertEqual(server._domain_results([row], 'target.example'), [])
        self.assertEqual(server._domain_results([row], 'other.example'), [row])

    def test_history_domain_filter_accepts_equivalent_idna_hosts(self):
        import server
        rows = [
            {'server': 'whoisxml', 'tool': 'whois_history',
             'target_value': 'XN--E1AFMKFD.XN--P1AI.', 'text': '{}'},
            {'server': 'directapi', 'tool': 'whois_history',
             'args': {'domain': 'ПРИМЕР.РФ.'}, 'text': '{}'},
        ]
        self.assertEqual(server._domain_results(rows, 'пример.рф'), rows)
        self.assertEqual(server._domain_results(rows, 'other.example'), [])

    def test_company_narrative_metadata_translation_preserves_check_scope(self):
        import server
        draft = {'summary': 'Регистрация историческая: 2014-12-20; confidence — низкая. Санкционные проверки не проводились.',
                 'conclusions': 'Владение доменом не подтверждено: domain_ownership_verified=false.',
                 'assumptions': '', 'checks': ''}
        with patch.object(server, 'llm', AsyncMock(return_value=json.dumps(draft))) as llm:
            summary, conclusions, _, _ = asyncio.run(server.synthesize_company_narrative('Example', {}, []))
        self.assertEqual(llm.await_count, 1)
        self.assertIn('2014-12-20', summary)
        self.assertIn('Санкционные проверки не проводились.', summary)
        self.assertIn('не подтверждено', conclusions)
        self.assertIsNone(server._NARRATIVE_METADATA.search(summary + conclusions))
        self.assertEqual(server._human_narrative('domain_ownership_verified=true'), 'владение доменом подтверждено')

    def test_domain_history_reaches_company_summary_without_current_owner(self):
        import server
        results = [
            {'server': 'whoisxml', 'tool': 'whois_current', 'ok': True,
             'target_value': 'example.org', 'text': json.dumps({
                 'domain': 'example.org', 'domainAvailability': 'AVAILABLE',
                 'dataError': 'MISSING_WHOIS_DATA'})},
            {'server': 'whoisxml', 'tool': 'whois_history', 'ok': True,
             'target_value': 'example.org', 'text': json.dumps({'records': [{
                 'registrant': 'Historical organization', 'registrantName': 'Historical contact',
                 'createdDate': '2000-01-01', 'audit': {'createdDate': '2020-01-01'}}]})},
        ]
        identity = {'query': 'Example', 'legal_name': None, 'confidence': 'низкая'}
        with patch.object(server, 'section_comments', AsyncMock(return_value={})), \
                patch.object(server, 'synthesize_company_narrative',
                             AsyncMock(return_value=('', '', '', ''))) as narrative:
            asyncio.run(server.build_company_dossier('Example', ['example.org'], results, identity))
        infrastructure = narrative.call_args.args[2]
        self.assertEqual(len(infrastructure), 1)
        history = infrastructure[0]['whois_history']
        self.assertIn('Historical organization', json.dumps(history))
        self.assertIn('2020-01-01', json.dumps(history))
        current = infrastructure[0]['whois']
        self.assertIn('AVAILABLE', json.dumps(current))
        self.assertNotIn('Historical organization', json.dumps(current))

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

    def test_explicit_company_target_wins_over_registry_candidate_phrase(self):
        task = ('Подробное досье по историческому брокерскому бренду Boston Brokerage Group (BBG), '
                'домены bbg.trade и bbg-russia.trade. Отдельный раздел: связь с российскими компаниями '
                'и гражданами РФ. Кандидаты: ИНН 7802880793 и британское LLP OC401309. '
                'Цель: Boston Brokerage Group (BBG).')
        companies = [t['value'] for t in recipes.detect_targets(task) if t['type'] == 'company']
        self.assertEqual(companies[0], 'Boston Brokerage Group (BBG)')
        import server
        plan = server.build_plan(task)
        self.assertTrue(any(t['type'] == 'inn' for t in plan['targets']))
        self.assertFalse(any(s['server'] == 'checko' for s in plan['steps']))

    def test_zoomeye_host_query_uses_valid_exact_match_syntax(self):
        import base64
        step = next(s for s in recipes.deep_domain_steps('bbg.trade', 0)
                    if s[0] == 'zoomeye')
        query = base64.b64decode(step[2]['qbase64']).decode()
        self.assertEqual(query, 'hostname="bbg.trade"')

    def test_checko_daily_quota_is_not_reported_as_missing_key(self):
        import server
        message = ('Ошибка: HTTP 403: {"meta":{"today_request_count":101,'
                   '"message":"Превышен суточный лимит запросов для бесплатного тарифа"}}')
        self.assertEqual(server._fail_reason(message), 'суточная квота исчерпана')

    def test_product_access_denial_is_not_reported_as_missing_key(self):
        import server
        row={'server':'whoisxml','tool':'whois_history','ok':True,
             'text':json.dumps({'error':'история WHOIS недоступна: HTTP 403; проверьте ключ и баланс',
                                'provider_errors':[{'error_type':'access_denied','http_status':403}]})}
        server.reclassify([row])
        self.assertFalse(row['ok'])
        self.assertIn('доступ к продукту ограничен',row['text'])
        self.assertNotIn('нужен ключ',row['text'])
        server.reclassify([row])
        self.assertIn('доступ к продукту ограничен',row['text'])

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
        untranslated = dict(good, text="Revenue in 2025 was EUR 500 million.")
        self.assertEqual(official.verified_claims({"claims": [untranslated]}, pages), [])
        foreign = dict(good, url='https://other.org/')
        self.assertEqual(official.verified_claims({'claims': [good,bad,foreign]}, pages), [good])

    def test_annual_claim_retains_document_year(self):
        page = {'category': 'annual', 'title': 'Example 2025 Annual Report',
                'url': 'https://example.org/ar25', 'text': 'Revenue was USD 500 million.'}
        claim = {'section': 'financial', 'text': 'Выручка составила USD 500 million.',
                 'quote': page['text'], 'url': page['url']}
        verified = official.verified_claims({'claims': [claim, claim]}, [page])
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0]['document_year'], '2025')
        md = '\n'.join(official.render({'official': {'pages': [page], 'claims': verified}}, {}))
        self.assertIn('годовой отчёт за 2025', md)

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
