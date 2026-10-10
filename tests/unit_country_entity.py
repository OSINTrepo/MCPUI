"""Регрессии идентификации РФ/США: точные идентификаторы и отсутствие чужих карточек."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'orchestrator'))
import entity
import dossier
import recipes
import sections


def checko(data, tool='get_company', args=None):
    return dict(server='checko', tool=tool, ok=True, phase='resolve',
                args=args or {'inn': '2309085638'}, text=json.dumps({'data': data}))


COMPANY = {'ИНН': '2309085638', 'ОГРН': '1032304945947', 'НаимСокр': 'ПАО "МАГНИТ"',
           'НаимПолн': 'ПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО "МАГНИТ"'}


class CountryTests(unittest.TestCase):
    def test_explicit_cik_is_not_russian_inn(self):
        task = 'компания Example Corporation, США, CIK: 0000789019, ticker EXAM'
        self.assertFalse(any(t['type'] == 'inn' for t in recipes.detect_targets(task)))
        self.assertFalse(recipes.looks_russian('Example Corporation', task))
        probes = entity.probe_specs('Example Corporation', task)
        self.assertIn(('directapi', 'sec_edgar', {'query': '0000789019'}), probes)
        self.assertFalse(any(s == 'checko' for s, _, _ in probes))
        self.assertEqual(recipes.inn_values(task + ', ИНН 2309085638'), ['2309085638'])
        self.assertEqual(recipes.inn_values('ИНН 0000789019'), ['0000789019'])
        self.assertIn(('directapi', 'sec_edgar', {'query': '0000789019'}),
                      entity.probe_specs('Example Corp', 'CIK 789019'))

    def test_late_sec_completes_identified_company_and_enables_financials(self):
        gleif = {'legal_name': 'Example Corporation', 'lei': 'example-lei',
                 'jurisdiction': 'US-WA', 'registration_status': 'ISSUED'}
        row = dict(server='directapi', tool='gleif_entity', ok=True, text=json.dumps(gleif))
        early = entity.resolve('Example Corporation', entity.parse_probes([row]), ['example.com'])
        self.assertTrue(early['legal_name'])
        self.assertIsNone(early['cik'])
        sec = dict(server='directapi', tool='sec_edgar', ok=True,
                   text=json.dumps({'name': 'EXAMPLE CORP', 'cik': '0000789019',
                                    'tickers': ['EXAM'], 'state_of_incorporation': 'WA'}))
        late = entity.refresh_identity(early, 'Example Corporation', [row, sec], ['example.com'])
        self.assertEqual(late['cik'], '0000789019')
        self.assertEqual(late['tickers'], ['EXAM'])
        self.assertEqual(late['lei'], early['lei'])
        self.assertIn(('directapi', 'sec_financials', {'query': '0000789019'}),
                      recipes.deep_company_steps(late['legal_name'], late))

    def test_late_registry_cannot_replace_another_confirmed_entity(self):
        current = {'legal_name': 'Example Corporation', 'jurisdiction': 'RU', 'inn': '2309085638'}
        sec = dict(server='directapi', tool='sec_edgar', ok=True,
                   text=json.dumps({'name': 'EXAMPLE CORP', 'cik': '0000789019',
                                    'tickers': ['EXAM'], 'state_of_incorporation': 'WA'}))
        self.assertEqual(entity.refresh_identity(current, 'Example Corporation', [sec], []), current)
        current = {'legal_name': 'Another Corp', 'jurisdiction': 'US-WA'}
        self.assertEqual(entity.refresh_identity(current, 'Example Corporation', [sec], []), current)
        current = {'legal_name': 'Example Corp', 'jurisdiction': 'US-WA', 'cik': '0000000001'}
        self.assertEqual(entity.refresh_identity(current, 'Example Corporation', [sec], []), current)

    def test_supplied_uk_llp_number_becomes_an_unconfirmed_opencorporates_candidate(self):
        task = 'Boston Brokerage Group, Russia links; candidate UK LLP OC401309'
        specs = entity.probe_specs('Boston Brokerage Group', task)
        self.assertIn(('directapi', 'opencorporates_search', {'query': 'OC401309'}), specs)
        row = {'server': 'directapi', 'tool': 'opencorporates_search', 'ok': True,
               'text': json.dumps({'query': 'OC401309', 'matches': [{
                   'name': 'Boston Brokerage Group LLP', 'company_number': 'OC401309',
                   'jurisdiction': 'gb', 'status': 'Dissolved', 'inactive': True,
                   'url': 'https://opencorporates.com/companies/gb/OC401309'}]})}
        probes = entity.parse_probes([row])
        ident = entity.resolve('Boston Brokerage Group', probes)
        self.assertIsNone(ident['legal_name'])
        match = next(c for c in ident['candidates'] if c.get('registration_number') == 'OC401309')
        self.assertEqual(match['jurisdiction'], 'gb')
        self.assertIn('opencorporates', match['origins'])
        self.assertIn('Dissolved', ';'.join(match['why']))

    def test_russian_name_is_not_split_into_fake_pao_company(self):
        targets = recipes.detect_targets('компания ПАО «Магнит», ИНН 2309085638, сайт magnit.com')
        self.assertEqual(len([t for t in targets if t['type'] == 'company']), 1)
        self.assertEqual(entity._norm(COMPANY['НаимПолн']), entity._norm('ПАО «Магнит»'))

    def test_exact_inn_probe_identifies_and_preserves_registry_card(self):
        specs = entity.probe_specs('ПАО «Магнит»', 'ИНН 2309085638')
        self.assertIn(('checko', 'get_company', {'inn': '2309085638'}), specs)
        row = checko(COMPANY)
        ident = entity.resolve('ПАО «Магнит»', entity.parse_probes([row]), ['magnit.com'])
        self.assertEqual((ident['inn'], ident['ogrn'], ident['jurisdiction']),
                         ('2309085638', '1032304945947', 'RU'))
        data = dossier.extract_company_data([row], ident)
        self.assertEqual(data['checko']['inn'], '2309085638')
        md = '\n'.join(sections.render_target('company', {**data, 'identity': ident}))
        self.assertIn('2309085638', md)
        self.assertIn('1032304945947', md)

    def test_registry_address_and_director_are_used_consistently(self):
        row = checko({**COMPANY, 'ЮрАдрес': {'АдресРФ': 'Краснодар, ул. Солнечная, 15'},
                      'Руковод': [{'ФИО': 'Пример Руководителя'}]})
        ident = {'inn': COMPANY['ИНН'], 'legal_name': COMPANY['НаимСокр']}
        data = dossier.extract_company_data([row], ident)
        self.assertEqual(data['checko']['address'], 'Краснодар, ул. Солнечная, 15')
        data['_failed'] = [{'tool': 'opencorporates_officers', 'reason': 'HTTP 403'}]
        self.assertEqual(sections._c_officers(data, {}), [])
        facts = dossier.company_data_for_llm(COMPANY['НаимСокр'], data, [], ident)
        self.assertEqual(facts['registry_director'], 'Пример Руководителя')
        self.assertIsNone(facts['opencorporates_officers_count'])

    def test_russian_financials_keep_rubles_years_and_entity_scope(self):
        payload = {'company': COMPANY, 'data': {
            '2024': {'2110': 412062000, '2400': -2000, '1600': 300000000000},
            '2025': {'2110': 0, '2400': 5354640000}},
            'bo.nalog.ru': {'Отчет': {'2025': 'https://bo.nalog.gov.ru/download/bfo/pdf/123'}}}
        ident = {'inn': COMPANY['ИНН']}
        fin = dossier._checko_financials(json.dumps(payload), ident)
        self.assertEqual(fin['years'], ['2025', '2024'])
        self.assertEqual(fin['metrics']['Выручка'], {'2025': 0, '2024': 412062000})
        self.assertEqual(fin['metrics']['Чистая прибыль (убыток)']['2024'], -2000)
        self.assertIsNone(dossier._checko_financials(json.dumps(payload), {'inn': '1234567890'}))
        row = dict(server='checko', tool='get_finances', ok=True, text=json.dumps(payload))
        data = dossier.extract_company_data([checko(COMPANY), row], ident)
        self.assertEqual(data['checko']['inn'], COMPANY['ИНН'])
        md = '\n'.join(sections._c_financials(data, {}))
        self.assertIn('РСБУ', md)
        self.assertIn('консолидированная', md)
        self.assertIn('412.1 млн', md)
        self.assertNotIn('CIK None', md)
        rendered = '\n'.join(sections.render_target('company', data,
            {'comments': {'c_financials': 'Выручка 412 млрд RUB — ошибочный пересказ'}}))
        self.assertNotIn('ошибочный пересказ', rendered)
        self.assertIn('412.1 млн', rendered)

    def test_wrong_inn_response_is_rejected(self):
        row = checko({**COMPANY, 'ИНН': '7707083893'})
        self.assertIsNone(entity.parse_probes([row])['checko'])

    def test_name_search_requires_one_exact_match(self):
        other = {**COMPANY, 'ИНН': '1234567890', 'НаимСокр': 'ООО "Другая компания"'}
        row = checko({'Записи': [other, COMPANY]}, 'search', {'query': 'ПАО «Магнит»'})
        self.assertEqual(entity.parse_probes([row])['checko']['inn'], COMPANY['ИНН'])
        row = checko({'Записи': [COMPANY, {**COMPANY, 'ИНН': '1234567890'}]}, 'search', {'query': 'ПАО «Магнит»'})
        self.assertIsNone(entity.parse_probes([row])['checko'])

    def test_unrelated_wikipedia_does_not_reach_company_report(self):
        wiki = {'title': 'Палеомагнитный экскурс Лашамп', 'extract': 'Палеомагнитное событие.'}
        self.assertFalse(entity._wiki_supports({'name': 'ПАО «Магнит»'}, wiki))
        row = dict(server='directapi', tool='wikipedia_summary', ok=True, text=json.dumps(wiki))
        data = dossier.extract_company_data([row], {'legal_name': 'ПАО «Магнит»'})
        self.assertIsNone(data['wikipedia'])

    def test_foreign_cik_does_not_leak_into_russian_winner(self):
        probes = entity.parse_probes([checko(COMPANY)])
        probes['sec'] = {'name': 'Unrelated Corp', 'cik': '0000000001', 'state_of_incorporation': 'DE'}
        probes['wikipedia'] = {'title': 'Магнит', 'extract': 'Магнит — российская компания.'}
        ident = entity.resolve('ПАО «Магнит»', probes)
        self.assertEqual(ident['inn'], COMPANY['ИНН'])
        self.assertIsNone(ident['cik'])

    def test_country_routes_and_cik_are_used(self):
        ru = recipes.deep_company_steps('ПАО «Магнит»', {'jurisdiction': 'RU', 'inn': COMPANY['ИНН']})
        self.assertIn(('checko', 'get_company', {'inn': COMPANY['ИНН']}), ru)
        self.assertIn(('checko', 'get_finances', {'inn': COMPANY['ИНН']}), ru)
        self.assertFalse(any(t in ('sec_edgar', 'sec_financials', 'uk_companies_house', 'borme_publications') for _, t, _ in ru))
        us = recipes.deep_company_steps('Example Corporation', {'jurisdiction': 'US-WA', 'cik': '0000789019'})
        self.assertIn(('directapi', 'sec_financials', {'query': '0000789019'}), us)
        self.assertFalse(any(s == 'checko' or t in ('borme_publications', 'uk_companies_house') for s, t, _ in us))
        es = recipes.deep_company_steps('Example SA', {'jurisdiction': 'ES'})
        self.assertTrue(any(t == 'borme_publications' for _, t, _ in es))


if __name__ == '__main__':
    unittest.main()
