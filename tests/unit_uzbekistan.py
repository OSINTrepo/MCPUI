"""Проверки карточек Узбекистана на синтетических организациях, без сети."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'directapi'))
import uzbekistan as U

URL = 'https://orginfo.uz/ru/organization/abcdef1234/'
HTML = """<html><p>ИНН</p><p>999999999</p>
<h2>Официальное название организации</h2><p>"EXAMPLE TECH" mas`uliyati cheklangan jamiyati</p>
<p>Краткое название организации</p><p>ООО "EXAMPLE TECH"</p>
<p>ИНН</p><p>123456789</p><p>Дата регистрации</p><p>06.04.2023</p>
<p>ОКЭД</p><p>62090 -</p><p>Информационные технологии</p>
<p>Уставный фонд</p><p>1 000,00 UZS</p>
<p>Адрес</p><p>Toshkent</p><p>MINOR MFY, 1-UY</p>
<p>Руководитель</p><p>EXAMPLE DIRECTOR</p>
<h2>Учредители</h2><p>EXAMPLE OWNER</p><p>100.00 %</p>
<p>Внимание</p><p>Приведенная выше информация актуальна на 01.09.2026</p>
<p>Похожие организации</p><p>ИНН</p><p>987654321</p></html>"""


class UzbekTests(unittest.TestCase):
    def test_card_is_scoped_to_company_not_login_form_or_neighbours(self):
        card = U.parse_card(HTML, URL)
        self.assertEqual(card['tax_id'], '123456789')
        self.assertEqual(card['director'], 'EXAMPLE DIRECTOR')
        self.assertEqual(card['founders'], [{'name': 'EXAMPLE OWNER', 'share_percent': 100.0}])
        self.assertEqual(card['source_dates'], ['01.09.2026'])
        self.assertIn('Информационные технологии', card['activity'])
        self.assertIn('MINOR MFY', card['address'])
        self.assertEqual(card['source_kind'], 'commercial_directory')

    def test_no_facts_from_snippet_captcha_or_wrong_identifier(self):
        self.assertIsNone(U.parse_card('<h1>Just a moment</h1>', URL))
        self.assertIsNone(U.parse_card(HTML.replace('123456789', '1234567890'), URL))
        self.assertIsNone(U.parse_card(HTML, 'https://evil.example/ru/organization/abcdef1234'))
        self.assertFalse(U.allowed('https://orginfo.uz.evil.example/ru/organization/abcdef1234'))
        self.assertFalse(U.allowed('https://orginfo.uz@127.0.0.1/ru/organization/abcdef1234'))
        self.assertFalse(U.allowed('http://orginfo.uz/ru/organization/abcdef1234'))

    def test_language_versions_canonicalize_only_allowed_hosts_and_card_paths(self):
        self.assertEqual(U.canonical_url('https://myorg.uz/en/company/uz/1234'),
                         'https://myorg.uz/ru/company/uz/1234')
        self.assertEqual(U.canonical_url('https://orginfo.uz/uz/organization/abcd/'),
                         'https://orginfo.uz/ru/organization/abcd/')
        self.assertEqual(U.canonical_url('https://myorg.uz.evil.example/en/company/uz/1234'), '')
        self.assertEqual(U.canonical_url('https://myorg.uz/en/login'), '')

    def test_exact_name_and_tax_id_without_fuzzy_wrong_entity(self):
        card = U.parse_card(HTML, URL)
        self.assertTrue(U.reconcile([card], 'ООО «Example Tech»')['matched'])
        self.assertTrue(U.reconcile([card], 'Example Tech MChJ')['matched'])
        self.assertFalse(U.reconcile([card], 'Example')['matched'])
        self.assertFalse(U.reconcile([card], 'Example Tech', '987654321')['matched'])
        other = {**card, 'tax_id': '987654321'}
        self.assertFalse(U.reconcile([card, other], 'Example Tech')['matched'])

    def test_conflicts_and_source_dates_survive_without_silent_winner(self):
        card = U.parse_card(HTML, URL)
        other = copy.deepcopy(card)
        other.update(capital='2 000,00 UZS', director='ANOTHER DIRECTOR')
        result = U.reconcile([card, other], 'Example Tech')
        self.assertNotIn('capital', result)
        self.assertNotIn('director', result)
        self.assertEqual(len(result['conflicts']['capital']), 2)
        self.assertFalse(result['official_registry_verified'])
        self.assertEqual(len(result['records']), 2)


if __name__ == '__main__':
    unittest.main()
