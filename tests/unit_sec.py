"""SEC: нормализация, неоднозначность, сбои и периоды сравнительной отчётности."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'directapi'))
import server as api


class SECTests(unittest.IsolatedAsyncioTestCase):
    async def test_corporation_matches_corp(self):
        rows = {'0': {'title': 'MICROSOFT CORP', 'cik_str': 789019, 'ticker': 'MSFT'}}
        with patch.object(api, '_get_json', AsyncMock(return_value=(rows, None))):
            self.assertEqual(await api._sec_cik('Microsoft Corporation'), ('0000789019', 'MICROSOFT CORP'))

    async def test_cik_does_not_require_ticker_index(self):
        with patch.object(api, '_get_json', AsyncMock()) as get:
            self.assertEqual((await api._sec_cik('CIK 789019'))[0], '0000789019')
            get.assert_not_called()

    async def test_ambiguity_is_not_first_match(self):
        rows = {'0': {'title': 'Example One Corp', 'cik_str': 1}, '1': {'title': 'Example Two Corp', 'cik_str': 2}}
        with patch.object(api, '_get_json', AsyncMock(return_value=(rows, None))):
            with self.assertRaises(api.SECLookupError):
                await api._sec_cik('Example')

    async def test_http_failure_is_not_absent_company(self):
        with patch.object(api, '_get_json', AsyncMock(return_value=(None, 'HTTP 403'))):
            result = json.loads(await api.sec_edgar('Example'))
            self.assertIn('unavailable', result['error'])
            self.assertIn('403', result['error'])
            self.assertNotIn('не отчитывается', result['error'])

    def test_comparatives_quarters_and_amendments(self):
        rows = [
            dict(form='10-K', fp='FY', fy=2026, start='2024-07-01', end='2025-06-30', val=280, filed='2026-07-30'),
            dict(form='10-K', fp='FY', fy=2026, start='2025-07-01', end='2026-06-30', val=310, filed='2026-07-30'),
            dict(form='10-K', fp='FY', fy=2026, start='2026-04-01', end='2026-06-30', val=90, filed='2026-07-30'),
            dict(form='10-K/A', fp='FY', fy=2026, start='2024-07-01', end='2025-06-30', val=281, filed='2026-08-30'),
        ]
        self.assertEqual(api._annual_xbrl_values({'units': {'USD': rows}}),
                         {'2025-06-30': 281.0, '2026-06-30': 310.0})


if __name__ == '__main__':
    unittest.main()
