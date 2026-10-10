"""Общий кэш двух WHOIS-обёрток сохраняет записи и не скрывает живой WHOIS."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, directory):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'servers' / directory / 'server.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WHOIS = load('whois_cache_integration', 'whoisxml')
DIRECT = load('direct_cache_integration', 'directapi')
SECRET = 'test-account-key-for-cache-integration'
BODY = {'recordsCount': 24, 'records': [
    {'domainName': 'example.com', 'registrantContact': {'organization': f'Organization {index}'},
     'audit': {'createdDate': f'2026-09-{index + 1:02d}T00:00:00Z'}} for index in range(24)]}


class WhoisCacheIntegration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = patch.dict(os.environ, {'WHOIS_HISTORY_CACHE_DIR': self.directory.name,
                                     'WHOIS_HISTORY_CACHE_TTL_SECONDS': '86400'})
        env.start()
        self.addCleanup(env.stop)
        for module in (WHOIS, DIRECT):
            for name, value in (('WHOISXML_KEY', SECRET), ('WHOXY_KEY', '')):
                setting = patch.object(module, name, value)
                setting.start()
                self.addCleanup(setting.stop)

    async def test_aliases_share_all_records_and_original_fetch_date(self):
        primary = AsyncMock(return_value=(BODY, None))
        alias = AsyncMock(side_effect=AssertionError('Duplicate paid history lookup'))
        with patch.object(WHOIS, '_get_json', primary), patch.object(DIRECT, '_get_json', alias):
            first = json.loads(await WHOIS.whois_history('EXAMPLE.COM.'))
            second = json.loads(await DIRECT.whois_history('example.com'))
            third = json.loads(await WHOIS.whois_history('example.com'))
        primary.assert_awaited_once()
        alias.assert_not_awaited()
        self.assertEqual(first['records'], second['records'])
        self.assertEqual(first['records_count'], 24)
        self.assertEqual(third['records_count'], 24)
        self.assertEqual(first['cache']['status'], 'miss')
        self.assertEqual(second['cache']['status'], 'hit')
        self.assertEqual(third['cache']['fetched_at'], first['cache']['fetched_at'])
        self.assertEqual(primary.await_args.kwargs['params']['domainName'], 'example.com')

    async def test_force_refresh_replaces_shared_history(self):
        revised = {'recordsCount': 25, 'records': BODY['records'] + [{'domainName': 'example.com'}]}
        with patch.object(WHOIS, '_get_json', AsyncMock(return_value=(BODY, None))):
            await WHOIS.whois_history('example.com')
        fetch = AsyncMock(return_value=(revised, None))
        with patch.object(DIRECT, '_get_json', fetch):
            updated = json.loads(await DIRECT.whois_history('example.com', force_refresh=True))
        fetch.assert_awaited_once()
        self.assertEqual(updated['cache']['status'], 'refresh')
        with patch.object(WHOIS, '_get_json', AsyncMock(side_effect=AssertionError('Should reuse refreshed history'))):
            reused = json.loads(await WHOIS.whois_history('example.com'))
        self.assertEqual(reused['records'], updated['records'])
        self.assertEqual(reused['records_count'], 25)

    async def test_history_cache_does_not_cache_current_whois(self):
        current = {'WhoisRecord': {'domainName': 'example.com', 'domainAvailability': 'AVAILABLE',
                                    'dataError': 'MISSING_WHOIS_DATA'}}
        with patch.object(WHOIS, '_get_json', AsyncMock(return_value=(BODY, None))):
            await WHOIS.whois_history('example.com')
        fetch = AsyncMock(return_value=(current, None))
        with patch.object(WHOIS, '_get_json', fetch):
            first = json.loads(await WHOIS.whois_current('example.com'))
            second = json.loads(await WHOIS.whois_current('example.com'))
        self.assertEqual(fetch.await_count, 2)
        self.assertEqual(first['domainAvailability'], 'AVAILABLE')
        self.assertEqual(second['dataError'], 'MISSING_WHOIS_DATA')
        self.assertNotIn('cache', second)

    async def test_invalid_domain_does_not_spend_credits(self):
        for module in (WHOIS, DIRECT):
            fetch = AsyncMock()
            with patch.object(module, '_get_json', fetch):
                result = json.loads(await module.whois_history('not a domain'))
            self.assertEqual(result['error_type'], 'invalid_input')
            fetch.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
