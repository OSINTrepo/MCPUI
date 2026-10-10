"""Отказы WHOIS не превращаются в пустые находки или ложное отсутствие ключа."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parent.parent


def load_server(name, directory):
    spec = importlib.util.spec_from_file_location(name, ROOT / "servers" / directory / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WHOIS = load_server("whoisxml_under_test", "whoisxml")
DIRECT = load_server("directapi_whois_under_test", "directapi")
SECRET = "test-secret-api-key"


class WhoisErrors(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Отказы API проверяются без повторного использования результатов соседних тестов.
        self.cache_settings = patch.dict(os.environ, {"WHOIS_HISTORY_CACHE_TTL_SECONDS": "0"})
        self.cache_settings.start()
        self.addCleanup(self.cache_settings.stop)

    async def current(self, body, error=None):
        with patch.object(WHOIS, "WHOISXML_KEY", SECRET), patch.object(WHOIS, "_get_json", AsyncMock(return_value=(body, error))):
            return json.loads(await WHOIS.whois_current("example.com"))

    async def history(self, module, body, error=None):
        with patch.object(module, "WHOISXML_KEY", SECRET), patch.object(module, "WHOXY_KEY", ""), patch.object(module, "_get_json", AsyncMock(return_value=(body, error))):
            return json.loads(await module.whois_history("example.com"))

    async def test_current_api200_quota_error_is_failure_and_hides_key(self):
        body = {"ErrorMessage": {"errorCode": "QUOTA_EXCEEDED", "message": f"Insufficient credits for apiKey={SECRET}"}}
        result = await self.current(body)
        self.assertEqual(result["error_type"], "quota_exhausted")
        self.assertEqual(result["provider_code"], "QUOTA_EXCEEDED")
        self.assertIn("квота", result["error"])
        self.assertNotIn("registrarName", result)
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_current_api200_authentication_error_is_failure(self):
        body = {"ErrorMessage": {"errorCode": "AUTHENTICATION_ERROR", "message": "Invalid API key"}}
        result = await self.current(body)
        self.assertEqual(result["error_type"], "authentication_failed")
        self.assertEqual(result["provider_code"], "AUTHENTICATION_ERROR")
        self.assertIn("ключ", result["error"])

    async def test_history_api200_error_does_not_claim_missing_key(self):
        body = {"code": 402, "messages": [f"Insufficient credits apiKey={SECRET}"]}
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, body)
                self.assertEqual(result["provider_errors"][0]["error_type"], "quota_exhausted")
                self.assertNotIn("нужен ключ", result["error"])
                self.assertNotIn("WHOXY_API_KEY", result["error"])
                self.assertNotIn("records_count", result)
                self.assertNotIn(SECRET, json.dumps(result))

    async def test_history_403_is_ambiguous_access_denial(self):
        body = {"code": 403, "messages": ["Access restricted. Reasons: insufficient credits balance, incorrect API key, or IP not in allowlist"]}
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, body, "HTTP 403")
                failure = result["provider_errors"][0]
                self.assertEqual(failure["error_type"], "access_denied")
                self.assertEqual(failure["http_status"], 403)
                self.assertIn("IP allowlist", result["error"])
                self.assertIn("баланс продукта", result["error"])

    async def test_history_no_records_is_a_successful_lookup(self):
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, {"code": 200, "recordsCount": 0, "records": []})
                self.assertNotIn("error", result)
                self.assertEqual(result["source"], "WhoisXML")
                self.assertEqual(result["records_count"], 0)
                self.assertEqual(result["records"], [])

    async def test_paid_history_keeps_all_snapshots_and_full_registrant_fields(self):
        records = [{
            "domainName": "example.com", "domainType": "updated",
            "createdDateISO8601": "2000-01-01T00:00:00Z",
            "updatedDateISO8601": "2010-01-01T00:00:00Z",
            "expiresDateISO8601": "2030-01-01T00:00:00Z",
            "registrarName": "Example registrar",
            "registrantContact": {"name": f"Contact {index}", "organization": f"Organization {index}"},
            "audit": {"createdDate": f"2026-09-{index + 1:02d} 00:00:00 UTC", "updatedDate": f"2026-09-{index + 1:02d} 01:00:00 UTC"},
            "nameServers": ["ns.example.com"], "status": ["ok"],
        } for index in range(24)]
        normalized = []
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, {"recordsCount": 24, "records": records})
                self.assertEqual(result["records_count"], 24)
                self.assertEqual(len(result["records"]), 24)
                first, last = result["records"][0], result["records"][-1]
                self.assertEqual(first["audit"]["createdDate"], "2026-09-01 00:00:00 UTC")
                self.assertEqual(last["registrant"], "Organization 23")
                self.assertEqual(last["registrantName"], "Contact 23")
                self.assertEqual(last["registrantOrganization"], "Organization 23")
                self.assertEqual(last["expiresDate"], "2030-01-01T00:00:00Z")
                self.assertEqual(last["nameServers"], ["ns.example.com"])
                normalized.append(result["records"])
        self.assertEqual(normalized[0], normalized[1])

    def test_history_normalizer_accepts_legacy_dates_and_malformed_contact(self):
        record = {"createdDate": "2001-01-01", "updatedDateRaw": "2010-01-01",
                  "expiresDateNormalized": "2030-01-01", "registrant": "Legacy organization",
                  "registrantContact": "unparsed", "audit": None}
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                rows = module.normalize_history_records([None, record])
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["createdDate"], "2001-01-01")
                self.assertEqual(rows[0]["registrant"], "Legacy organization")
                self.assertEqual(rows[0]["audit"], {"createdDate": None, "updatedDate": None})

    async def test_history_malformed_response_is_not_empty_success(self):
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, {"unexpected": "payload"})
                self.assertEqual(result["provider_errors"][0]["error_type"], "invalid_response")
                self.assertNotIn("records_count", result)

    async def test_incomplete_paid_history_is_not_cached_as_complete(self):
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                result = await self.history(module, {"recordsCount": 2, "records": [{"domainName": "example.com"}]})
                self.assertEqual(result["provider_errors"][0]["error_type"], "invalid_response")

    async def test_direct_paid_history_disables_automatic_retries(self):
        get = AsyncMock(return_value=({"recordsCount": 0, "records": []}, None))
        with patch.object(DIRECT, "WHOISXML_KEY", SECRET), patch.object(DIRECT, "_get_json", get):
            await DIRECT._wx_whoisxml("example.com")
        self.assertEqual(get.await_args.kwargs["retries"], 0)

    async def test_current_registry_data_fields_and_top_level_dates_are_retained(self):
        body = {"WhoisRecord": {"createdDateNormalized": "2010-01-01 00:00:00 UTC", "registrant": {"name": ""}, "nameServers": {"hostNames": []}, "registryData": {
            "registrarName": "Example registrar", "registrant": {"organization": "Example organization"},
            "updatedDateNormalized": "2025-01-01 00:00:00 UTC", "expiresDate": "2027-01-01",
            "nameServers": {"hostNames": ["ns.example.com"]}, "status": "ok"}}}
        result = await self.current(body)
        self.assertNotIn("error", result)
        self.assertEqual(result["registrarName"], "Example registrar")
        self.assertEqual(result["registrant"], "Example organization")
        self.assertEqual(result["createdDate"], "2010-01-01 00:00:00 UTC")
        self.assertEqual(result["updatedDate"], "2025-01-01 00:00:00 UTC")
        self.assertEqual(result["expiresDate"], "2027-01-01")
        self.assertEqual(result["nameServers"], ["ns.example.com"])
        self.assertEqual(result["status"], "ok")

    async def test_available_domain_without_whois_record_is_not_auth_failure(self):
        body = {"WhoisRecord": {"domainName": "example.com", "dataError": "MISSING_WHOIS_DATA",
            "domainAvailability": "AVAILABLE", "registryData": {"domainName": "example.com",
            "dataError": "MISSING_WHOIS_DATA", "rawText": "", "audit": {}}}}
        result = await self.current(body)
        self.assertNotIn("error", result)
        self.assertEqual(result["domainAvailability"], "AVAILABLE")
        self.assertEqual(result["dataError"], "MISSING_WHOIS_DATA")
        self.assertIsNone(result["registrarName"])
        self.assertEqual(result["nameServers"], [])

    async def test_current_missing_record_shape_is_failure(self):
        result = await self.current({"unexpected": "payload"})
        self.assertEqual(result["error_type"], "invalid_response")

    async def test_fallback_provider_can_return_records_after_primary_failure(self):
        body = {"status": 1, "whois_records": [{"create_date": "2010-01-01", "domain_registrar": {"registrar_name": "Fallback registrar"}}]}
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                get = AsyncMock(side_effect=[({"code": 403, "messages": ["Access restricted"]}, "HTTP 403"), (body, None)])
                with patch.object(module, "WHOISXML_KEY", SECRET), patch.object(module, "WHOXY_KEY", "test-fallback-key"), patch.object(module, "_get_json", get):
                    result = json.loads(await module.whois_history("example.com"))
                self.assertNotIn("error", result)
                self.assertEqual(result["source"], "Whoxy")
                self.assertEqual(result["records_count"], 1)
                self.assertEqual(result["records"][0]["registrarName"], "Fallback registrar")

    async def test_missing_keys_are_classified_without_network_calls(self):
        for module in (WHOIS, DIRECT):
            with self.subTest(module=module.__name__):
                get = AsyncMock()
                with patch.object(module, "WHOISXML_KEY", ""), patch.object(module, "WHOXY_KEY", ""), patch.object(module, "_get_json", get):
                    result = json.loads(await module.whois_history("example.com"))
                self.assertIn("ключ", result["error"])
                self.assertEqual(result["error_type"], "missing_key")
                get.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
