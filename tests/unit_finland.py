"""Finnish registry coverage, exact identity matching and cross-country routing."""
import asyncio
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "servers" / "orchestrator"))
sys.path.insert(0, str(ROOT / "servers" / "directapi"))
import entity
import finland
import recipes
import httpx


COMPANY = {"businessId": {"value": "1234567-1", "registrationDate": "2000-01-02", "source": "1"},
           "names": [{"name": "Example Oy", "type": "1", "version": 1, "source": "1"},
                     {"name": "Old Example Oy", "type": "1", "version": 2, "endDate": "2020-01-01"}],
           "companyForms": [{"type": "OY", "version": 1, "descriptions": [
               {"languageCode": "1", "description": "Osakeyhtiö"},
               {"languageCode": "3", "description": "Limited company"}]}],
           "registrationDate": "2000-02-03", "tradeRegisterStatus": "1", "status": "2",
           "registeredEntries": [{"register": "1", "type": "1", "registrationDate": "2000-02-03"}],
           "addresses": [{"type": 1, "street": "Esimerkkikatu", "buildingNumber": "2", "postCode": "00100",
                          "postOffices": [{"languageCode": "1", "city": "Helsinki"}], "country": "FI"}],
           "website": {"url": "https://example.fi"}, "lastModified": "2026-10-08T00:00:00"}


def registry_row(payload, args=None):
    return {"server": "directapi", "tool": "fi_company_records", "ok": True,
            "args": args or {"query": "Example Oy"}, "text": json.dumps(payload)}


class FinnishRegistryTests(unittest.TestCase):
    def test_business_id_checksum_and_leading_zero(self):
        for value in ("1234567-1", "0112038-9", "3182491-8"):
            self.assertTrue(finland.valid_business_id(value), value)
        for value in ("1234567-8", "0112038-8", "12345671", "123456-1", "abcdefg-1"):
            self.assertFalse(finland.valid_business_id(value), value)

    def test_exact_official_record_preserves_dates_codes_and_provenance(self):
        result = finland.reconcile({"totalResults": 1, "companies": [COMPANY]}, "Example Oy")
        self.assertTrue(result["matched"])
        self.assertTrue(result["official_registry_verified"])
        self.assertEqual(result["registered_at"], "2000-02-03")
        self.assertEqual(result["business_id_registered_at"], "2000-01-02")
        self.assertEqual(result["legal_form"], "Limited company")
        self.assertEqual(result["trade_register_status_code"], "1")
        self.assertEqual(result["source_url"], finland.API + "?businessId=1234567-1")
        self.assertIn("Helsinki", result["addresses"][0]["address"])
        self.assertNotIn("director", result)

    def test_association_is_not_namesake_commercial_company(self):
        result = finland.reconcile({"totalResults": 1, "companies": [COMPANY]}, "Example rf")
        self.assertFalse(result["matched"])
        self.assertNotIn("business_id", result)
        result = finland.reconcile({"totalResults": 0, "companies": []}, "Example rf", "3182491-8")
        self.assertFalse(result["official_registry_verified"])
        self.assertIn("отдельной проверки", result["reason"])
        self.assertIn("не доказывает", result["scope"])
        self.assertEqual(result["manual_verification"][0]["url"], finland.ASSOCIATIONS)

    def test_history_auxiliary_names_and_substrings_do_not_identify_target(self):
        for query in ("Old Example Oy", "Example", "Example Finland Oy"):
            self.assertFalse(finland.reconcile({"companies": [COMPANY]}, query)["matched"])
        row = copy.deepcopy(COMPANY)
        row["names"] = [{"name": "Example Oy", "type": "3", "version": 1}]
        self.assertFalse(finland.reconcile({"companies": [row]}, "Example Oy")["matched"])

    def test_namesakes_and_truncated_results_remain_unconfirmed(self):
        other = copy.deepcopy(COMPANY)
        other["businessId"]["value"] = "0112038-9"
        result = finland.reconcile({"totalResults": 2, "companies": [COMPANY, other]}, "Example Oy")
        self.assertFalse(result["matched"])
        self.assertFalse(finland.reconcile({"totalResults": 101, "companies": [COMPANY]}, "Example Oy")["matched"])
        self.assertTrue(finland.reconcile({"totalResults": 2, "companies": [COMPANY, other]},
                                         "Example Oy", "1234567-1")["matched"])

    def test_wrong_id_is_rejected_even_for_exact_name(self):
        result = finland.reconcile({"companies": [COMPANY]}, "Example Oy", "0112038-9")
        self.assertFalse(result["matched"])

    def test_authenticated_or_paid_sources_are_never_used(self):
        original = httpx.AsyncClient
        calls = []
        def reply(request):
            calls.append(request)
            return httpx.Response(200, json={"totalResults": 0, "companies": []})
        with patch.object(finland.httpx, "AsyncClient", lambda **kwargs: original(
                transport=httpx.MockTransport(reply), **kwargs)):
            result = asyncio.run(finland.collect("Example rf", "3182491-8"))
        self.assertFalse(result["matched"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].url.host, "avoindata.prh.fi")
        self.assertEqual(calls[0].url.params["businessId"], "3182491-8")
        self.assertNotIn("authorization", calls[0].headers)

    def test_provider_failure_and_invalid_id_cannot_be_identity(self):
        original = httpx.AsyncClient
        def reply(request):
            return httpx.Response(503, text="Service unavailable")
        with patch.object(finland.httpx, "AsyncClient", lambda **kwargs: original(
                transport=httpx.MockTransport(reply), **kwargs)):
            result = asyncio.run(finland.collect("Example Oy"))
        self.assertFalse(result["official_registry_verified"])
        self.assertEqual(result["error"], "HTTP 503")
        with patch.object(finland.httpx, "AsyncClient", side_effect=AssertionError("must not fetch")):
            result = asyncio.run(finland.collect("Example Oy", "1234567-8"))
        self.assertFalse(result["matched"])


class FinnishRoutingTests(unittest.TestCase):
    def test_finnish_association_rf_is_not_russia_or_citizenship(self):
        task = "Финляндия. Домен: example.fi. Цель: Example rf"
        self.assertEqual(recipes.country_hint(task), "FI")
        self.assertFalse(recipes.looks_russian("Example rf", task))
        self.assertEqual(entity._norm("Example rf"), "example")
        self.assertEqual(recipes.explicit_company_target("Цель: Example rf. Домен: example.fi"), "Example rf")
        specs = entity.probe_specs("Example rf", task + "; Y-tunnus 3182491-8")
        self.assertIn(("directapi", "fi_company_records", {"query": "Example rf", "business_id": "3182491-8"}), specs)
        self.assertFalse(any(server == "checko" or tool == "sec_edgar" for server, tool, _ in specs))

    def test_russian_connections_focus_does_not_override_finnish_country(self):
        task = ("Цель: Example rf\nФинляндия, Y-tunnus 3182491-8. "
                "Проверить связи с российскими компаниями и гражданами РФ")
        self.assertEqual(recipes.country_hint(task), "FI")
        self.assertFalse(recipes.looks_russian("Example rf", task))
        self.assertEqual(recipes.country_hint("Финляндия и Россия"), "")
        self.assertEqual(recipes.country_hint("example.fi rf"), "")  # Domain/legal form alone is not a country assertion.

    def test_official_exact_match_resolves_finnish_entity_without_russian_inn(self):
        payload = finland.reconcile({"companies": [COMPANY]}, "Example Oy")
        ident = entity.resolve("Example Oy", entity.parse_probes([registry_row(payload)]), ["example.fi"], "FI")
        self.assertEqual(ident["legal_name"], "Example Oy")
        self.assertEqual(ident["business_id"], "1234567-1")
        self.assertEqual(ident["registration_number"], "1234567-1")
        self.assertIsNone(ident["inn"])
        self.assertTrue(ident["official_registry_verified"])
        steps = recipes.deep_company_steps(ident["legal_name"], ident)
        self.assertFalse(any(server == "checko" or tool in ("sec_edgar", "uk_companies_house", "fi_company_records")
                             for server, tool, _ in steps))

    def test_empty_registry_does_not_promote_user_business_id_to_verified(self):
        payload = finland.reconcile({"companies": []}, "Example rf", "3182491-8")
        ident = entity.resolve("Example rf", entity.parse_probes([registry_row(payload,
            {"query": "Example rf", "business_id": "3182491-8"})]), ["example.fi"], "FI")
        self.assertIsNone(ident["legal_name"])
        self.assertIsNone(ident["business_id"])
        self.assertFalse(ident["official_registry_verified"])
        self.assertIn(("directapi", "fi_company_records", {"query": "Example rf", "business_id": "3182491-8"}),
                      recipes.deep_company_steps("Example rf", ident, task="Финляндия, Y-tunnus 3182491-8"))

    def test_entity_rejects_wrong_id_and_association_legal_form(self):
        payload = finland.reconcile({"companies": [COMPANY]}, "Example Oy")
        for args in ({"query": "Example Oy", "business_id": "0112038-9"}, {"query": "Example rf"}):
            self.assertIsNone(entity.parse_probes([registry_row(payload, args)])["fi_registry"])


if __name__ == "__main__":
    unittest.main()
