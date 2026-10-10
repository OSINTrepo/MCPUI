"""Регрессии живого теста: страны, реквизиты, даты, счётчики и атрибуция."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'servers' / 'orchestrator'))
import dossier as D
import entity
import recipes
import sections

UZ = {'matched': True, 'jurisdiction': 'UZ', 'tax_id': '123456789',
      'name': 'ООО "EXAMPLE TECH"', 'director': 'EXAMPLE DIRECTOR',
      'registration_number': '1000001', 'source_kind': 'commercial_directory',
      'records': [{'name': 'EXAMPLE TECH', 'tax_id': '123456789',
                   'director': 'EXAMPLE DIRECTOR', 'capital': '1000 UZS',
                   'founders': [{'name': 'EXAMPLE OWNER', 'share_percent': 100}],
                   'source_url': 'https://orginfo.uz/ru/organization/abcdef/',
                   'source_dates': ['01.09.2026']}],
      'conflicts': {'capital': ['1000 UZS', '1050 UZS']}}


class ReportConsistencyTests(unittest.TestCase):
    def test_unconfirmed_domain_identity_excludes_namesake_brands(self):
        terms = D._cse_terms({'query': 'Tochka.fi rf', 'legal_name': None,
                             'domains': ['tochka.fi']}, 'Tochka.fi rf')
        for item in ({'title': 'Tochka Bank and QIWI partnership', 'link': 'https://news.example/tochka'},
                     {'title': 'Tochka Opory', 'snippet': 'Company in Russia'},
                     {'title': 'tochka.fi.evil.example', 'link': 'https://tochka.fi.evil.example'}):
            self.assertFalse(D._cse_relevant(item, terms))
        self.assertTrue(D._cse_relevant({'title': 'Tochka.fi rf — events', 'link': 'https://tochka.fi/events'}, terms))
        self.assertTrue(D._cse_relevant({'title': 'Association', 'snippet': 'Contact info@tochka.fi'}, terms))

    def test_cached_history_keeps_provider_fetch_date_in_report_and_narrative(self):
        cache = {"status": "hit", "fetched_at": "2026-10-02T04:00:00+00:00",
                 "expires_at": "2026-10-09T04:00:00+00:00", "age_seconds": 86400,
                 "ttl_seconds": 604800}
        row = {"server": "whoisxml", "tool": "whois_history", "ok": True,
               "args": {"domain": "example.com"}, "retrieved_at": "2026-10-03T04:00:00+00:00",
               "text": json.dumps({"domain": "example.com", "source": "whoisxml",
                                   "cache": cache, "records": [{"registrant": "Historic organization",
                                                               "audit": {"createdDate": "2021-01-01"}}]})}
        data = D.extract_domain_data([row])
        source = data["whois_history_sources"][0]
        self.assertEqual(source["cache"], cache)
        self.assertEqual(source["response_returned_at"], row["retrieved_at"])
        facts = D.whois_history_facts(data)
        self.assertEqual(facts["sources"], data["whois_history_sources"])
        self.assertIn("не означает новый запрос источника", facts["scope"])
        md = "\n".join(sections._whois_history(data, {}))
        self.assertIn("2026-10-02 04:00:00 UTC", md)
        self.assertIn("повторного запроса истории не было", md)
        self.assertNotIn("2026-10-03", md)
        self.assertIn("2021-01-01", md)

    def test_duplicate_history_sources_keep_provenance_without_duplicate_records(self):
        record = {"registrant": "Historic organization", "audit": {"createdDate": "2021-01-01"}}
        rows = []
        for server in ("directapi", "whoisxml", "whoisxml"):
            rows.append({"server": server, "tool": "whois_history", "ok": True,
                         "args": {"domain": "example.com"},
                         "text": json.dumps({"domain": "example.com", "source": "whoisxml",
                            "cache": {"status": "hit", "fetched_at": "2026-10-02T04:00:00Z"},
                            "records": [record]})})
        data = D.extract_domain_data(rows)
        self.assertEqual(data["whois_history"], [record])
        self.assertEqual(len(data["whois_history_sources"]), 2)
        self.assertEqual(len(data["_sources"]["whois_history"]), 2)
        md = "\n".join(sections._whois_history(data, {}))
        self.assertEqual(md.count("История получена у источника whoisxml:"), 1)

    def test_history_preserves_received_duplicates_but_does_not_duplicate_alias_payload(self):
        record = {"registrant": "Historic organization", "audit": {"createdDate": "2021-01-01"}}
        payload = {"domain": "example.com", "source": "whoisxml", "records": [record, dict(record)],
                   "cache": {"status": "hit", "fetched_at": "2026-10-02T04:00:00Z"}}
        rows = [{"server": server, "tool": "whois_history", "ok": True,
                 "args": {"domain": "example.com"}, "text": json.dumps(payload)}
                for server in ("whoisxml", "directapi")]
        for results in (rows[:1], rows):
            data = D.extract_domain_data(results)
            self.assertEqual(len(data["whois_history"]), 2)
            self.assertEqual(D.whois_history_facts(data)["records_count"], 2)
            self.assertTrue(all(source["records_count"] == 2 for source in data["whois_history_sources"]))
            md = "\n".join(sections._whois_history(data, {}))
            self.assertIn("Получено исторических записей: 2; показано после удаления одинаковых нормализованных записей: 1.", md)
        self.assertEqual(len(data["whois_history_sources"]), 2)

    def test_history_rejects_wrong_domain_response_and_does_not_invent_fetch_date(self):
        for server in ("directapi", "whoisxml"):
            row = {"server": server, "tool": "whois_history", "ok": True,
                   "args": {"domain": "example.com"}, "retrieved_at": "2026-10-03T04:00:00Z",
                   "text": json.dumps({"domain": "other.example", "source": "whoisxml",
                                       "records": [{"registrant": "Other organization"}]})}
            data = D.extract_domain_data([row])
            self.assertFalse(data["whois_history"])
            self.assertFalse(data["whois_history_sources"])
            row["text"] = json.dumps({"domain": "example.com", "source": "whoisxml",
                                       "records": [{"registrant": "Historic organization"}]})
            data = D.extract_domain_data([row])
            self.assertEqual(data["whois_history_sources"][0]["cache"], {})
            self.assertNotIn("История получена у источника", "\n".join(sections._whois_history(data, {})))

    def test_unicode_history_request_accepts_equivalent_idna_domain_only(self):
        domain = "пример.рф"
        ascii_domain = domain.encode("idna").decode("ascii")
        record = {"registrant": "Historic organization", "audit": {"createdDate": "2021-01-01"}}
        for server in ("directapi", "whoisxml"):
            row = {"server": server, "tool": "whois_history", "ok": True,
                   "args": {"domain": domain.upper() + "."},
                   "text": json.dumps({"domain": ascii_domain, "source": "whoisxml",
                                       "records": [record]})}
            data = D.extract_domain_data([row])
            self.assertEqual(data["whois_history"], [record])
            self.assertEqual(data["whois_history_sources"][0]["domain"], ascii_domain)
            row["text"] = json.dumps({"domain": "other.example", "source": "whoisxml",
                                       "records": [record]})
            data = D.extract_domain_data([row])
            self.assertFalse(data["whois_history"])
            self.assertFalse(data["whois_history_sources"])

    def test_unavailable_history_provenance_does_not_create_evidence(self):
        row = {"server": "whoisxml", "tool": "whois_history", "ok": False,
               "args": {"domain": "example.com"},
               "text": json.dumps({"domain": "example.com", "error": "credits_insufficient",
                                   "cache": {"status": "unavailable"}})}
        data = D.extract_domain_data([row])
        self.assertEqual(data["whois_history_sources"][0]["cache"]["status"], "unavailable")
        self.assertFalse(data["whois_history"])
        self.assertIsNone(D.whois_history_facts(data))

    def test_current_whois_stays_independent_of_cached_history(self):
        rows = [{"server": "whoisxml", "tool": "whois_current", "ok": True,
                 "retrieved_at": "2026-10-03T04:00:00Z",
                 "text": json.dumps({"domain": "example.com", "registrant": "Current organization",
                                     "updatedDate": "2026-10-03", "createdDate": "2026-10-01"})},
                {"server": "whoisxml", "tool": "whois_history", "ok": True,
                 "text": json.dumps({"domain": "example.com", "source": "whoisxml",
                     "cache": {"status": "hit", "fetched_at": "2026-10-02T04:00:00Z"},
                     "records": [{"registrant": "Historical organization", "createdDate": "2000-01-01"}]})}]
        data = D.extract_domain_data(rows)
        self.assertEqual(data["whois"]["registrant"], "Current organization")
        self.assertEqual(data["whois"]["registration"], "2026-10-01")
        self.assertEqual(data["whois"]["last_changed"], "2026-10-03")
        self.assertIn("2000-01-01", "\n".join(sections._whois_history(data, {})))
        self.assertNotIn("2000-01-01", "\n".join(sections._whois(data, {})))

    def test_history_table_keeps_distinct_registrants_expiries_and_snapshots(self):
        base = {"createdDate": "2000-01-01", "updatedDate": "2010-01-01",
                "expiresDate": "2030-01-01", "registrarName": "Example registrar",
                "registrant": "Historical organization", "registrantName": "Historical contact",
                "audit": {"createdDate": "2020-01-01"}}
        rows = [dict(base), {**base, "registrant": "Privacy proxy"},
                {**base, "expiresDate": "2031-01-01"},
                {**base, "audit": {"createdDate": "2021-01-01"}}, dict(base)]
        md = "\n".join(sections._whois_history({"whois_history": rows}, {}))
        self.assertIn("показано после удаления одинаковых нормализованных записей: 4", md)
        self.assertIn("Privacy proxy", md)
        self.assertIn("Historical contact", md)
        self.assertIn("2031-01-01", md)
        self.assertIn("2021-01-01", md)
        self.assertIn("Снимок WHOIS", md)
        self.assertIn("не подтверждает текущего владельца", md)
        self.assertLess(md.index("2020-01-01"), md.index("2021-01-01"))

    def test_history_table_does_not_silently_cap_the_purchased_set(self):
        rows = [{"createdDate": "2000-01-01", "registrarName": "Example registrar",
                 "registrant": f"Organization {index:02d}",
                 "audit": {"createdDate": f"2026-09-{index + 1:02d}"}}
                for index in range(24)]
        md = "\n".join(sections._whois_history({"whois_history": list(reversed(rows))}, {}))
        self.assertIn("показано после удаления одинаковых нормализованных записей: 24", md)
        self.assertIn("Organization 00", md)
        self.assertIn("Organization 23", md)
        self.assertLess(md.index("Organization 00"), md.index("Organization 23"))

    def test_history_section_rejects_unverified_llm_control_change_comment(self):
        data = {"whois_history": [{"domainType": "dropped", "registrant": "Historic organization",
                                  "audit": {"createdDate": "2021-01-01"}}]}
        injected = "Смена контроля доказана: dropped/added означает нового владельца."
        md = "\n".join(sections.render_target("domain", data, {
            "target": "example.com", "comments": {"whois_history": injected}}))
        self.assertNotIn(injected, md)
        self.assertNotIn("**Вывод:**", md)
        self.assertIn("dropped/added не доказывают смену контроля", md)
        self.assertIn("не устанавливают непрерывный период владения", md)

    def test_history_narrative_keeps_oldest_newest_names_and_states_its_limit(self):
        rows = [{"createdDate": "2000-01-01", "registrarName": "Example registrar",
                 "registrant": f"Organization {index:02d}", "registrantName": f"Contact {index:02d}",
                 "registrantOrganization": f"Organization {index:02d}",
                 "audit": {"createdDate": f"2026-09-{index + 1:02d}"}}
                for index in range(30)]
        facts = D.data_for_llm("example.com", {"whois_history": list(reversed(rows))})["whois_history"]
        self.assertEqual(facts["records_count"], 30)
        self.assertEqual(facts["groups_count"], 30)
        self.assertEqual(len(facts["observations"]), 24)
        self.assertEqual(facts["omitted_groups"], 6)
        self.assertEqual(facts["observations"][0]["registrant_name"], "Contact 00")
        self.assertEqual(facts["observations"][-1]["registrant_name"], "Contact 29")
        self.assertIn("не непрерывный период владения", facts["scope"])

    def test_history_narrative_groups_repeated_contact_without_assuming_ownership_period(self):
        base = {"createdDate": "2000-01-01", "registrarName": "Example registrar",
                "registrant": "Historic organization", "registrantName": "Historic contact",
                "registrantOrganization": "Historic organization", "domainType": "added"}
        rows = [{**base, "audit": {"createdDate": "2015-01-01"}, "expiresDate": "2016-01-01"},
                {**base, "audit": {"createdDate": "2020-01-01"}, "expiresDate": "2021-01-01"}]
        facts = D.whois_history_facts({"whois_history": rows})
        self.assertEqual(facts["groups_count"], 1)
        self.assertEqual(facts["observations"][0]["record_count"], 2)
        self.assertEqual(facts["observations"][0]["first_observed"], "2015-01-01")
        self.assertEqual(facts["observations"][0]["last_observed"], "2020-01-01")
        self.assertEqual(facts["observations"][0]["expiry_last"], "2021-01-01")

    def test_whoisxml_current_fallback_maps_dates_status_contacts_and_nameservers(self):
        row = {"server": "whoisxml", "tool": "whois_current", "ok": True,
               "text": json.dumps({"domain": "example.com", "registrarName": "Current registrar",
                "createdDate": "2000-01-01", "updatedDate": "2026-01-01", "expiresDate": "2027-01-01",
                "registrant": "Current organization", "status": "clientTransferProhibited",
                "nameServers": ["ns.example.com"]})}
        data = D.extract_domain_data([row])
        self.assertEqual(data["whois"]["domain_name"], "example.com")
        self.assertEqual(data["whois"]["registration"], "2000-01-01")
        self.assertEqual(data["whois"]["expiration"], "2027-01-01")
        self.assertEqual(data["whois"]["status"], ["clientTransferProhibited"])
        md = "\n".join(sections._whois(data, {}))
        contacts = "\n".join(sections._whois_contacts(data, {}))
        self.assertIn("Current registrar", md)
        self.assertIn("ns.example.com", md)
        self.assertIn("Current organization", contacts)
        self.assertIn("whois_current", md)

    def test_available_current_domain_does_not_inherit_dates_from_history(self):
        rows = [{"server": "whoisxml", "tool": "whois_current", "ok": True,
                 "text": json.dumps({"domain": "example.com", "domainAvailability": "AVAILABLE",
                                     "dataError": "MISSING_WHOIS_DATA"})},
                {"server": "whoisxml", "tool": "whois_history", "ok": True,
                 "text": json.dumps({"records": [{"createdDate": "2000-01-01", "registrant": "Old organization"}]})}]
        data = D.extract_domain_data(rows)
        self.assertIsNone(data["whois"]["registration"])
        self.assertIsNone(data["whois"]["registrant"])
        md = "\n".join(sections._whois(data, {}))
        self.assertIn("AVAILABLE", md)
        self.assertIn("MISSING_WHOIS_DATA", md)
        self.assertIn("доступен для регистрации", md)
        self.assertNotIn("2000-01-01", md)
        self.assertNotIn("Old organization", md)

    def test_explicit_foreign_country_overrides_ooo_in_both_waves(self):
        for country in ('Узбекистан', 'узбекской', 'Казахстан', 'Беларусь', 'Кыргызстан', 'США'):
            task = f'Досье компании ООО «Example Tech», {country}'
            self.assertFalse(recipes.looks_russian('ООО Example Tech', task))
            self.assertFalse(any(s == 'checko' for s, _, _ in entity.probe_specs('ООО Example Tech', task)))
            steps = recipes.deep_company_steps('ООО Example Tech', task=task)
            self.assertFalse(any(s == 'checko' or t == 'uk_companies_house' for s, t, _ in steps))
            if country != 'США':
                self.assertFalse(any(t == 'sec_edgar' for _, t, _ in steps))
        self.assertTrue(recipes.looks_russian('ООО Example Tech', 'Россия'))

    def test_uzbek_probe_accepts_tax_id_and_does_not_add_russian_target(self):
        task = 'ООО «Example Tech», Узбекистан, STIR 123456789'
        self.assertIn(('directapi', 'uz_company_records', {'query': 'ООО Example Tech', 'tax_id': '123456789'}),
                      entity.probe_specs('ООО Example Tech', task))
        self.assertFalse(any(t['type'] == 'inn' for t in recipes.detect_targets(task)))

    def test_uzbek_identity_keeps_directory_provenance_and_rejects_foreign_card(self):
        row = {'server': 'directapi', 'tool': 'uz_company_records', 'ok': True,
               'args': {'query': 'ООО Example Tech'}, 'phase': 'resolve', 'text': json.dumps(UZ)}
        probes = entity.parse_probes([row])
        ident = entity.resolve('ООО Example Tech', probes, ['exampletech.uz'], country='UZ')
        self.assertEqual(ident['inn'], '123456789')
        self.assertEqual(ident['registration_number'], '1000001')
        self.assertEqual(ident['jurisdiction'], 'UZ')
        self.assertEqual(ident['confidence'], 'средняя')
        self.assertTrue(ident['directory_verified'])
        self.assertEqual(ident["confirms"], 1)
        combined = {**probes, "checko": {"name": 'ООО "EXAMPLE TECH"', "inn": "9999999999"}}
        scoped = entity.resolve("Example Tech", combined, country="UZ")
        self.assertEqual(scoped["inn"], "123456789")
        self.assertEqual(sum(bool(c["chosen"]) for c in scoped["candidates"]), 1)
        data = D.extract_company_data([row], ident)
        md = '\n'.join(sections.render_target('company', data, {'identity': ident}))
        for value in ('EXAMPLE DIRECTOR', 'EXAMPLE OWNER', '1000 UZS', '1050 UZS', '01.09.2026', 'Расхождения'):
            self.assertIn(value, md)
        self.assertIn('Государственная выписка не получена', md)
        self.assertNotIn('uz_directory', D.extract_company_data([row], {'inn': '999999999', 'jurisdiction': 'UZ'}))
        wrong = entity.resolve('ООО Example Tech', {'checko': {'name': 'ООО Example Tech', 'inn': '1234567890'}},
                               ['exampletech.uz'], country='UZ')
        self.assertIsNone(wrong['legal_name'])
        self.assertIsNone(wrong['inn'])

    def test_guessed_domain_is_not_a_registry_identity(self):
        res = entity.resolve('Example Tech', {}, country='UZ')
        self.assertIsNone(res['legal_name'])
        self.assertEqual(res['confirms'], 0)
        self.assertFalse(any('domain' in c['sources'] for c in res['candidates']))

    def test_certificate_status_uses_full_date_and_unknown_is_not_active(self):
        now = datetime(2026, 9, 24, 12, tzinfo=timezone.utc)
        for date in ('8/30/2026', '2026-06-30T23:04:01Z', 'Apr 30 23:00:00 2026 GMT'):
            self.assertEqual(D.cert_status({'valid_until': date}, now), 'expired')
        self.assertEqual(D.cert_status({'valid_until': '10/30/2026'}, now), 'active')
        self.assertEqual(D.cert_status({'valid_until': '9/24/2026'}, now), 'active')
        self.assertEqual(D.cert_status({'valid_until': '2026-09-24T11:59:59Z'}, now), 'expired')
        self.assertEqual(D.cert_status({'valid_until': '2027-01-01', 'valid_from': '2026-12-01'}, now), 'future')
        for date in ('2026', 'invalid', '', None):
            self.assertEqual(D.cert_status({'valid_until': date}, now), 'unknown')
            self.assertFalse(D._cert_active(date))

    def test_tables_and_narrative_share_subdomain_and_certificate_counts(self):
        cert = {'subject': 'example.uz', 'issuer': 'Example CA', 'valid_until': '10/30/2026'}
        data = {'subdomains': {'example.uz', 'dev.example.uz', 'www.example.uz', 'badexample.uz'},
                'certs': [cert, dict(cert)]}
        facts = D.data_for_llm('example.uz', data)
        self.assertEqual(facts['subdomain_count'], 2)
        self.assertEqual(facts['cert_count'], 1)
        md = '\n'.join(sections._subdomains(data, {'target': 'example.uz'}))
        self.assertIn('Поддомены — 2', md)
        self.assertNotIn('badexample.uz', md)

    def test_social_table_filters_unrelated_hits_and_escapes_titles(self):
        data = {'cse': [{'engine': 'social', 'results': [
            {'title': 'Example Tech | Engineer', 'link': 'https://linkedin.com/in/example',
             'snippet': 'Works at Example Tech'},
            {'title': 'Unrelated celebrity', 'link': 'https://facebook.com/groups/unrelated',
             'snippet': 'No connection to target'}]}]}
        md = '\n'.join(sections._cse_social(data, {'target': 'Example Tech'}))
        self.assertIn('linkedin.com/in/example', md)
        self.assertNotIn('facebook.com', md)
        self.assertIn('не подтверждённый список сотрудников', md)
        self.assertNotIn('| Example Tech | Engineer |', md)

    def test_provider_network_is_not_assumed_owned_and_unsafe_comments_suppressed(self):
        self.assertIn('принадлежность компании не установлена', sections._ip_kind('EXAMPLE HOSTING'))
        self.assertEqual(sections._ip_kind('Amazon'), 'AWS')
        data = {'cse': [{'engine': 'web', 'results': [{'title': 'Example Tech', 'link': 'https://example.uz'}]}]}
        md = '\n'.join(sections.render_target('company', data, {'target': 'Example Tech',
                         'comments': {'c_cse': 'Веб-поиск не дал результатов'}}))
        self.assertIn('example.uz', md)
        self.assertNotIn('не дал результатов', md)
        facts = D.company_data_for_llm('Example Tech', {**data, 'uz_directory': UZ}, [])
        self.assertTrue(facts['web_search'][0]['results'])
        self.assertEqual(facts['directory_director'], 'EXAMPLE DIRECTOR')


class CandidateRegistryConsistency(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.identity = {"query": "Example Brand", "legal_name": None, "inn": None,
                         "jurisdiction": None, "domains": ["example.trade"],
                         "confidence": "низкая", "confirms": 0, "candidates": []}
        self.company = {"inn": "7802880793", "identity_verified": True,
            "domain_ownership_verified": False,
            "seed": {"basis": "exact_name_unique_registry_match", "url": "https://news.example.org/history"},
            "card": {"ИНН": "7802880793", "ОГРН": "1147847439080", "НаимПолн": 'ООО "ПРИМЕР"',
                "НаимСокр": 'ООО "ПРИМЕР"', "ДатаРег": "2014-12-12", "ДатаВып": "2026-10-02",
                "Статус": {"Наим": "Недействующая"}, "Ликвид": {"Дата": "2020-11-30"},
                "Руковод": [{"ФИО": "ПРИМЕР РУКОВОДИТЕЛЯ", "ИНН": "123456789012",
                              "НаимДолжн": "ДИРЕКТОР", "ДатаЗаписи": "2014-12-12"}]},
            "checks": {"get_finances": {"status": "received", "response": {"data": {
                "2020": {"2110": {"СумОтч": 0}, "1600": {"СумОтч": 10000}, "2400": {}}}}}}}
        self.research = {"companies": [self.company], "mentions": [], "pages": [],
                         "claims": [{"text": "Источник сообщает о работе Example Brand в 2018 году.",
                                     "quote": "Example Brand operated in 2018.",
                                     "url": "https://news.example.org/history", "snapshot": None}],
                         "calls": [], "failures": []}

    async def test_unresolved_brand_keeps_verified_candidates_in_narrative_and_report(self):
        import server
        observed = {}

        async def write(messages, **kwargs):
            observed.update(json.loads(messages[-1]["content"].split("(JSON):\n", 1)[1]))
            return json.dumps({"summary": "Получена карточка отдельного юридического лица; связь с брендом не установлена."})

        row = {"server": "orchestrator", "tool": "corporate_research", "phase": "corporate_research",
               "ok": True, "text": json.dumps(self.research)}
        with patch.object(server, "section_comments", AsyncMock(return_value={})), patch.object(server, "llm", write):
            md = await server.build_company_dossier("Example Brand", [], [row], self.identity)
        facts = observed["corporate_research"]
        self.assertIsNone(observed["identity"]["legal_name"])
        self.assertEqual(facts["verified_company_count"], 1)
        profile = facts["profiles"][0]
        self.assertEqual(profile["inn"], "7802880793")
        self.assertEqual(profile["name"], 'ООО "ПРИМЕР"')
        self.assertFalse(profile["target_identity_match"])
        self.assertFalse(profile["domain_ownership_verified"])
        self.assertEqual(profile["target_affiliation"], "not_established")
        self.assertEqual(profile["registered_at"], "2014-12-12")
        self.assertEqual(profile["liquidated_at"], "2020-11-30")
        self.assertEqual(profile["officers"][0]["record_date"], "2014-12-12")
        self.assertEqual(profile["financials"][0]["revenue"], 0)
        self.assertNotIn("net_profit", profile["financials"][0])
        self.assertIn("get_finances", profile["available_checks"])
        self.assertEqual(facts["claims"][0]["source_url"], "https://news.example.org/history")
        self.assertNotIn("123456789012", json.dumps(facts))
        self.assertIn("Отдельные реестровые профили", md)
        self.assertIn("Исследованные домены", md)
        self.assertIn("Регистрационные сведения других юрлиц не приписываются самой цели", md)
        self.assertNotIn("Данные реестров ниже не приводятся", md)
        self.assertIn('ПРИМЕР', md)
        self.assertIn("7802880793", md)

    async def test_related_registry_candidate_keeps_role_and_historical_dates(self):
        import server
        self.company["seed"] = {"basis": "registry_related_ogrn", "relationship": {
            "company": "7802537321", "role": "СвязРуковод", "person": "ПРИМЕР РУКОВОДИТЕЛЯ"}}
        self.company["card"]["ДатаРег"] = "2007-01-01"
        self.company["card"]["Ликвид"]["Дата"] = "2013-01-01"
        profile = server._corporate_research_facts(self.research, self.identity)["profiles"][0]
        self.assertEqual(profile["registry_relationship"]["source_company_inn"], "7802537321")
        self.assertEqual(profile["registry_relationship"]["role"], "СвязРуковод")
        self.assertIn("не принадлежность группе", profile["registry_relationship"]["scope"])
        self.assertEqual(profile["liquidated_at"], "2013-01-01")
        self.assertEqual(profile["target_affiliation"], "not_established")

    async def test_unverified_cards_are_not_promoted_to_registry_fact(self):
        import server
        self.company["identity_verified"] = False
        facts = server._corporate_research_facts(self.research, self.identity)
        self.assertEqual(facts["verified_company_count"], 0)
        self.assertEqual(facts["profiles"], [])
        md = "\n".join(sections._c_identity({"identity": self.identity, "corporate_research": facts}, {}))
        self.assertNotIn("Отдельные реестровые профили", md)
        self.assertNotIn("Данные реестров ниже не приводятся", md)


if __name__ == '__main__':
    unittest.main()
