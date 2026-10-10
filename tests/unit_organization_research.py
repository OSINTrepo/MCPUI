"""Document-grounded organization facts, namesake filtering and bounded collection."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'servers' / 'orchestrator'))
import organization_research as research

URL = 'https://tochka.fi/about'
TEXT = 'Tochka.fi rf Business ID 3182491-8. Alexandr Foy is the main producer.'


def result(tool, payload, ok=True):
    return {'server': 'directapi', 'tool': tool, 'ok': ok, 'text': json.dumps(payload)}


def claim(**changes):
    value = {'category': 'identity', 'text': 'Сайт сообщает Business ID 3182491-8.',
             'quote': TEXT, 'url': URL}
    value.update(changes)
    return value


class VerifiedFactsTests(unittest.TestCase):
    def test_segmented_pages_retains_literal_bounded_fragments_and_source_metadata(self):
        paragraph = 'Published professional role and documentary evidence. ' * 24
        source = {'url': URL, 'text': TEXT + '\n\n' + paragraph + '\nEnd of source.',
                  'published_at': '2024-03-14', 'document_date': '2024-03-14',
                  'role_periods': ['2025–2027'], 'links': ['https://example.org/']}
        segmented = research.segmented_pages([source])
        self.assertEqual(len(segmented), 1)
        page = segmented[0]
        self.assertEqual(page['url'], URL)
        self.assertEqual(page['published_at'], source['published_at'])
        self.assertEqual(page['document_date'], source['document_date'])
        self.assertEqual(page['role_periods'], source['role_periods'])
        self.assertNotIn('text', page)
        self.assertNotIn('links', page)
        self.assertGreater(len(page['segments']), 3)
        self.assertEqual([part['id'] for part in page['segments']],
                         list(range(1, len(page['segments']) + 1)))
        for fragment in page['segments']:
            self.assertLessEqual(len(fragment['text']), 350)
            self.assertIn(fragment['text'], source['text'])
        self.assertEqual(source['text'], TEXT + '\n\n' + paragraph + '\nEnd of source.')

    def test_grounded_segments_rejects_bad_ids_and_never_moves_fragments_between_urls(self):
        other_url = 'https://provider.example/terms'
        pages = research.segmented_pages([
            {'url': URL, 'text': TEXT},
            {'url': other_url, 'text': 'Published provider terms.\nCommission 25 percent for organisers.'}])
        supported = {**claim(), 'source_ids': [1, 1], 'quote': 'Fabricated model quotation'}
        bad = [{**claim(), 'source_ids': ids} for ids in
               (None, [], '1', [True], [1.0], ['1'], [0], [99], [1, 1, 1, 1])]
        bad += [claim(), {**claim(), 'url': 'https://unknown.example/', 'source_ids': [1]},
                {**claim(), 'source_ids': [2], 'quote': pages[1]['segments'][1]['text']}]
        got = research.grounded_segments({'claims': [supported] + bad}, pages)
        self.assertEqual(len(got['claims']), 1)
        self.assertEqual(got['claims'][0]['quote'], [TEXT])
        self.assertEqual(got['claims'][0]['url'], URL)
        self.assertEqual(research.verified_claims(got, [{'url': URL, 'text': TEXT}]),
                         [claim(quote=[TEXT])])

    def test_quote_original_url_numbers_and_deduplication(self):
        candidates = [claim(), claim(), claim(url='https://another.example/source'),
                      claim(text='Сайт сообщает Business ID 9999999-9.'),
                      claim(quote='This quote does not occur in the target document.'),
                      claim(category='citizenship'), None]
        got = research.verified_claims({'claims': candidates}, [{'url': URL, 'text': TEXT}])
        self.assertEqual(got, [claim()])

    def test_quote_from_other_read_page_cannot_be_moved_to_target_url(self):
        pages = [{'url': URL, 'text': TEXT},
                 {'url': 'https://provider.example/terms', 'text': 'Commission 25 percent for organisers.'}]
        moved = claim(text='Комиссия составляет 25 процентов.', quote=pages[1]['text'])
        self.assertEqual(research.verified_claims({'claims': [moved]}, pages), [])

    def test_joint_event_quote_cannot_justify_meta_claim_that_evidence_is_absent(self):
        quote = 'За акцией стоят Демократическое сообщество русскоязычных в Финляндии и проект Tochka.fi.'
        absent = claim(category='foreign',
            text='Документы не подтверждают гражданство или договорные связи; такие данные отсутствуют.',
            quote=quote)
        self.assertEqual(research.verified_claims({'claims': [absent]},
                                                [{'url': URL, 'text': quote}]), [])

    def test_distinct_literal_quote_fragments_ground_one_fact_without_fabricated_ellipsis(self):
        first = 'Alexandr Foy arrived in Finland in 2012.'
        second = 'He serves as the main producer of Tochka.fi.'
        page = {'url': URL, 'text': first + '\nA separate intervening paragraph.\n' + second}
        supported = claim(category='people', text='Источник указывает приезд Foy в 2012 году и роль главного продюсера.',
                          quote=[first, second])
        fabricated = claim(category='people', text=supported['text'],
                           quote='Alexandr Foy arrived in Finland in 2012 ... He serves as the main producer of Tochka.fi.')
        wrong_part = claim(category='people', text=supported['text'],
                           quote=[first, 'He owns the target association and all its contracts.'])
        self.assertEqual(research.verified_claims({'claims': [supported, fabricated, wrong_part]},
                                                [page]), [supported])

    def test_numbers_must_occur_in_fragments_and_fragment_count_is_bounded(self):
        first = 'Alexandr Foy arrived in Finland in 2012.'
        second = 'He serves as the main producer of Tochka.fi.'
        page = {'url': URL, 'text': first + '\n' + second}
        wrong_year = claim(text='Источник указывает приезд в 2024 году.', quote=[first, second])
        excessive = claim(text='Источник указывает приезд в 2012 году.', quote=[first, second, first, second])
        self.assertEqual(research.verified_claims({'claims': [wrong_year, excessive]}, [page]), [])

    def test_whitespace_punctuation_and_cyrillic_requirement(self):
        supported = claim(quote='Tochka.fi rf\nBusiness ID 3182491-8. Alexandr Foy is the main producer.')
        english_only = claim(text='The business ID is 3182491-8.')
        self.assertEqual(research.verified_claims({'claims': [supported, english_only]},
                                                [{'url': URL, 'text': TEXT}]), [supported])

    def test_namesake_bank_and_domain_suffix_are_not_target(self):
        for text in ('Банк Точка, Tochka Bank, financial services in Russia',
                     'Tochka employees at https://tochka.ru',
                     'https://tochka.fi.evil.example is a different host',
                     'support@not-tochka.fi.example'):
            self.assertFalse(research.relevant(text, 'Tochka.fi rf', ['tochka.fi']), text)
        self.assertTrue(research.relevant('Tochka.fi rf is an association', 'Tochka.fi rf', []))
        self.assertTrue(research.relevant('Write to info@tochka.fi', 'Tochka.fi rf', ['tochka.fi']))
        self.assertFalse(research.relevant('Tochka Bank', 'Tochka', []))

    def test_requested_work_triggers_both_languages_without_every_company_lookup(self):
        for task in ('Проверить сотрудников и договоры', 'Источники финансирования и гранты',
                     'Links to foreign organizations', 'Company employees and contracts',
                     'Find the main employee and signed contract', 'Участники из России'):
            with self.subTest(task=task):
                self.assertTrue(research.requested(task))
        for task in ('', 'Generate a company report', 'Find DNS records for example.fi'):
            self.assertFalse(research.requested(task), task)

    def test_render_preserves_dates_and_does_not_turn_missing_evidence_into_absence(self):
        page = {'url': URL, 'title': 'Tochka | Legal', 'published_at': '2024-03-14',
                'retrieved_at': '2026-10-08T00:00:00Z', 'method': 'HTTP / HTML', 'truncated': True}
        text = '\n'.join(research.render({research.PHASE: {'pages': [page], 'claims': [claim()],
                                                        'failures': [{'reason': 'HTTPError'}]}}))
        for value in ('2024-03-14', '2026-10-08T00:00:00Z', 'текст ограничен',
                      'не устанавливает отсутствие', 'сниппеты не считаются'):
            self.assertIn(value, text)
        self.assertIn('Tochka &#124; Legal', text)

    def test_summary_input_keeps_source_date_for_historical_roles(self):
        historical = claim(category='people', text='Документ называет Foy председателем ассоциации.')
        source = {'claims': [historical], 'pages': [{'url': URL, 'text': TEXT,
                  'published_at': '2024-03-14', 'retrieved_at': '2026-10-08T00:00:00Z'}]}
        payload = research.facts_for_llm(source)
        self.assertIn('2024-03-14', json.dumps(payload, ensure_ascii=False))
        self.assertEqual(source['claims'], [historical])


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_malformed_batch_keeps_other_grounded_facts_and_bounds_concurrency(self):
        pages = [{'url': f'https://tochka.fi/source/{n}', 'text': TEXT} for n in range(9)]
        initial = [result('corporate_website', {'pages': pages})]
        active, peak = 0, 0
        sizes = []

        async def call(server, tool, args):
            return result(tool, {'results': []})

        async def extract(batch):
            nonlocal active, peak
            sizes.append(len(batch))
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(0.01)
                if any(page['url'].endswith('/4') for page in batch):
                    return {}  # Invalid/truncated structured response in only one batch.
                return {'claims': [claim(url=page['url']) for page in batch]}
            finally:
                active -= 1

        out = await research.collect('Сотрудники', 'Tochka.fi rf', [], initial, call, extract,
                                     deadline=5, max_calls=5)
        self.assertEqual(len(out['pages']), len(pages))
        self.assertGreater(len(out['claims']), 0)
        self.assertLess(len(out['claims']), len(pages))
        self.assertIn(pages[0]['url'], {row['url'] for row in out['claims']})
        self.assertNotIn(pages[4]['url'], {row['url'] for row in out['claims']})
        self.assertGreater(len(sizes), 1)
        self.assertLessEqual(max(sizes), 4)
        self.assertLessEqual(peak, 2)
        self.assertTrue(any(row.get('tool') == 'focused_fact_extraction' and
                            row.get('reason') == 'ValueError' for row in out['failures']))

    async def test_slow_extraction_is_cancelled_at_collection_deadline(self):
        initial = [result('public_document', {'url': URL, 'text': TEXT})]
        cancelled = asyncio.Event()

        async def call(server, tool, args):
            return result(tool, {'results': []})

        async def extract(pages):
            try:
                await asyncio.sleep(0.2)
                return {'claims': [claim()]}
            finally:
                cancelled.set()

        out = await research.collect('Сотрудники', 'Tochka.fi rf', [], initial, call, extract,
                                     deadline=0.03, max_calls=10)
        self.assertEqual(out['claims'], [])
        self.assertTrue(cancelled.is_set())
        self.assertTrue(out['budget_exhausted'])
        self.assertTrue(any(row.get('tool') == 'focused_fact_extraction' and
                            row.get('reason') == 'TimeoutError' for row in out['failures']))

    async def test_collector_additional_text_limit_is_marked_in_page_provenance(self):
        long_text = TEXT + (' More published target information.' * 1000)
        initial = [result('public_document', {'url': URL, 'text': long_text,
            'truncated': False, 'original_chars': len(long_text),
            'retrieved_at': '2026-10-08T00:00:00Z', 'method': 'HTTP / text'})]

        async def call(server, tool, args):
            return result(tool, {'results': []})

        async def extract(pages):
            return {'claims': []}

        out = await research.collect('Сотрудники', 'Tochka.fi rf', [], initial, call, extract,
                                     deadline=5, max_calls=5)
        page = out['pages'][0]
        self.assertEqual(len(page['text']), 30000)
        self.assertTrue(page['truncated'])
        self.assertEqual(page['original_chars'], len(long_text))
        self.assertEqual(page['text_sha256'], hashlib.sha256(page['text'].encode()).hexdigest())

    async def test_reuses_read_pages_and_never_promotes_search_snippets(self):
        calls, extracted = [], []
        initial = [result('corporate_website', {'pages': [
            {'url': URL, 'title': 'Target', 'text': TEXT,
             'retrieved_at': '2025-01-02T03:04:05Z', 'method': 'saved HTTP'}]}),
            result('public_document', {'url': URL, 'text': 'Duplicate must not overwrite original'})]

        async def call(server, tool, args):
            calls.append((server, tool, args))
            if tool == 'google_cse':
                return result(tool, {'results': [
                    {'link': URL, 'title': 'Tochka.fi', 'snippet': 'Annual grant is 999999 euros.'},
                    {'link': 'https://bank.example/about', 'title': 'Tochka Bank',
                     'snippet': 'A Russian bank with 900 employees.'}]})
            self.fail('Already read target and unrelated bank must not be downloaded')

        async def extract(pages):
            extracted.extend(pages)
            return {'claims': [claim(), claim(category='funding', text='Грант составил 999999 евро.',
                quote='Tochka.fi Annual grant is 999999 euros.')]}

        out = await research.collect('Сотрудники и договоры', 'Tochka.fi rf', ['tochka.fi'],
                                     initial, call, extract, max_calls=10, deadline=5)
        self.assertEqual(len(out['pages']), 1)
        self.assertEqual(out['claims'], [claim()])
        self.assertEqual(extracted[0]['text'], TEXT)
        self.assertEqual(extracted[0]['retrieved_at'], '2025-01-02T03:04:05Z')
        self.assertEqual(extracted[0]['text_sha256'], hashlib.sha256(TEXT.encode()).hexdigest())
        self.assertTrue(all(tool == 'google_cse' for _, tool, _ in calls))
        self.assertTrue(all(row['selected_urls'] == [URL] for row in out['searches']))

    async def test_call_budget_is_shared_by_parallel_seed_reads_and_searches(self):
        calls = []

        async def call(server, tool, args):
            calls.append((server, tool, args))
            return result(tool, {'url': args['url'], 'text': TEXT})

        async def extract(pages):
            return {'claims': []}

        out = await research.collect('Сотрудники', 'Tochka.fi rf', ['tochka.fi'], [], call, extract,
            seed_urls=[f'https://source.example/{n}' for n in range(6)], max_calls=2, deadline=5)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(out['calls']), 2)
        self.assertTrue(out['budget_exhausted'])
        self.assertEqual(len(out['pages']), 2)

    async def test_failed_document_snippet_and_wrong_namesake_reply_are_not_facts(self):
        extracted = []

        async def call(server, tool, args):
            if tool == 'google_cse':
                return result(tool, {'results': [
                    {'link': 'https://news.example/story', 'title': 'Tochka.fi founder',
                     'snippet': 'Search alleges a grant of 90000 euros.'}]})
            return result(tool, {'url': args['url'], 'text': 'Tochka Bank is a financial institution in Russia.'})

        async def extract(pages):
            extracted.append(pages)
            self.fail('Irrelevant full document must not reach extraction')

        out = await research.collect('Сотрудники', 'Tochka.fi rf', ['tochka.fi'], [], call, extract,
                                     deadline=5, max_calls=10)
        self.assertEqual(out['pages'], [])
        self.assertEqual(out['claims'], [])
        self.assertEqual(extracted, [])

    async def test_unsafe_seed_and_interactive_registry_are_not_called(self):
        calls = []

        async def call(server, tool, args):
            calls.append((server, tool, args))
            return result(tool, {'results': []})

        async def extract(pages):
            self.fail('No public pages available')

        out = await research.collect('Сотрудники', 'Tochka.fi rf', [], [], call, extract,
            seed_urls=['http://127.0.0.1/admin', 'https://user:secret@public.example/',
                       'https://yhdistysrekisteri.prh.fi/'], deadline=5)
        self.assertTrue(all(tool == 'google_cse' for _, tool, _ in calls))
        self.assertEqual(out['pages'], [])
        self.assertTrue(any('реестр' in row['reason'] for row in out['failures']))


if __name__ == '__main__':
    unittest.main()
