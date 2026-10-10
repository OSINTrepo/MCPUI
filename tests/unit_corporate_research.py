"""Регрессии атрибуции, ограничений обхода и полного корпоративного сбора."""
import asyncio
import json
import os
from pathlib import Path
import sys
import unittest
import tempfile
import hashlib
from datetime import datetime,timezone
from unittest.mock import patch, AsyncMock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'servers'/'orchestrator'))
import corporate_research as C
import dossier
import report
import recipes

INN='7802880793'
NAME='ООО "ПРИМЕР"'


class ResearchTests(unittest.TestCase):
    def test_request_for_domain_owners_is_not_a_company_name(self):
        targets=recipes.detect_targets('Исследуй example.trade и example-russia.trade: найди компании за этими доменами, ИНН')
        self.assertEqual([t['value'] for t in targets if t['type']=='domain'],['example.trade','example-russia.trade'])
        self.assertFalse(any(t['type']=='company' for t in targets))

    def test_search_description_is_used_for_relevance(self):
        result=C.search_items({'text':json.dumps({'organic':[{'link':'https://example.org/article','title':'Для инвесторов','description':'Example Holdings registry'}]})})
        self.assertIn('Example Holdings',result[0]['text'])

    def test_domain_is_not_a_similarly_named_brand_and_industry_conflict_is_rejected(self):
        self.assertFalse(C.relevant_hit({'text':'Example Trade LLC'},['example.trade']))
        self.assertTrue(C.relevant_hit({'text':'Email support@example.trade'},['example.trade']))
        self.assertFalse(C.relevant_hit({'text':'Example Group real estate rentals'},['Example Group'],'Forex traders, forex, forex'))

    def test_listing_does_not_attribute_unrelated_companies(self):
        p=C.page_record('https://news.example.org/','ООО «Другое» [Example Group](https://news.example.org/company)')
        self.assertEqual(C.article_links(p,['Example Group']),['https://news.example.org/company'])
        p['is_listing']=True
        self.assertEqual(C.mentions([p]),[])
    def test_identifiers_are_not_phones_or_invalid_checksum(self):
        self.assertTrue(C.valid_inn(INN))
        for s in ('0000000000','1234567890','890309918532','+7802880793',None):
            self.assertFalse(C.valid_inn(s))

    def test_quote_grounding_and_distinct_legal_forms(self):
        p=C.page_record('https://example.org/','Example Ltd and Example LLP. ООО «Пример»')
        got=C.mentions([p],{'mentions':[
            {'name':'Example Ltd','kind':'legal','url':p['url'],'quote':'Example Ltd and Example LLP.'},
            {'name':'Example LLP','kind':'legal','url':p['url'],'quote':'Example Ltd and Example LLP.'},
            {'name':'Wrong Company','kind':'legal','url':p['url'],'quote':'Example Ltd'},
            {'name':'Example Ltd','kind':'legal','url':'https://other.org','quote':'Example Ltd'},None]})
        self.assertEqual({m['name'] for m in got},{'Example Ltd','Example LLP','ООО «Пример»'})

    def test_document_claim_requires_quote_and_original_numbers(self):
        p=C.page_record('https://example.org/legal','The registered company number is 12345.')
        claim={'text':'Регистрационный номер 12345','quote':p['text'],'url':p['url']}
        got=C.verified_claims([p],{'claims':[claim,dict(claim,text='Номер 99999'),dict(claim,url='https://wrong.org')]})
        self.assertEqual(len(got),1)
        self.assertEqual(got[0]['text'],claim['text'])

    def test_registry_ambiguity_and_pagination_are_rejected(self):
        row={'ИНН':INN,'НаимСокр':NAME}
        def r(rows,total):return {'text':json.dumps({'data':{'Записи':rows,'ЗапВсего':total}})}
        self.assertEqual(C.registry_match('ООО «Пример»',r([row],1)),row)
        self.assertIsNone(C.registry_match(NAME,r([row],100)))
        self.assertIsNone(C.registry_match(NAME,r([row,row],2)))
        self.assertIsNone(C.registry_match('Другое',r([row],1)))

    def test_archive_date_is_actual_not_requested(self):
        p=C.page_record('https://web.archive.org/web/20200101000000/http://example.org/',
                        '[Главная](/web/20170716075228/http://example.org/)')
        self.assertEqual(p['snapshot'],'20170716075228')
        p=C.page_record(p['url'],'No timestamp in returned content')
        self.assertTrue(p['historical']);self.assertIsNone(p['snapshot'])

    def test_crawler_stays_on_target_and_rejects_unsafe_urls(self):
        p=C.page_record('https://web.archive.org/web/20170716075228/http://example.org/',
            '[Контакты](/about/contacts/) [Contract](https://evil.org/contract.pdf) '
            '[Contract](http://127.0.0.1/contract.pdf) [Contract](//user:pass@example.org/contract.pdf)')
        self.assertEqual(C.links(p),['https://web.archive.org/web/20170716075228/http://example.org/about/contacts/'])
        for u in ('http://127.0.0.1','http://169.254.169.254','http://host.local/','file:///tmp/x','https://u:p@example.org','http://[::1]','http://example.org:9000'):
            self.assertFalse(C.safe_url(u),u)

    def test_article_contacts_are_not_target_contacts(self):
        pages=[C.page_record('https://example.org/contact','Email support@other.org',domain='example.org'),
               C.page_record('https://news.org/article','Email journalist@news.org')]
        self.assertEqual([r['value'] for r in C.contacts(pages)],['support@other.org'])

    def test_extended_finances_keep_null_distinct_from_zero(self):
        payload={'company':{'ИНН':INN},'data':{'2020':{'1600':{'СумОтч':10000},'2110':{'СумОтч':0},'2400':{}}}}
        got=dossier._checko_financials(json.dumps(payload),{'inn':INN})
        self.assertEqual(got['metrics']['Активы']['2020'],10000)
        self.assertEqual(got['metrics']['Выручка']['2020'],0)
        self.assertNotIn('Чистая прибыль (убыток)',got['metrics'])

    def test_same_name_does_not_create_person_edge(self):
        c=[{'inn':str(i),'card':{'Руковод':[{'ФИО':'Иван Иванов','ИНН':str(i)}]}} for i in (1,2)]
        self.assertEqual(C.registry_edges(c),[])
        c[1]['card']['Руковод'][0]['ИНН']='1'
        self.assertEqual(C.registry_edges(c)[0]['companies'],['1','2'])

    def test_one_hop_management_lead_does_not_become_group_member(self):
        data={'companies':[{'inn':INN,'card':{'НаимПолн':NAME,'ОГРН':'1147847439080',
                                             'Ликвид':{'Дата':'2013-09-17'}},
                            'seed':{'basis':'registry_related_ogrn','relationship':{
                                'company':'7802537321','person':'Иван Иванов','role':'СвязРуковод'}}}]}
        md='\n'.join(C.render(data))
        for value in ('7802537321','Иван Иванов','по руководству','Запись может быть исторической',
                      'Принадлежность этого юрлица к исследуемому бренду или группе не установлена',
                      '2013-09-17'):
            self.assertIn(value,md)

    def test_full_collection_checks_identity_then_enriches_and_marks_gaps(self):
        calls=[]
        async def call(sid,tool,args):
            calls.append((sid,tool,args))
            if tool=='scrape_as_markdown':return {'ok':True,'text':'Контактная информация ООО «Пример», ИНН '+INN+'; support@example.org. '+('Данные компании. '*5)}
            if tool=='search':data={'data':{'Записи':[{'ИНН':INN,'НаимСокр':NAME}],'ЗапВсего':1}}
            elif tool=='get_company':data={'data':{'ИНН':INN,'ОГРН':'1147847439080','НаимСокр':NAME,'НаимПолн':NAME,'Учред':{'ФЛ':[{'ФИО':'Участник','Доля':{'Процент':67}}]}}}
            elif tool=='get_finances':data={'company':{'ИНН':INN},'data':{'2020':{'1600':{'СумОтч':10000},'2110':{'СумОтч':0}}}}
            elif tool=='get_timeline':return {'ok':False,'text':'timeout'}
            elif tool in ('get_legal_cases','get_fedresurs','get_bankruptcy_messages'):data={'company':{'ИНН':INN},'data':{'ЗапВсего':0,'Записи':[],'СтрВсего':1,'СтрТекущ':1}}
            else:data={'results':[]}
            return {'ok':True,'text':json.dumps(data)}
        with patch.dict(os.environ,{'NEWDB_MCP_TOKEN':''}):
            out=asyncio.run(C.collect('компания',['example.org'],None,[],call,deadline=5))
        self.assertEqual(len(out['companies']),1)
        self.assertFalse(out['companies'][0]['domain_ownership_verified'])
        self.assertEqual(out['companies'][0]['checks']['get_timeline']['status'],'unavailable')
        md='\n'.join(C.render(out))
        for s in ('67%','остатка не установлена','10 000','нет данных','Полная история не получена','не доказывает'):self.assertIn(s,md)
        self.assertTrue(any(t=='get_bankruptcy_messages' for _,t,_ in calls))

    def test_call_budget_and_wrong_company_reply(self):
        async def call(sid,tool,args):
            if tool=='get_company':return {'ok':True,'text':json.dumps({'data':{'ИНН':'7802537321','НаимПолн':NAME}})}
            return {'ok':False,'text':'no source'}
        with patch.dict(os.environ,{'NEWDB_MCP_TOKEN':''}):
            out=asyncio.run(C.collect('ИНН '+INN,[],{'inn':INN,'jurisdiction':'RU','legal_name':NAME},[],call,max_calls=1))
        self.assertEqual(len(out['calls']),1)
        self.assertEqual(out['companies'],[])
        self.assertTrue(out['budget_exhausted'])

    def test_evidence_is_saved_untruncated_and_counted_by_actual_source(self):
        evidence={'version':1,'pages':[{'text':'x'*15000}],
                  'calls':[{'server':'checko','name':'Checko','tool':'get_company','ok':True}],
                  'url':'https://example.org/?token=secret'}
        row={'server':'orchestrator','phase':C.PHASE,'tool':'corporate_research',
             'ok':True,'text':json.dumps(evidence)}
        self.assertEqual(report.coverage([row])['calls_total'],1)
        self.assertEqual(report.source_matrix([row])[0]['server'],'checko')
        with tempfile.TemporaryDirectory() as folder, patch.object(report,'write_html',return_value=True),patch.object(report,'write_pdf',return_value=True):
            info=report.save_report('Проверка', [row], '2026-09-29',folder,'http://localhost:8899','Готово')
            saved=json.loads((Path(folder)/(info['slug']+'.research.json')).read_text())
            self.assertEqual(len(saved['pages'][0]['text']),15000)
            self.assertNotIn('secret',saved['url'])
            self.assertIn(info['slug'] + '.research.json', info['markdown'])
            self.assertNotIn(info['research_url'], info['markdown'])

    def test_archived_cache_keeps_original_retrieval_date(self):
        async def call(sid,tool,args):return {'ok':False,'text':'network unavailable'}
        async def get(url,cap):return b'[]',url
        with tempfile.TemporaryDirectory() as folder:
            year=datetime.now(timezone.utc).year
            for age in (3,9):
                args={'url':f'https://web.archive.org/web/{year-age}0101000000/http://example.org/'}
                key=hashlib.sha256(json.dumps(['brightdata','scrape_as_markdown',args],sort_keys=True).encode()).hexdigest()
                row={'server':'brightdata','tool':'scrape_as_markdown','args':args,'ok':True,
                     'retrieved_at':'2026-01-01T10:00:00Z','text':'Archived corporate page. '*8}
                (Path(folder)/(key+'.json')).write_text(json.dumps(row))
            out=asyncio.run(C.collect('Архив',['example.org'],None,[],call,archive_get=get,cache_dir=folder))
        self.assertEqual(len(out['pages']),2)
        self.assertTrue(all(p['retrieved_at']=='2026-01-01T10:00:00Z' and p['cache_reused'] for p in out['pages']))
        self.assertIn('исторический снимок повторно не загружался','\n'.join(C.render(out)))


class InvestigateIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_ui_entrypoint_attaches_research_to_report(self):
        import server
        result={'version':1,'companies':[],'pages':[], 'failures':[], 'calls':[]}
        plan={'targets':[{'type':'inn','value':INN}], 'steps':[
            {'server':'checko','target':{'type':'inn','value':INN},'tool':'get_company','args':{'inn':INN},'name':'Checko'}]}
        row={'server':'checko','tool':'get_company','ok':True,
             'text':json.dumps({'data':{'ИНН':INN,'НаимПолн':NAME}})}
        with patch.object(server,'CATALOG',{'checko':{}}),patch.object(server,'build_plan',return_value=plan),\
             patch.object(server,'DOMAIN_DEEP',True),patch.object(server,'CORPORATE_RESEARCH',True),\
             patch.object(server,'run_one',AsyncMock(return_value=row)),\
             patch.object(server,'synthesize_dossier',AsyncMock(return_value='Основной отчёт')),\
             patch.object(server.corporate_research,'collect',AsyncMock(return_value=result)) as collect,\
             patch.object(server.report,'save_report',return_value={}) as save,\
             patch.object(server,'render_chat_summary',return_value='готово'):
            self.assertEqual(await server.investigate('Досье ИНН '+INN),'готово')
        self.assertEqual(collect.call_args.args[2]['inn'],INN)
        self.assertIn('Юридические лица: поиск по сайтам и архивам',save.call_args.args[5])
        self.assertTrue(any(r.get('phase')==C.PHASE for r in save.call_args.args[1]))


if __name__=='__main__':unittest.main()
