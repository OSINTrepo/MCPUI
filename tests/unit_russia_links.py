"""Дополнительный фокус не меняет цель и не превращает ФИО в гражданство."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'servers/orchestrator'))
import russia_links as R
import recipes
import entity
import dossier
import sections

class Focus(unittest.TestCase):
 def test_requested_and_target_country(self):
  task='Досье по ООО «Tashsoftcom», Узбекистан. Проверь связь с российскими компаниями и гражданами РФ.'
  self.assertTrue(R.requested(task));self.assertEqual(recipes.country_hint(task),'UZ')
  companies=[x['value'] for x in recipes.detect_targets(task) if x['type']=='company']
  self.assertFalse(any('граждан' in x or 'РФ' in x for x in companies))
  self.assertEqual(recipes.country_hint('Досье российской компании ООО Пример. Связи с РФ.'),'RU')
 def test_unrelated_task_unchanged(self):
  self.assertFalse(R.requested('Досье компании ООО Пример, Россия'))
  self.assertEqual(R.target_context('Apple Inc, США'),'Apple Inc, США')
 def test_english_focus(self):
  task='Apple Inc, USA; links with Russian companies and citizens'
  self.assertTrue(R.requested(task));self.assertEqual(recipes.country_hint(task),'US')
 def test_russia_focus_does_not_assign_target_jurisdiction(self):
  task=('Boston Brokerage Group, домены bbg.trade и bbg-russia.trade. '
        'Отдельный раздел: связь с российскими компаниями и гражданами РФ. '
        'Кандидаты: ИНН 7802880793, 7802537321, 7802661760, 7802862106 и британское LLP OC401309.')
  self.assertTrue(R.requested(task));self.assertEqual(recipes.country_hint(task),'')
  self.assertFalse(any(sid=='checko' for sid,_,_ in entity.probe_specs('Boston Brokerage Group',task)))
 def test_person_dedup_and_no_citizenship_inference(self):
  p=R.people_from_data({'uz_directory':{'director':'EXAMPLE PERSON','founders':[{'name':'EXAMPLE PERSON'}]}})
  self.assertEqual(len(p),1); self.assertEqual(p[0]['citizenship'],'not_established')
 def test_failed_source_section(self):
  d=dossier.extract_company_data([{'tool':'russia_connections','ok':False,'text':'timeout'}])
  md='\n'.join(sections.render_target('company',d,{}))
  self.assertIn('Целевая проверка не выполнена',md);self.assertIn('Отсутствие связей не установлено',md)
 def test_empty_source_is_not_no_links(self):
  md='\n'.join(R.render({'russia_connections':{'company':'Example'}},{}))
  self.assertIn('не доказывает отсутствие',md)
 def test_media_reported_company_links_are_not_presented_as_registry_matches(self):
  focus={'company':'Boston Brokerage Group','people':[],'searches':[],'hits':[],
         'relations':[{'entity':'ООО «БИ БИ ДЖИ КОНСАЛТИНГ»','relation':'создано для заявленной брокерской деятельности',
                       'country':'Россия','date':'с 2014 года (по публикации)','status':'source_reported',
                       'source_urls':['https://www.kommersant.ru/doc/5940417','https://66.ru/news/incident/262804/']}],
         'retrieved_at':'2026-10-01T11:40:00Z','scope':'Публичные публикации прочитаны.'}
  md='\n'.join(R.render({'russia_connections':focus},{}))
  self.assertIn('Публичный источник сообщает о связи',md)
  self.assertNotIn('Имя и ИНН цели совпали',md)
  self.assertIn('https://www.kommersant.ru/doc/5940417',md)
  self.assertIn('https://66.ru/news/incident/262804/',md)
 def test_read_article_is_distinguished_from_search_snippet(self):
  focus={'company':'Boston Brokerage Group','relations':[],'people':[],'searches':[],
         'hits':[{'kind':'company','title':'Инвесторы не досчитались выплат',
                  'snippet':'По сообщению публикации, проводились доследственные проверки.',
                  'url':'https://www.kommersant.ru/doc/5940417','status':'page_read'}],
         'retrieved_at':'2026-10-01T11:40:00Z','scope':'Публичные публикации прочитаны.'}
  md='\n'.join(R.render({'russia_connections':focus},{}))
  self.assertIn('Прочитанная публикация; это сообщение источника, не запись реестра',md)
  self.assertNotIn('Фрагмент поиска, не проверенный факт',md)
 def test_newdb_egrul_candidate_shows_record_without_linking_to_target(self):
  check={'subject':'ИНН 7802862106 (кандидат пользователя; связь с целью не установлена)',
         'request_id':'test-request','method':'egrul','params':{'inn':'7802862106'},'match_basis':'user_supplied_candidate_tax_id',
         'status':'complete','response':{'results':{'egrul':{'result':{'data':[{'matches':[{
          'name_full':'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "ММСИС КОНСАЛТИНГ СЕВЕРО-ЗАПАД"',
          'name_short':'ООО "ММСИС КОНСАЛТИНГ СЕВЕРО-ЗАПАД"','inn':'7802862106',
          'ogrn':'1147847195495','status':'Деятельность прекращена','region':'Санкт-Петербург',
          'registration_date':'03.06.2014','okved_name':'Деятельность по вопросам финансового посредничества'}]}]}}}}}
  md='\n'.join(R.render({'russia_connections':{'company':'Boston Brokerage Group'},
                        'russia_newdb':{'checks':[check]}},{}))
  self.assertIn('ММСИС КОНСАЛТИНГ СЕВЕРО-ЗАПАД',md)
  self.assertIn('ОГРН 1147847195495',md)
  self.assertIn('Связь с целевой компанией не установлена',md)
 def test_employment_requires_page_quote(self):
  data={'people':[{'name':'Example Person'}],'pages':[{'url':'https://www.linkedin.com/in/example','text':'Example Person worked as Engineer at Example Co in 2020–2022.'}]}
  claim={'person':'Example Person','employer':'Example Co','role':'Engineer','period':'2020–2022','quote':data['pages'][0]['text'],'url':data['pages'][0]['url']}
  self.assertEqual(len(R.verified_employment({'findings':[claim]},data)),1)
  self.assertFalse(R.verified_employment({'findings':[{**claim,'employer':'Invented Co'}]},data))
  self.assertFalse(R.verified_employment({'findings':[{**claim,'quote':'Invented quote not in the source page'}]},data))
  self.assertFalse(R.verified_employment({'findings':[claim]},{**data,'pages':[]}))
 def test_no_free_comment_overrides_focus(self):
  md='\n'.join(sections.render_target('company',{'russia_connections':{'company':'Example'}},{'comments':{'c_russia_connections':'Все владельцы граждане РФ'}}))
  self.assertNotIn('Все владельцы граждане РФ',md)
 def test_html_and_table_escape(self):
  self.assertNotIn('<script>',R.esc('<script>|[x]'))
  self.assertEqual(R.link('javascript:alert(1)'),'—')

if __name__=='__main__': unittest.main()
