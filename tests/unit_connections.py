"""Границы доказательств и сетевых запросов в целевом поиске связей."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'servers/directapi'))
import connections as C

PAGE = '<h1>Example Tech</h1><p>ИНН 123456789</p><table><tr><th>Тип</th><th>Название компании</th><th>Страна</th><th>Дата</th></tr><tr><td>поставщик</td><td>Example Supplier</td><td>Россия</td><td>22.12.2023</td></tr></table>'

class Evidence(unittest.TestCase):
 def test_relation_has_date_source_and_identity(self):
  r=C.parse_page(PAGE,'https://i2b-centre.ru/example','Example Tech','123456789')['relations'][0]
  self.assertEqual(r['status'],'source_reported'); self.assertEqual(r['date'],'22.12.2023')
  self.assertEqual(r['identity_basis'],'name_and_tax_id')
 def test_merged_title_before_header(self):
  page=PAGE.replace('<table>','<table><tr><td colspan="4">Клиенты и поставщики</td></tr>')
  r=C.parse_page(page,'https://i2b-centre.ru/example','Example Tech','123456789')['relations']
  self.assertEqual(len(r),1);self.assertEqual(r[0]['entity'],'Example Supplier')
 def test_wrong_identifier_is_rejected(self):
  self.assertFalse(C.parse_page(PAGE,'https://i2b-centre.ru/example','Example Tech','987654321')['relations'])
 def test_name_only_is_candidate(self):
  self.assertEqual(C.parse_page(PAGE,'https://i2b-centre.ru/example','Example Tech','')['relations'][0]['status'],'candidate')
 def test_footer_country_does_not_make_relationship(self):
  page=PAGE.replace('<td>Россия</td>','<td>Казахстан</td>')+'<footer>Россия</footer>'
  self.assertFalse(C.parse_page(page,'https://i2b-centre.ru/example','Example Tech','123456789')['relations'])
 def test_url_allowlist(self):
  self.assertTrue(C.readable_url('https://www.linkedin.com/in/example'))
  for u in ['http://checko.ru/x','https://checko.ru.evil.test/','https://127.0.0.1/', 'https://checko.ru@127.0.0.1/', 'https://checko.ru:8000/']:
   self.assertFalse(C.readable_url(u))
 def test_queries_cover_registries_employment_and_citizenship(self):
  q=C.queries('Example Tech','123456789',[{'name':'Example Person'}])
  self.assertEqual({k for k,_ in q},{'company','registry','linkedin','citizenship'})
  self.assertTrue(any('ЕГРИП' in s and 'Example Person' in s for _,s in q))
 def test_failed_search_is_not_negative_fact(self):
  async def search(*args,**kwargs): return json.dumps({'error':'provider unavailable'})
  result=asyncio.run(C.collect('Example Tech','',[],search))
  self.assertFalse(result['searches']);self.assertTrue(result['failures'])

if __name__=='__main__': unittest.main()
