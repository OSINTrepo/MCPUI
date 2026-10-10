"""NewDB: область запросов, защита токена, ошибки != отсутствие связей."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'servers/orchestrator'))
import newdb as N

class NewDB(unittest.TestCase):
 def test_uz_tax_id_never_sent_to_russian_registry(self):
  jobs=N.requests('Example',{'jurisdiction':'UZ','inn':'310379504'},[])
  self.assertEqual(jobs,[])
 def test_full_name_checks_limited_registers(self):
  jobs=N.requests('Example',{},[{'name':'Example Person'}])
  self.assertEqual({j['method'] for j in jobs},{'fns_mass_founders','fns_mass_leaders'})
  self.assertTrue(all(j['match_basis']=='name_only' for j in jobs))
 def test_russian_identifiers(self):
  jobs=N.requests('Example',{'jurisdiction':'RU','inn':'7707083893'},[{'name':'Example Person','inn_ru':'123456789012'}])
  self.assertIn('egrul',{j['method'] for j in jobs});self.assertIn('egrul_ip',{j['method'] for j in jobs})
 def test_user_supplied_company_inns_are_checked_as_unlinked_candidates(self):
  inns=['7802880793','7802537321','7802661760','7802862106']
  jobs=N.requests('Boston Brokerage Group',{},[],candidate_tax_ids=inns)
  self.assertEqual([j['params']['inn'] for j in jobs],inns)
  self.assertTrue(all(j['match_basis']=='user_supplied_candidate_tax_id' for j in jobs))
  self.assertTrue(all('связь с целью не установлена' in j['subject'] for j in jobs))
 def test_invalid_or_duplicate_candidate_inns_are_not_submitted(self):
  jobs=N.requests('Example',{},[],candidate_tax_ids=['7802880793','7802880793','1234567890'])
  self.assertEqual([j['params']['inn'] for j in jobs],['7802880793'])
 def test_worker_503_is_failure_and_running_job_stays_pending(self):
  restart={'state':'restart','results':{'egrul':{'result':{'status':503,'error':'worker timeout'}}}}
  self.assertEqual(N._job_status(restart,'egrul'),'failed')
  self.assertEqual(N._job_status({'state':'in progress'},'egrul'),'pending')
  self.assertEqual(N._job_status({'state':'completed'},'egrul'),'complete')
 def test_secrets_redacted_recursively(self):
  d=N.sanitize({'token':'secret','balance':69,'data':{'api_key':'secret','url':'https://x/?token=secret&x=1','message':'secret'}},'secret')
  self.assertNotIn('secret',json.dumps(d));self.assertNotIn('token',d)
  self.assertNotIn('balance',d)
 def test_error_is_not_success(self):
  for value in [{'ok':False},{'ok':True,'text':json.dumps({'ok':False})}, {'ok':True,'text':json.dumps({'body':{'error':'balance'}})}]:
   with self.assertRaises(ValueError): N.unwrap(value)
 def test_missing_key_no_network(self):
  out=asyncio.run(N.collect('Example',{},[],'') )
  self.assertEqual(out['status'],'not_configured');self.assertEqual(out['checks'],[])
 def test_submit_uses_header_not_token_argument(self):
  seen=[]
  class Client:
   def __init__(self,*args,**kw): self.headers=kw['headers']
   async def call(self,tool,args):
    seen.append((tool,args,self.headers))
    return {'ok':True,'text':json.dumps({'body':{'state':'complete','token':'secret','results':{}}})}
  with patch.object(N,'MCPClient',Client): out=asyncio.run(N.collect('Example',{},[{'name':'Example Person'}],'secret'))
  self.assertEqual(len(out['checks']),2)
  self.assertNotIn('secret',json.dumps(out))
  self.assertTrue(all('token' not in args and headers['Authorization']=='Bearer secret' for _,args,headers in seen))

if __name__=='__main__': unittest.main()
