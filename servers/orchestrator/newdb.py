"""NewDB MCP: ограниченные проверки реестров, токен только в HTTP-заголовке."""
from __future__ import annotations
import asyncio
import json
import os
import re
import time
import uuid
from datetime import datetime,timezone
from mcp_client import MCPClient

ENDPOINT='https://api.newdb.net/mcp'
METHODS={'egrul','egrul_ip','fns_mass_founders','fns_mass_leaders'}
RESULT_TIMEOUT_SECONDS=max(30,min(300,float(os.environ.get('NEWDB_RESULT_TIMEOUT_SECONDS','120'))))


def _valid_company_inn(value):
    value=str(value or '')
    if not re.fullmatch(r'\d{10}',value) or len(set(value))==1:
        return False
    return sum(int(x)*w for x,w in zip(value[:9],[2,4,10,3,5,9,4,6,8]))%11%10==int(value[-1])


def _job_status(data,method):
    state=str(data.get('state') or '').lower()
    if state in ('complete','completed'): return 'complete'
    if state in ('error','failed','restart'): return 'failed'
    result=((data.get('results') or {}).get(method) or {}).get('result') or {}
    try: code=int(result.get('status') or 0)
    except (TypeError,ValueError): code=0
    if result.get('error') or 400<=code<600: return 'failed'
    return 'pending'


def sanitize(obj,token=''):
    if isinstance(obj,dict):
        return {k:sanitize(v,token) for k,v in obj.items()
                if not re.search(r'token|authorization|api.?key|headers',k,re.I)
                and k.casefold()!='balance'}
    if isinstance(obj,list): return [sanitize(v,token) for v in obj]
    if isinstance(obj,str):
        if token: obj=obj.replace(token,'[REDACTED]')
        return re.sub(r'((?:^|[?&])(?:token|api_key)=)[^&\s]+',r'\1[REDACTED]',obj,flags=re.I)
    return obj


def requests(company,identity,people,candidate_tax_ids=None):
    out=[]
    inn=str((identity or {}).get('inn') or '')
    seen_inns=set()
    if (identity or {}).get('jurisdiction')=='RU' and _valid_company_inn(inn):
        out.append({'subject':company,'method':'egrul','params':{'inn':inn,'country':'ru'},'match_basis':'tax_id'})
        seen_inns.add(inn)
    # User-supplied numbers remain candidates. Query each exact identifier, but
    # never imply that its registry record belongs to the named target.
    for raw in candidate_tax_ids or []:
        candidate=str(raw or '')
        if _valid_company_inn(candidate) and candidate not in seen_inns:
            out.append({'subject':f'ИНН {candidate} (кандидат пользователя; связь с целью не установлена)',
                        'method':'egrul','params':{'inn':candidate,'country':'ru'},
                        'match_basis':'user_supplied_candidate_tax_id'})
            seen_inns.add(candidate)
    for person in people[:2]:
        # Имя — лишь поисковый критерий. Не присваиваем ИНН по однофамильцу.
        who=person['name']
        for method in ('fns_mass_founders','fns_mass_leaders'):
            out.append({'subject':who,'method':method,'params':{'fio':who,'country':'ru'},'match_basis':'name_only'})
        inn=str(person.get('inn_ru') or '')
        if re.fullmatch(r'\d{12}',inn):
            out.append({'subject':who,'method':'egrul_ip','params':{'innfiz':inn,'country':'ru'},'match_basis':'tax_id'})
    return out[:6]


def unwrap(reply):
    if not reply.get('ok'): raise ValueError('MCP tool error')
    data=json.loads(reply.get('text') or '{}')
    if not isinstance(data,dict) or data.get('ok') is False: raise ValueError('NewDB request error')
    body=data.get('body',data)
    if not isinstance(body,dict): raise ValueError('NewDB invalid body')
    if body.get('error') or body.get('status') in (400,401,402,403,429,500):
        raise ValueError('NewDB response error')
    return body


async def collect(company,identity,people,token,candidate_tax_ids=None):
    result={'status':'not_configured','checks':[],
            'scope':'По ФИО — только реестры массовых учредителей/руководителей. '
                    'Отсутствие в этих реестрах не означает отсутствия компаний или ИП. '
                    'ЕГРЮЛ проверяет подтверждённый ИНН цели и отдельно переданные ИНН-кандидаты; '
                    'проверка кандидата не устанавливает связь с целью. '
                    'Совпадение ФИО не доказывает тождество лица или гражданство.',
            'retrieved_at':datetime.now(timezone.utc).isoformat()}
    if not token: return result
    jobs=requests(company,identity,people,candidate_tax_ids)
    result['status']='no_identifiers' if not jobs else 'checked'
    sem=asyncio.Semaphore(2)
    async def run(job):
        async with sem:
            record={**job,'request_id':str(uuid.uuid4()),'status':'pending'}
            client=MCPClient(ENDPOINT,headers={'Authorization':'Bearer '+token},timeout=20)
            try:
                assert job['method'] in METHODS
                data=unwrap(await client.call('newdb_submit_request',{
                    'method':job['method'],'params':job['params'],'requestId':record['request_id']}))
                request_id=data.get('requestId') or record['request_id']
                record['request_id']=request_id
                state=_job_status(data,job['method'])
                deadline=time.monotonic()+RESULT_TIMEOUT_SECONDS
                while state=='pending' and time.monotonic()<deadline:
                    await asyncio.sleep(3)
                    data=unwrap(await client.call('newdb_get_result',{'requestId':request_id}))
                    state=_job_status(data,job['method'])
                record['status']=state
                record['response']=sanitize(data,token)
            except Exception as exc:
                record['status']='unavailable';record['error_type']=type(exc).__name__
            return sanitize(record,token)
    result['checks']=await asyncio.gather(*(run(j) for j in jobs))
    return result
