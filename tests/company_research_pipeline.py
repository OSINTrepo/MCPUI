"""Живой проверочный прогон того же корпоративного этапа, который вызывает UI.

Запуск в контейнере: python tests/company_research_pipeline.py example.org
Не использует заранее найденные ИНН или документы конкретной компании.
"""
import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime,timezone
from pathlib import Path

sys.path.insert(0,'/app')
import server
import corporate_research as research


async def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('domains',nargs='+')
    parser.add_argument('--label',default='live')
    parser.add_argument('--seconds',type=int,default=240)
    args=parser.parse_args()
    if not args.label.replace('-','').replace('_','').isalnum():raise ValueError('invalid label')
    out=Path('/reports/corporate-research-validation')/args.label
    out.mkdir(parents=True,exist_ok=True)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('weasyprint').setLevel(logging.ERROR)
    logging.getLogger('fontTools').setLevel(logging.ERROR)
    calls=[];started=time.monotonic()
    async def call(sid,tool,params):
        r=await server.run_one(sid,{'type':'domain','value':args.domains[0]},tool,params)
        server.reclassify([r]);calls.append(r)
        (out/'calls.json').write_text(json.dumps(calls,ensure_ascii=False,indent=2))
        print(round(time.monotonic()-started),sid,tool,params,r.get('ok'),flush=True)
        return r
    async def extract(pages):
        answer=await server.llm([
            {'role':'system','content':research.EXTRACT_PROMPT},
            {'role':'user','content':json.dumps([{'url':p['url'],'text':p['text'][:14000]} for p in pages],ensure_ascii=False)}
        ],max_tokens=2500,model=server.REPORT_MODEL)
        return server._json_from(answer or '') or {}
    task='Подробная корпоративная проверка и архивные связи: '+', '.join(args.domains)
    data=await research.collect(task,args.domains,None,[],call,extract,deadline=args.seconds,
                               cache_dir=Path('/reports/.corporate-cache'))
    (out/'research.json').write_text(json.dumps(data,ensure_ascii=False,indent=2))
    result={'server':'orchestrator','name':'Корпоративная проверка','phase':research.PHASE,
            'tool':'corporate_research','ok':bool(data['pages'] or data['companies']),
            'text':json.dumps(data,ensure_ascii=False)}
    body='# '+task+'\n\n'+'\n'.join(research.render(data))
    when=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    info=server.report.save_report(task,[result],when,str(out),server.REPORTS_URL_BASE+'/corporate-research-validation/'+args.label,body)
    summary={'elapsed_seconds':round(time.monotonic()-started,1),'companies':[c['inn'] for c in data['companies']],
             'pages':len(data['pages']),'calls':len(data['calls']),'budget_exhausted':data['budget_exhausted'],
             'html':info.get('html_url'),'pdf':info.get('pdf_url'),'research':info.get('research_url')}
    (out/'run.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    print(json.dumps(summary,ensure_ascii=False,indent=2),flush=True)


if __name__=='__main__':asyncio.run(main())
