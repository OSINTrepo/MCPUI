#!/usr/bin/env python3
"""Сравнение референса и двух прогонов; содержание тела без сырого приложения.

Не является оценкой истинности: буквальное совпадение исторических IP/имён не
требуется от текущего снимка. Отдельно считаются таблицы и покрытие тем.
"""
import argparse
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent


class Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.skip=0; self.parts=[]; self.tables=0
    def handle_starttag(self, tag, attrs):
        if tag in ('script','style','svg'): self.skip+=1
        if tag == 'table': self.tables+=1
        if tag in ('p','div','tr','h1','h2','h3','h4','h5','li'): self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in ('script','style','svg'): self.skip=max(0,self.skip-1)
    def handle_data(self, value):
        if not self.skip: self.parts.append(value)


def facts(text):
    ips=set()
    for s in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text):
        try: ipaddress.ip_address(s); ips.add(s)
        except ValueError: pass
    hosts=set(re.findall(r'\b(?:[a-z0-9-]+\.)+(?:indracompany\.com|indra\.es|indragroup\.com)\b',text.lower()))
    return ips,hosts


def generated(folder):
    evidence=json.loads((folder/'evidence.json').read_text())
    report=max((p for p in folder.glob('*.md') if p.name!='chat.md'), key=lambda p: p.stat().st_mtime)
    body=report.read_text().split('## Приложение:')[0]
    return evidence,report,body


def main():
    p=argparse.ArgumentParser();p.add_argument('--final',default='revised')
    p.add_argument('--output-prefix', default='', help='Префикс артефактов отдельного сравнения моделей')
    a=p.parse_args()
    folder=ROOT/'reports'/'indra-comparison'
    target=ROOT/'INDRA SISTEMAS SA (CIF A28599033) (1).html'
    parsed=Text();parsed.feed(target.read_text());reference=''.join(parsed.parts)
    base,bpath,btext=generated(folder/'baseline');final,fpath,ftext=generated(folder/a.final)
    ri,rh=facts(reference);bi,bh=facts(btext);fi,fh=facts(ftext)
    # Проверки — индикаторы наполнения разделов, не семантическая «процентная схожесть».
    topics=[
      ('Юридическое имя и CIF',r'A[- ]?28599033'),
      ('Штаб-квартира',r'BRUSELAS|Bruselas|Брюссел'),
      ('Бизнес-направления',r'## Бизнес-структура'),
      ('Технологические проекты',r'## Технологические платформы'),
      ('География бизнеса',r'## Штаб-квартира и географическое присутствие'),
      ('Финансовые сведения',r'## Финансовые показатели'),
      ('Корпоративные связи',r'## Корпоративная структура'),
      ('Совет директоров',r'## Совет директоров'),
      ('Комитеты',r'## Комитет —'),
      ('Исполнительное руководство',r'## Исполнительное руководство'),
      ('Представители / apoderados',r'## Представители и apoderados'),
      ('Акты BORME',r'## Корпоративные события в официальных'),
      ('DNS и регистрация домена',r'## DNS-записи'),
      ('Почтовая безопасность',r'## Почтовая безопасность'),
      ('IP-адреса и диапазоны',r'## IP-диапазоны'),
      ('SSL-сертификаты',r'## SSL-сертификаты'),
      ('Поддомены по функциям',r'сгруппированы по функции'),
      ('Поддомены с IP',r'## Поддомены → IP'),
      ('Поддомены без текущего IP',r'## Поддомены без текущих'),
      ('Reverse IP',r'## Совместно размещённые домены'),
      ('География инфраструктуры',r'## Географическое распределение'),
      ('Связанные файлы',r'## Связанные \(communicating\) файлы'),
      ('История WHOIS',r'## Историческая регистрация'),
      ('Источники и ограничения',r'## Ограничения данных'),
    ]
    def tables(s):return len(re.findall(r'^\*\*Таблица \d+\.',s,re.M))
    def identity(e):return (e.get('identity') or {}).get('legal_name') or 'не разрешена'
    rows=[]
    for label,rx in topics:
        rows.append((label,bool(re.search(rx,btext,re.I)),bool(re.search(rx,ftext,re.I))))
    metrics={'reference_tables':parsed.tables,'baseline_tables':tables(btext),'final_tables':tables(ftext),
             'reference_ips':len(ri),'baseline_ips':len(bi),'final_ips':len(fi),
             'reference_hosts':len(rh),'baseline_hosts':len(bh),'final_hosts':len(fh),
             'baseline_reference_host_overlap':len(rh&bh),'final_reference_host_overlap':len(rh&fh),
             'baseline_reference_ip_overlap':len(ri&bi),'final_reference_ip_overlap':len(ri&fi),
             'baseline_topics':sum(x[1] for x in rows),'final_topics':sum(x[2] for x in rows),
             'topics_total':len(rows)}
    lines=['# INDRA: сравнение содержания', '',
           f'Референс: `{target.name}`. Снимок референса: апрель 2026; новый сбор: {final["when"]}.', '',
           f'[Первый отчёт]({bpath.relative_to(folder).with_suffix(".html")}) · '
           f'[Новый отчёт]({fpath.relative_to(folder).with_suffix(".html")})', '',
           'Сравнивается основное тело до приложения. Совпадение исторических записей '
           'не является проверкой истинности; оформление не оценивается.', '',
           '| Метрика | Референс | До исправлений | После |','|---|---:|---:|---:|',
           f'| Таблицы | {parsed.tables} | {tables(btext)} | {tables(ftext)} |',
           f'| Уникальные IPv4 в теле | {len(ri)} | {len(bi)} | {len(fi)} |',
           f'| Поддомены трёх основных доменов в теле | {len(rh)} | {len(bh)} | {len(fh)} |',
           f'| Совпадающие с референсом поддомены | — | {len(rh&bh)} | {len(rh&fh)} |',
           f'| Совпадающие с референсом IPv4 | — | {len(ri&bi)} | {len(ri&fi)} |',
           f'| Разрешение юрлица | INDRA SISTEMAS SA | {identity(base)} | {identity(final)} |','',
           '## Тематическое покрытие', '',
           '«Есть» означает наличие раздела/маркера с данными, а не равную глубину референсу.', '',
           '| Тема референса | До | После |','|---|---|---|']
    lines += [f'| {label} | {"есть" if before else "нет"} | {"есть" if after else "нет"} |'
              for label,before,after in rows]
    borme = {}
    for result in final["results"]:
        if result.get("ok") and result.get("tool") == "borme_publications":
            borme = json.loads(result["text"])
    imported = [r for r in final['results'] if r.get('server') == 'official-import']
    if imported:
        lines += ['', '## Условия итогового прогона', '',
                  'Итог собран из сохранённых сетевых ответов и отдельно обозначенного импорта официальных страниц. '
                  'DNS/HTTP контейнеров давали таймауты; состав органов управления и география восстановлены '
                  'через внешний web-reader. Это не полностью успешный автоматический сбор. '
                  'Исходные ошибки сохранены в evidence.json; метод и время чтения указаны в отчёте.', '']
    lines += ['', '## Почему значения могут отличаться', '',
              '- Референс содержит исторические IP, сертификаты и назначения. Новый сбор датирован отдельно.',
              '- Роли с официального сайта отражают состав на дату чтения; BORME показывает события, '
              'а не гарантированно действующие доверенности.',
              '- SPF/DMARC и сертификаты выводятся из полученных ответов, даже когда они расходятся с референсом.',
              '- Полнота архивов WHOIS, passive DNS и BORME зависит от доступных источников и лимитов. '
              'Данные из референса не подставляются в системный отчёт.', '',
              '## Оставшиеся содержательные различия', '',
              f'- BORME: {len(borme.get("announcements", []))} актов и '
              f'{len(borme.get("officer_events", []))} событий в сохранённых ответах; это ограниченная '
              'выборка, а не полный архив полномочий и не список действующих apoderados.',
              '- Состав совета и комитетов дан по текущему официальному сайту; апрельские должности '
              'из референса не перенесены как действующие.',
              '- Подтверждены CySAS, ECYSAP и роль Indra. Архитектурная зависимость «CySAS — основа ECYSAP» '
              'не утверждается без прямого подтверждения прочитанными источниками.',
              '- Не восстановлены все региональные адреса, старые поддомены indra.es и полная хронология '
              'сертификатов/passive DNS. Совпадение тем не означает равную полноту.', '',
              '## Артефакты и воспроизведение', '',
              '- `baseline/evidence.json` и `' + a.final + '/evidence.json` — ответы источников, идентичность и синтез.',
              '- `tests/indra_pipeline.py` — новый сетевой прогон или повторная сборка сохранённых ответов.',
              '- `tests/compare_indra.py` — расчёт этих метрик.', '']
    (folder/(a.output_prefix+'comparison.md')).write_text('\n'.join(lines))
    (folder/(a.output_prefix+'metrics.json')).write_text(json.dumps(metrics,ensure_ascii=False,indent=2))
    print(json.dumps(metrics,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
