"""Корпоративные факты из прочитанных страниц: проверка цитат и секции досье."""
from __future__ import annotations

import re
import dossier as D

TITLES = {
    'overview': 'Общая информация и масштаб деятельности',
    'business': 'Бизнес-структура и направления деятельности',
    'legal': 'Юридические сведения с официального сайта',
    'locations': 'Штаб-квартира и географическое присутствие',
    'financial': 'Финансовые показатели и отчётность компании',
    'ownership': 'Акционеры и структура владения',
    'projects': 'Технологические платформы и проекты',
}


def normalize(s):
    return ' '.join(str(s or '').split()).casefold()


def verified_claims(candidate: dict, pages: list[dict]) -> list[dict]:
    """LLM может переводить факты, но обязан предъявить точную цитату и её URL."""
    sources = {p['url']: normalize(p.get('text')) for p in pages}
    out = []
    for c in candidate.get('claims', []) if isinstance(candidate, dict) else []:
        if not isinstance(c, dict) or c.get('section') not in TITLES:
            continue
        quote, fact, url = c.get('quote'), c.get('text'), c.get('url')
        if not isinstance(quote, str) or not isinstance(fact, str):
            continue
        if len(quote) < 20 or len(quote) > 1200 or len(fact) > 900:
            continue
        if normalize(quote) not in sources.get(url, ''):
            continue
        # Не допускаем чисел, которых нет в приведённом доказательстве.
        digits = re.findall(r'\d+', fact)
        if any(n not in re.findall(r'\d+', quote) for n in digits):
            continue
        out.append({k: c[k] for k in ('section', 'text', 'quote', 'url')})
    return out[:35]


def render(data, ctx):
    source = data.get('official') or {}
    if not source.get('pages'):
        return []
    pages = source['pages']
    claims = source.get('claims') or []
    md = []
    if source.get("collection_note"):
        md += ["## Происхождение корпоративных данных", "", source["collection_note"], ""]
    # CIF берётся из прочитанной юридической страницы, а не из исходной задачи.
    legal = next((p for p in pages if p.get('category') == 'legal'), None)
    if legal:
        m = re.search(r'\b([ABCDEFGHJNPQRSUVW])[- .]?(\d{8})\b', legal.get('text', ''))
        if m:
            md += ['## Юридический идентификатор компании', '']
            md += D._md_table(['Параметр', 'Значение', 'Источник'], [
                ['CIF / NIF', ''.join(m.groups()), f"[Юридическая информация]({legal['url']})"],
                ['Сайт после редиректа', source.get('official_domain'), source.get('redirect_url')],
                ['Дата чтения', source.get('retrieved_at'), 'HTTP / официальный сайт'],
            ]) + ['']
    metrics = source.get("metrics") or []
    if metrics:
        md += ["## Финансовые показатели и масштаб компании", ""]
        rows = []
        for m in metrics:
            value = f"{m['value']:,.0f}".replace(",", " ")
            rows.append([m["label"], m.get("year") or "на дату чтения",
                         f"{m.get('operator', '')}{value} {m['unit']}",
                         f"[{m['source_value']}]({m['url']})"])
        md += D._md_table(["Показатель", "Период", "Значение", "Запись источника"], rows) + [""]
    businesses = source.get("businesses") or []
    if businesses:
        md += ["## Бизнес-структура и направления деятельности", ""]
        md += D._md_table(["Направление", "Описание источника (оригинал)", "Источник"], [
            [b["name"], b["description"], f"[Сайт]({b['url']})"] for b in businesses]) + [""]
    projects = source.get("projects") or []
    if projects:
        md += ["## Технологические платформы и проекты", ""]
        md += D._md_table(["Проект и опубликованное назначение", "Источник"], [
            [p["title"], f"[Каталог проектов]({p['url']})"] for p in projects]) + [""]
    location_rows = []
    for page in pages:
        if page.get("category") != "locations":
            continue
        offices = re.search(r"(?:oficinas en|offices in)\s+(\d+)\s+(?:países|countries)", page.get("text", ""), re.I)
        if offices:
            location_rows.append(["Офисы", offices.group(1) + " стран", f"[География присутствия]({page['url']})"])
    if location_rows:
        md += ["## Штаб-квартира и географическое присутствие", ""]
        md += D._md_table(["Параметр", "Значение", "Источник"], location_rows) + [""]
    for category, title in TITLES.items():
        if (category == "business" and businesses) or (category == "projects" and projects):
            continue
        if category in ("overview", "financial") and metrics:
            continue
        rows = [c for c in claims if c['section'] == category]
        if not rows:
            continue
        md += ['## ' + title, '']
        for c in rows:
            md += [f"- {c['text']} [Источник]({c['url']})"]
        md += ['']
    people = source.get('people') or []
    groups = list(dict.fromkeys(p['group'] for p in people))
    for group in groups:
        rows = [p for p in people if p['group'] == group]
        label = ('Совет директоров' if group.lower() == 'consejo de administración' else
                 'Исполнительное руководство' if group.lower() == 'comité de dirección' else 'Комитет')
        md += [f'## {label} — {group}', '',
               f"_Официальный сайт, чтение {rows[0].get('retrieved_at') or source.get('retrieved_at', '')}. "
               'Состав на дату чтения; не архив назначений._', '']
        md += D._md_table(['Имя', 'Роль / должность', 'Последнее назначение', 'Источник'], [
            [p['name'], p.get('role'), p.get('appointed') or 'не указано',
             f"[Состав органа]({p['source_url']})"] for p in rows]) + ['']
    if people:
        md += ['## Структура корпоративного управления', '',
               '```mermaid', 'graph LR', '  company["Компания"]']
        for i, group in enumerate(groups):
            md += [f'  company --> g{i}["{D._mm_label(group)}"]']
            # Схема показывает членство в органе, не предполагаемые линии подчинения.
            for j, p in enumerate(p for p in people if p['group'] == group):
                if j >= 4:
                    break
                md += [f'  g{i} --> p{i}_{j}["{D._mm_label(p["name"])}"]']
        md += ['```', '', '_Связь означает членство; должности приведены в таблицах._', '']
    pubs = source.get('publications') or []
    if pubs:
        md += ['## Официальные финансовые публикации', '']
        md += D._md_table(['Документ', 'Ссылка'],
                          [[p['title'], f"[Документ]({p['url']})"] for p in pubs[:15]]) + ['']
    md += ['## Прочитанные корпоративные источники', '']
    md += D._md_table(['Раздел', 'Страница', 'Состояние', 'Чтение / метод'], [
        [p['category'], f"[{p['title']}]({p['url']})",
         f"первые 10000 из {p['original_chars']} символов" if p.get('truncated') else 'прочитана',
         str(p.get('retrieved_at') or source.get('retrieved_at', '')) + ' / ' + p.get('collection_method', 'HTTP')] 
        for p in pages]) + ['']
    if not claims:
        md += ['_Структурированный перевод текста недоступен. '
               'Состав органов управления и ссылки извлечены без LLM._', '']
    if source.get('failures'):
        md += ['_Не прочитаны: ' + '; '.join(f"{p['url']} ({p['reason']})"
                                           for p in source['failures']) + '_', '']
    return md
