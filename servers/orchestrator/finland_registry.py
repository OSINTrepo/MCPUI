"""Официальный охват финского реестра отдельно от раскрытий самого сайта."""
import html
from urllib.parse import quote


def render(data, ctx):
    source = data.get('fi_registry')
    if not source:
        return []
    def escape(value):
        return html.escape(str(value or 'не получено')).replace('|', '&#124;').replace('\n', ' ')
    def link(url, label):
        return '[' + label + '](' + quote(url, safe=':/?=&%#@+;,~_-') + ')'
    lines = ['## Финляндия: официальный реестр и границы проверки', '', source.get('scope', ''), '']
    if source.get('matched') and source.get('official_registry_verified'):
        lines += ['| Поле | Значение |', '|---|---|']
        for key, label in (('name', 'Наименование'), ('business_id', 'Y-tunnus / Business ID'),
                           ('legal_form', 'Правовая форма'), ('registered_at', 'Дата регистрации'),
                           ('business_id_registered_at', 'Дата присвоения Business ID'),
                           ('activity', 'Деятельность'), ('last_modified', 'Обновление записи')):
            if source.get(key):
                lines += ['| ' + label + ' | ' + escape(source[key]) + ' |']
        for address in source.get('addresses', []):
            lines += ['| Адрес из реестра | ' + escape(address.get('address')) + ' |']
    else:
        lines += ['Государственная карточка целевого объединения этим API не получена. '
                  'Пустой ответ коммерческого реестра не доказывает отсутствия объединения. '
                  'Сведения сайта о его названии и Y-tunnus приводятся с отдельной атрибуцией.', '']
    if source.get('source_url'):
        lines += [link(source['source_url'], 'Ответ PRH/YTJ API') + ' · чтение: ' + escape(source.get('retrieved_at')), '']
    for item in source.get('manual_verification', []):
        if item.get('url'):
            lines += ['- ' + link(item['url'], escape(item.get('name') or 'Ручная проверка'))]
    return lines + ['']
