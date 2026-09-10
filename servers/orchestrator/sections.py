"""Реестр секций досье — единый упорядоченный источник правды по разделам отчёта.

Каждая секция декларативна: к каким типам цели применима (domain/ip/company) и
функция render(data, ctx) -> markdown. Данные готовит один проход
dossier.extract_domain_data / extract_company_data (с провенансом в data["_sources"]);
секции только рендерят. Добавить источник = добавить секцию, а не править
1000-строчные функции. Инфраструктурные парсеры/хелперы живут в dossier и
переиспользуются здесь (импорт односторонний: sections -> dossier).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

import dossier as D
import official

DOMAIN, IP, COMPANY = "domain", "ip", "company"


@dataclass(frozen=True)
class Section:
    id: str
    applies_to: frozenset
    render: Callable            # (data, ctx) -> list[str]  ("" если данных нет)


_TABLE_SEP = re.compile(r"^\|[\s:-]*\|[\s|:-]*$")


def _number_tables(block: list[str], counter: list[int]) -> list[str]:
    """Пронумеровать таблицы блока: «**Таблица N. <подпись>**» над шапкой.

    Как в референс-досье: на нумерованную таблицу можно сослаться из выводов, и
    сразу видно, что это отдельная единица данных, а не продолжение текста.
    Подпись берём из ближайшего заголовка выше (## … или **…:**) — отдельных
    подписей секции не заводят."""
    out: list[str] = []
    caption = ""
    for i, ln in enumerate(block):
        s = ln.strip()
        if s.startswith("## "):
            caption = s[3:].strip()
        elif s.startswith("**") and s.endswith("**") and len(s) > 4:
            # Подзаголовок внутри секции («**Активные:**», «**Рассмотренные
            # кандидаты.**») — он точнее общего заголовка, когда таблиц несколько.
            caption = s[2:-2].strip().rstrip(":.")
        # Шапка таблицы = строка «| … |», под которой разделитель «|---|---|».
        if (s.startswith("|") and i + 1 < len(block)
                and _TABLE_SEP.match(block[i + 1].strip())):
            counter[0] += 1
            head = f"**Таблица {counter[0]}." + (f" {caption}**" if caption else "**")
            out += [head, ""]
        out.append(ln)
    return out


def render_target(kind: str, data: dict, ctx: dict | None = None) -> list[str]:
    """Собрать markdown-секции для типа цели kind из общего data (parse-once).
    ctx['comments'] = {section_id: текст} — если задано, под секцией печатается
    вывод аналитика.
    ctx['exclude'] = {section_id} — секции, которые рисует другой слой (напр.
    веб-поиск принадлежит корпоративному слою, иначе он печатался дважды)."""
    ctx = ctx or {}
    comments = ctx.get("comments") or {}
    exclude = ctx.get("exclude") or frozenset()
    # Сквозной счётчик «Таблица N.» — общий на весь отчёт, включая главы по
    # каждому домену. Список (а не int), чтобы номер разделялся между вызовами.
    ctx.setdefault("_tno", [0])
    md: list[str] = []
    for s in SECTIONS:
        if kind in s.applies_to and s.id not in exclude:
            block = s.render(data, ctx) or []
            if block:
                block = _number_tables(block, ctx["_tno"])
                c = comments.get(s.id)
                if c:
                    block = block + [f"**Вывод:** {c}", ""]
                md += block
    return md


def populated_ids(kind: str, data: dict, ctx: dict | None = None) -> list[str]:
    """ID секций, у которых есть данные для kind (для адресного LLM-комментария).

    ВАЖНО: рендерим на ОДНОРАЗОВОМ счётчике таблиц. Эта функция реально вызывает
    render каждой секции, и с общим счётчиком пробный проход съедал номера —
    нумерация в самом отчёте начиналась не с единицы и шла с дырами."""
    ctx = dict(ctx or {})
    ctx["_tno"] = [0]
    return [s.id for s in SECTIONS if kind in s.applies_to and (s.render(data, ctx) or [])]


# Читаемые заголовки секций для промпта комментариев.
TITLES = {
    "org": "Организация (реестр)", "whois": "Регистрация домена (WHOIS/RDAP)",
    "whois_contacts": "Контакты домена", "dns": "DNS-записи",
    "mail": "Почтовая безопасность (SPF/DMARC/DKIM)", "ips": "IP-адреса и сети",
    "ranges": "IP-диапазоны", "reverse_cohost": "Совместно размещённые домены",
    "geo": "География инфраструктуры", "certs": "SSL-сертификаты",
    "subdomains": "Поддомены", "subdomain_ips": "Поддомены→IP",
    "files": "Связанные файлы", "shodan": "Живые активы (Shodan)",
    "whois_history": "История регистрации", "reputation": "Репутация",
    "typosquat": "Домены-двойники (тайпсквоттинг)",
    "voidly_status": "Доступность по странам",
    "voidly_history": "История доступности (Voidly)",
    "web_inspect": "Веб-инспекция", "webrefs": "Внешние связи", "cse": "Веб-поиск",
    "cse_social": "Социальные сети", "cse_news": "Новости", "cse_leaks": "Утечки и угрозы",
    "tech_stack": "Стек технологий", "related_domains": "Связанные домены",
    "c_identity": "Идентификация цели",
    "c_org": "Организация", "c_structure": "Корпоративная структура",
    "c_officers": "Руководство", "c_borme": "Реестр Испании (BORME)",
    "c_sec": "SEC EDGAR", "c_wikipedia": "Wikipedia",
    "c_cse": "Веб-поиск", "c_sanctions": "Санкции",
    "c_checko": "Реестр РФ (ЕГРЮЛ)", "c_financials": "Финансовые показатели",
    "c_companyscope": "Сводка из открытых источников", "c_filings": "Отчётность",
    "c_uk_ch": "Реестр Великобритании (Companies House)",
    "c_aleph": "OCCRP Aleph (утечки/санкции/связи)",
}


# ------------------ секции доменного/IP слоя (extract_domain_data) -----------
def _org(data, ctx):
    return D._gleif_org_section(data.get("gleif"), (data.get("_sources") or {}).get("org"))


def _whois(data, ctx):
    w = data.get("whois")
    if not w:
        return []
    md = ["## Регистрация домена (WHOIS / RDAP)", ""] + D._src_line(data, "whois")
    md += D._md_table(["Параметр", "Значение"], [
        ["Регистратор", w.get("registrar")],
        ["Создан", w.get("registration")],
        ["Истекает", w.get("expiration")],
        ["Изменён", w.get("last_changed")],
        ["Статусы", ", ".join(w.get("status") or [])],
        ["NS", ", ".join(w.get("nameservers") or [])],
    ])
    return md + [""]


def _dns(data, ctx):
    dns = data.get("dns")
    if not dns:
        return []
    rows = []
    for rt in ("A", "AAAA", "MX", "NS", "TXT"):
        vals = dns.get(rt) or []
        if vals:
            rows.append([rt, ", ".join(str(v) for v in vals[:12])])
    if not rows:
        return []
    return ["## DNS-записи", ""] + D._src_line(data, "dns") + \
        D._md_table(["Тип", "Значения"], rows) + [""]


def _dns_infra(data, ctx):
    """Mermaid-диаграмма DNS-топологии: домен → NS/MX."""
    dns = data.get("dns") or {}
    if not dns.get("NS") and not dns.get("MX"):
        return []
    domain = (ctx or {}).get("target") or ""
    lines = D._mermaid_dns_topology(domain, dns)
    if not lines:
        return []
    return [f"## Инфраструктура домена {domain}", ""] + lines + [""]


_MX_PROVIDERS: dict[str, str] = {
    "iphmx.com": "Cisco Secure Email (IronPort)",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "mail.protection.outlook.com": "Microsoft 365",
    "mimecast.com": "Mimecast",
    "pphosted.com": "Proofpoint",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "smtp.salesforce.com": "Salesforce",
    "mailjet.com": "Mailjet",
    "mandrillapp.com": "Mailchimp Transactional",
}


def _detect_mx_provider(dns: dict) -> str:
    """Определить почтового провайдера по MX-записям DNS."""
    providers: set[str] = set()
    for mx in (dns.get("MX") or []):
        if isinstance(mx, str):
            parts = mx.strip().split()
            host = parts[-1].rstrip(".").lower() if parts else ""
        elif isinstance(mx, dict):
            host = (mx.get("exchange") or mx.get("host") or "").rstrip(".").lower()
        else:
            host = str(mx).rstrip(".").lower()
        for suffix, name in _MX_PROVIDERS.items():
            if host.endswith(suffix) or suffix in host:
                providers.add(name)
                break
    return ", ".join(sorted(providers))


def _mail(data, ctx):
    mail = data.get("mail") or {}
    dkim_selectors = mail.get("dkim_selectors") or {}
    has_data = any(mail.get(k) for k in ("SPF", "DMARC", "MTA_STS", "BIMI", "DKIM")) or dkim_selectors
    if not has_data:
        return []
    import re
    md = ["## Почтовая безопасность (SPF / DMARC / DKIM)", ""] + D._src_line(data, "mail")
    # Провайдер из MX-записей (определяем детерминированно, без LLM)
    provider = _detect_mx_provider(data.get("dns") or {})
    if provider:
        md += [f"- **Почтовый провайдер (по MX):** {provider}"]
    if mail.get("SPF"):
        pol = "жёсткая (-all)" if "-all" in mail["SPF"] else (
            "мягкая (~all)" if "~all" in mail["SPF"] else "нестрогая")
        md += [f"- **SPF** ({pol}): `{mail['SPF']}`"]
    if mail.get("DMARC"):
        m = re.search(r"p=(\w+)", mail["DMARC"])
        pol = {"reject": "reject — отклонять", "quarantine": "quarantine — карантин",
               "none": "none — только мониторинг"}.get(m.group(1) if m else "", "—")
        md += [f"- **DMARC** (политика: {pol}): `{mail['DMARC']}`"]
    if dkim_selectors:
        sels = ", ".join(sorted(dkim_selectors.keys()))
        md += [f"- **DKIM**: ✅ найдены селекторы — {sels}"]
    elif mail.get("DKIM"):
        md += [f"- **DKIM**: найдены селекторы — {', '.join(sorted(mail['DKIM']))}"]
    else:
        md += ["- **DKIM**: ❌ не найден (проверены стандартные селекторы)"]
    if mail.get("MTA_STS"):
        md += [f"- **MTA-STS**: `{mail['MTA_STS']}`"]
    if mail.get("BIMI"):
        md += [f"- **BIMI**: `{mail['BIMI']}`"]
    return md + [""]


def _ips(data, ctx):
    ips = data.get("ips") or {}
    if not ips:
        return []
    info = data.get("ip_info") or {}
    asn = data.get("asn_by_ip") or {}
    rows = []
    for ip in sorted(ips):
        ii = info.get(ip) or {}
        rows.append([ip, ips.get(ip) or "—",
                     ii.get("name") or ii.get("organization") or "—",
                     asn.get(ip) or "—",
                     (ii.get("range") or "—"), ii.get("country") or "—"])
    return [f"## IP-адреса и сети (пассивный DNS + RDAP) — {len(ips)}", ""] + \
        D._src_line(data, "ips") + \
        D._md_table(["IP", "Дата (VT)", "Сеть/Организация", "AS", "Диапазон", "Страна"], rows) + [""] + \
        D.cap_note(data, "ips")


# IP-тип по владельцу/организации (облако vs собственная сеть) — для таблиц.
_CLOUD = [("google", "Google Cloud"), ("amazon", "AWS"), ("aws", "AWS"),
          ("microsoft", "Azure"), ("azure", "Azure"), ("cloudflare", "Cloudflare"),
          ("akamai", "Akamai"), ("fastly", "Fastly"), ("digitalocean", "DigitalOcean"),
          ("hetzner", "Hetzner"), ("ovh", "OVH"), ("incapsula", "Imperva/Incapsula"),
          ("selectel", "Selectel"), ("yandex", "Yandex Cloud")]


def _ip_kind(owner: str) -> str:
    low = (owner or "").lower()
    for key, label in _CLOUD:
        if key in low:
            return label
    return "собственная сеть" if owner and owner != "—" else "—"


def _whois_contacts(data, ctx):
    """Административные/технические/abuse-контакты из RDAP (ref Table 2)."""
    w = data.get("whois") or {}
    ents = [e for e in (w.get("entities") or []) if e.get("roles") or e.get("name")]
    if not ents:
        return []
    rows = [[", ".join(e.get("roles") or []) or "—", e.get("name") or "—",
             e.get("handle") or "—"] for e in ents[:12]]
    return ["## Контакты домена (WHOIS/RDAP)", ""] + D._src_line(data, "whois") + \
        D._md_table(["Роли", "Имя/Организация", "Handle"], rows) + [""]


def _subdomain_ips(data, ctx):
    """Резолвинг поддоменов в IP (ref Table 19): поддомен → IP → тип сети."""
    m = data.get("subdomain_ips") or {}
    m = {k: v for k, v in m.items() if v}
    if not m:
        return []
    info = data.get("ip_info") or {}
    rows = []
    for host in sorted(m)[:80]:
        ip = m[host]
        owner = (info.get(ip) or {}).get("name") or (info.get(ip) or {}).get("organization") or ""
        rows.append([host, ip, _ip_kind(owner)])
    md = [f"## Поддомены → IP ({len(m)})", ""] + D._src_line(data, "subdomain_ips")
    md += D._md_table(["Поддомен", "IP", "Тип сети (по владельцу сети)"], rows) + [""]
    missing = data.get("dns_unresolved") or []
    if missing:
        md += ["## Поддомены без текущих A/AAAA-записей", "",
               "Пустой ответ в одной из сохранённых проверок; это не доказывает, что сервис закрыт.", ""]
        md += D._md_table(["Поддомен", "Статус"], [[h, "A/AAAA не получены"] for h in missing]) + [""]
    failures = data.get("dns_failures") or []
    if failures:
        md += ["_DNS не проверен из-за ошибки: " + ", ".join(x["host"] for x in failures) + "._", ""]
    return md


def _reverse_cohost(data, ctx):
    """Совместно размещённые домены на IP цели (reverse-IP, ref Table 18/21)."""
    co = {ip: hosts for ip, hosts in (data.get("cohost") or {}).items() if hosts}
    if not co:
        return []
    rows = []
    for ip in sorted(co):
        hosts = co[ip]
        rows.append([ip, str(len(hosts)), ", ".join(hosts[:12]) +
                     (f" … +{len(hosts) - 12}" if len(hosts) > 12 else "")])
    return ["## Совместно размещённые домены (reverse-IP)", ""] + D._src_line(data, "cohost") + \
        D._md_table(["IP", "Кол-во", "Домены на этом IP"], rows) + [""]


def _geo(data, ctx):
    """Географическое распределение инфраструктуры (страны/города) — агрегат."""
    from collections import Counter
    countries, cities = Counter(), Counter()
    for ii in (data.get("ip_info") or {}).values():
        if ii.get("country"):
            countries[ii["country"]] += 1
    for a in (data.get("shodan_assets") or []):
        if a.get("country"):
            countries[str(a["country"])] += 1
    if not countries:
        return []
    rows = [[c, str(n)] for c, n in countries.most_common(15)]
    return ["## Географическое распределение инфраструктуры", ""] + \
        D._md_table(["Страна", "IP/сервисов"], rows) + [""]


def _ranges(data, ctx):
    return D._ranges_section(data.get("ip_info") or {})


def _certs(data, ctx):
    certs = data.get("certs") or []
    if not certs:
        return []
    seen, uniq = set(), []
    for c in certs:
        k = (c.get("subject"), c.get("issuer"), c.get("valid_until"))
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    active = [c for c in uniq if D._cert_active(c.get("valid_until"))]
    historical = [c for c in uniq if not D._cert_active(c.get("valid_until"))]
    md = [f"## SSL-сертификаты — {len(uniq)} "
          f"(активных: {len(active)}, исторических: {len(historical)})", ""]
    md += D._src_line(data, "certs")
    for title, group in (("Активные", active), ("Исторические / истёкшие", historical)):
        if not group:
            continue
        def _fp(c: dict) -> str:
            fp = (c.get("thumbprint") or c.get("fingerprint") or
                  c.get("sha256_fingerprint") or c.get("fingerprint_sha256") or "—")
            return fp[:16] + "…" if fp != "—" and len(fp) > 16 else fp
        has_san = any(c.get("san") for c in group)
        if has_san:
            rows = [[c.get("subject"), c.get("san") or "—", c.get("issuer"),
                     c.get("valid_until"), _fp(c)] for c in group[:25]]
            md += [f"**{title}:**", ""]
            md += D._md_table(["Subject", "SAN / Alt Names", "Issuer", "по", "Serial/Fingerprint"],
                               rows) + [""]
        else:
            rows = [[c.get("subject"), c.get("issuer"), c.get("valid_from"),
                     c.get("valid_until"), _fp(c)] for c in group[:25]]
            md += [f"**{title}:**", ""]
            md += D._md_table(["Subject", "Issuer", "Действует с", "по", "Serial/Fingerprint"],
                               rows) + [""]
        if len(group) > 25:
            md += [f"_Показаны 25 из {len(group)} записей этой группы._", ""]
    return md + D.cap_note(data, "certs")


def _subdomains(data, ctx):
    domain = ctx.get("target", "")
    subs = sorted(s for s in data.get("subdomains", set())
                  if s.endswith(domain) and s != domain)
    if not subs:
        return []
    groups: dict[str, list[str]] = {}
    for s in subs:
        groups.setdefault(D.classify_subdomain(s), []).append(s)
    md = [f"## Поддомены — {len(subs)} (сгруппированы по функции)", ""] + D._src_line(data, "subdomains")
    # Кросс-корреляция: сколько поддоменов подтверждено ≥2 независимыми источниками.
    src = data.get("subdomain_src") or {}
    if src:
        multi = sorted((s for s in subs if len(src.get(s, ())) >= 2),
                       key=lambda s: -len(src.get(s, ())))
        if multi:
            top = ", ".join(f"{s} ({len(src[s])})" for s in multi[:8])
            md += [f"- **Подтверждено ≥2 источниками:** {len(multi)} из {len(subs)}. "
                   f"Наиболее подтверждённые: {top}", ""]
    order = [f for f, _ in D._FUNC_RULES] + ["Прочее"]
    rows = []
    for func in order:
        if func in groups:
            items = groups[func]
            rows.append([func, str(len(items)), ", ".join(items[:20]) +
                         (f" … +{len(items) - 20}" if len(items) > 20 else "")])
    return (md + D._md_table(["Функция", "Кол-во", "Поддомены"], rows) + [""]
            + D.cap_note(data, "subdomains"))


def _files(data, ctx):
    files = data.get("files") or []
    if not files:
        return []
    rows = [[f.get("name"), f.get("type"), f.get("first_seen")] for f in files[:15]]
    # Это файлы, которые ОБРАЩАЛИСЬ к домену, а не файлы компании: без этой
    # оговорки таблица с .apk и .exe читалась как «вредоносное ПО цели»,
    # причём тремя разделами ниже стояло «вредоносных: 0».
    return (["## Связанные (communicating) файлы", "",
             "_Файлы, которые по данным VirusTotal обращались к домену. "
             "Принадлежности цели это не означает — как правило это сторонние "
             "образцы, замеченные в обращении к её сервисам._", ""]
            + D._src_line(data, "files")
            + D._md_table(["Файл", "Тип", "Первое появление"], rows) + [""]
            + D.cap_note(data, "files"))


def _shodan(data, ctx):
    assets = data.get("shodan_assets") or []
    if not assets:
        return []
    rows = []
    for a in assets[:25]:
        rows.append([str(a.get("ip") or "—"), str(a.get("port") or "—"),
                     (a.get("product") or a.get("service") or "—"),
                     a.get("version") or "—", str(a.get("http") or "—"),
                     a.get("org") or "—", a.get("risk") or "—"])
    return [f"## Живые активы (Shodan) — {len(assets)}", ""] + D._src_line(data, "shodan") + \
        D._md_table(["IP", "Порт", "Сервис", "Версия", "HTTP/TLS", "Организация",
                     "Потенциальные риски"], rows) + [""]


def _whois_history(data, ctx):
    hist = data.get("whois_history") or []
    if not hist:
        return []
    seen_h, rows = set(), []
    for h in hist:
        key = (h.get("registrarName"), h.get("createdDate"), h.get("updatedDate"))
        if key in seen_h:
            continue
        seen_h.add(key)
        rows.append([h.get("createdDate") or h.get("createdDateNormalized") or "—",
                     h.get("updatedDate") or "—", h.get("registrarName") or "—",
                     h.get("registrant") or "—"])
    if not rows:
        return []
    return ["## Историческая регистрация (WHOIS History)", ""] + D._src_line(data, "whois_history") + \
        D._md_table(["Создан", "Изменён", "Регистратор", "Регистрант"], rows[:15]) + [""]


def _reputation(data, ctx):
    rep = data.get("reputation")
    if not rep:
        return []
    return ["## Репутация (VirusTotal)", ""] + D._src_line(data, "reputation") + \
        D._md_table(["Показатель", "Значение"], [
            ["Reputation score", rep.get("reputation")],
            ["Вредоносные", rep.get("malicious")],
            ["Подозрительные", rep.get("suspicious")],
            ["Чистые", rep.get("clean")],
        ]) + [""]


def _typosquat(data, ctx):
    """Домены-двойники (тайпсквоттинг/фишинг) — зарегистрированные lookalike-домены."""
    items = data.get("typosquat") or []
    if not items:
        return []
    rows = []
    for it in items[:30]:
        dom = (it.get("domain") or it.get("name") or str(it))[:60]
        fuzzer = it.get("fuzzer") or it.get("type") or "—"
        ips = ", ".join(it.get("dns_a") or it.get("dns-a") or [])[:40] or "—"
        ns = ", ".join(it.get("dns_ns") or it.get("dns-ns") or [])[:40] or "—"
        rows.append([dom, fuzzer, ips, ns])
    return ([f"## Домены-двойники (тайпсквоттинг / фишинг) — {len(items)}", ""]
            + D._src_line(data, "typosquat")
            + ["_Зарегистрированные lookalike-домены. Могут использоваться для "
               "фишинга, перехвата трафика или имитации бренда._", ""]
            + D._md_table(["Домен", "Тип мутации", "IP (dns_a)", "NS"], rows) + [""])


def _voidly_status(data, ctx):
    """Доступность домена в странах (Voidly, 119+ стран)."""
    items = data.get("voidly_status") or []
    if not items:
        return []
    # Если первый элемент — сводный dict (plain-text путь), рендерим по-другому
    first = items[0] if items else {}
    if "blocked_countries" in first:
        blocked_n = first.get("blocked_countries", 0)
        isps_n = first.get("blocking_isps", 0)
        label = first.get("status_label", "")
        md = ["## Доступность по странам (Voidly)", ""]
        md += D._src_line(data, "voidly_status")
        md += [f"- **Статус:** {label}" if label else
               f"- **Статус:** {'✅ доступен' if first.get('status') == 'accessible' else '❌ заблокирован'}"]
        md += [f"- **Заблокирован в:** {blocked_n} стран, {isps_n} провайдеров"]
        md += [""]
        return md
    # JSON-путь: список дикт с country/status полями
    blocked = [i for i in items
               if (i.get("status") or i.get("accessible") or "").lower()
               in ("blocked", "restricted", "false")]
    accessible = [i for i in items
                  if (i.get("status") or i.get("accessible") or "").lower()
                  in ("accessible", "true", "ok")]
    md = [f"## Доступность по странам (Voidly) — {len(items)} стран", ""]
    md += D._src_line(data, "voidly_status")
    if blocked:
        codes = ", ".join(
            b.get("code") or b.get("country_code") or b.get("country") or "?"
            for b in blocked[:20])
        md += [f"- **Заблокирован в {len(blocked)} странах:** {codes}"]
    md += [f"- **Доступен:** {len(accessible)} стран", ""]
    return md


def _voidly_history(data, ctx):
    """История доступности домена (Voidly get_domain_history)."""
    hist = data.get("voidly_history") or []
    if not hist:
        return []
    md = ["## История доступности (Voidly)", ""]
    md += D._src_line(data, "voidly_history")
    md += ["| Дата | Доступно | Стран заблокировано |",
           "|---|---|---|"]
    for entry in hist[:15]:
        date = (entry.get("date") or entry.get("timestamp") or
                entry.get("checked_at") or entry.get("time") or "—")
        if isinstance(date, str) and len(date) > 10:
            date = date[:10]
        acc = entry.get("accessible") or entry.get("status") or ""
        accessible = "✅" if (acc is True or str(acc).lower() in ("true", "accessible", "ok")) else "❌"
        blocked = str(entry.get("blocked_countries_count") or entry.get("blocked_count") or 0)
        md.append(f"| {date} | {accessible} | {blocked} |")
    md.append("")
    return md


def _web_inspect(data, ctx):
    return D._webinspect_section(data)


def _webrefs(data, ctx):
    return D._webrefs_section(ctx.get("target", ""), data)


def _cse(data, ctx):
    return D._cse_section(data, ctx.get("identity"), ctx.get("target", ""))


_SOCIAL_DOMAINS: dict[str, str] = {
    "linkedin.com": "LinkedIn", "twitter.com": "Twitter/X", "x.com": "Twitter/X",
    "facebook.com": "Facebook", "instagram.com": "Instagram", "youtube.com": "YouTube",
    "github.com": "GitHub", "t.me": "Telegram", "vk.com": "VK",
    "tiktok.com": "TikTok", "pinterest.com": "Pinterest",
}

_NEWS_DOMAINS: frozenset = frozenset({
    "reuters.com", "bloomberg.com", "ft.com", "wsj.com", "bbc.com",
    "theguardian.com", "cnbc.com", "apnews.com", "nytimes.com",
    "expansion.com", "cincodias.elpais.com", "elconfidencial.com",
    "eleconomista.es", "elpais.com", "elmundo.es",
})

_LEAK_KEYWORDS: tuple = ("leak", "breach", "hack", "credential", "infostealer",
                          "ransomware", "dump", "утечка", "взлом", "слив")
_LEAK_DOMAINS: frozenset = frozenset({
    "hudsonrock.com", "haveibeenpwned.com", "dehashed.com",
    "cybernews.com", "bleepingcomputer.com", "darktracer.com",
    "pastebin.com", "paste.sh",
})


def _cse_all_items(data: dict) -> list[dict]:
    """Собрать все результаты из d['cse'] в плоский список dicts с полем 'url'."""
    items = []
    for c in (data.get("cse") or []):
        engine = c.get("engine", "")
        for it in (c.get("results") or []):
            item = dict(it)
            item.setdefault("_engine", engine)
            url = it.get("link") or it.get("url") or ""
            item["url"] = url
            items.append(item)
    return items


def _cse_social(data, ctx):
    """Профили в социальных сетях из результатов веб-поиска."""
    # Сначала проверяем прямой ключ cse_social (если dossier пометил запрос)
    results = []
    for c in (data.get("cse") or []):
        if c.get("engine") == "social":
            results.extend(c.get("results") or [])
    if not results:
        results = _cse_all_items(data)
    rows, seen = [], set()
    for r in results:
        url = r.get("link") or r.get("url") or ""
        title = r.get("title") or ""
        for dom, platform in _SOCIAL_DOMAINS.items():
            if dom in url and url not in seen:
                seen.add(url)
                rows.append((platform, title[:60], url))
                break
    if not rows:
        return []
    md = ["## Социальные сети", "", "| Платформа | Профиль | URL |", "|---|---|---|"]
    for platform, title, url in rows:
        md.append(f"| {platform} | {title} | {url} |")
    md.append("")
    return md


def _cse_news(data, ctx):
    """Новости из деловых СМИ (результаты веб-поиска)."""
    results = []
    for c in (data.get("cse") or []):
        if c.get("engine") == "news":
            results.extend(c.get("results") or [])
    if not results:
        results = _cse_all_items(data)
    rows, seen = [], set()
    for r in results:
        url = r.get("link") or r.get("url") or ""
        title = r.get("title") or ""
        snippet = r.get("snippet") or r.get("description") or ""
        is_news = any(nd in url for nd in _NEWS_DOMAINS)
        if is_news and url not in seen:
            seen.add(url)
            source = next((nd for nd in _NEWS_DOMAINS if nd in url), url.split("/")[2] if "/" in url else url)
            rows.append((title[:80], source, snippet[:120], url))
    if not rows:
        return []
    md = ["## Новости", "", "| Заголовок | Источник | Фрагмент |", "|---|---|---|"]
    for title, source, snippet, url in rows[:8]:
        title_link = f"[{title}]({url})"
        md.append(f"| {title_link} | {source} | {snippet} |")
    md.append("")
    return md


def _cse_leaks(data, ctx):
    """Упоминания утечек и кибератак из результатов веб-поиска."""
    results = []
    for c in (data.get("cse") or []):
        if c.get("engine") == "leaks":
            results.extend(c.get("results") or [])
    if not results:
        results = _cse_all_items(data)
    rows, seen = [], set()
    for r in results:
        url = r.get("link") or r.get("url") or ""
        title = r.get("title") or ""
        snippet = r.get("snippet") or r.get("description") or ""
        combined = (title + " " + snippet).lower()
        is_leak = (any(ld in url for ld in _LEAK_DOMAINS) or
                   any(kw in combined for kw in _LEAK_KEYWORDS))
        if is_leak and url not in seen:
            seen.add(url)
            rows.append((title[:80], snippet[:150], url))
    if not rows:
        return []
    md = ["## Утечки и угрозы", "", "| Источник | Описание |", "|---|---|"]
    for title, snippet, url in rows:
        title_link = f"[{title}]({url})"
        md.append(f"| {title_link} | {snippet} |")
    md.append("")
    return md


def _tech_stack(data, ctx):
    """Стек технологий (ContrastAPI tech_fingerprint или аналог)."""
    stack = data.get("tech_stack") or []
    if not stack:
        return []
    md = ["## Стек технологий", "", "| Технология | Категория | Версия |", "|---|---|---|"]
    for item in stack:
        tech = item.get("name") or item.get("tech") or "—"
        cat = item.get("category") or item.get("type") or "—"
        ver = item.get("version") or "—"
        md.append(f"| {tech} | {cat} | {ver} |")
    md.append("")
    return md


def _related_domains(data, ctx):
    """Связанные домены: NS/MX-хосты и цель редиректа."""
    related = data.get("related_domains") or []
    if not related:
        return []
    md = ["## Связанные домены", "",
          "| Домен | Тип связи | Регистратор | Создан | Истекает |",
          "|---|---|---|---|---|"]
    for item in related:
        domain = item.get("domain") or "—"
        rel = item.get("relationship") or "—"
        whois = item.get("whois") or {}
        registrar = whois.get("registrar") or "—"
        created = (whois.get("created") or whois.get("registration") or "—")[:10]
        expires = (whois.get("expires") or whois.get("expiration") or "—")[:10]
        md.append(f"| {domain} | {rel} | {registrar} | {created} | {expires} |")
    md.append("")
    return md


# ------------------ секции корпоративного слоя (extract_company_data) --------
_SRC_TITLE = {"sec_edgar": "SEC EDGAR", "gleif": "GLEIF (реестр LEI)",
              "wikipedia": "Wikipedia", "domain": "официальный домен",
              "gleif_hint": "GLEIF (подсказка)", "query": "запрос пользователя"}


def _c_identity(data, ctx):
    """Идентификация цели: как разговорное название стало юрлицом, чем это
    подтверждено и что отвергнуто.

    Без этого раздела досье утверждало личность цели без доказательств: запрос
    «Meta» точно совпал с датской фирмой-пустышкой META, и её карточка ушла в
    резюме, хотя вся инфраструктура принадлежит Meta Platforms."""
    ident = data.get("identity") or ctx.get("identity")
    if not ident:
        return []
    md = ["## Идентификация цели", ""]
    chosen = ident.get("legal_name")
    rows = [["Исходный запрос", ident.get("query")],
            ["Каноническое юр. имя", chosen or "не подтверждено"],
            ["LEI", ident.get("lei")], ["CIK", ident.get("cik")],
            ["Тикеры", ", ".join(ident.get("tickers") or []) or None],
            ["Юрисдикция", ident.get("jurisdiction")],
            ["Официальные домены", ", ".join(ident.get("domains") or []) or None],
            ["Независимых подтверждений", str(ident.get("confirms", 0))],
            ["Уверенность", ident.get("confidence")]]
    md += D._md_table(["Параметр", "Значение"], rows) + [""]
    cands = [c for c in (ident.get("candidates") or [])
             if c.get("sources") != ["query"]]
    if len(cands) > 1 or (cands and not chosen):
        md += ["Отвергнутые кандидаты приводятся явно — чтобы решение можно было "
               "перепроверить, а не принимать на веру.", "",
               "**Рассмотренные кандидаты**", ""]
        crows = []
        for c in cands[:8]:
            srcs = ", ".join(_SRC_TITLE.get(s, s) for s in c.get("sources") or [])
            why = "; ".join(c.get("why") or []) or "—"
            if c.get("rejected"):
                why = f"{c['rejected']}" + (f"; {why}" if why != "—" else "")
            crows.append([c.get("name"), c.get("jurisdiction") or "—", srcs,
                          str(c.get("score", 0)),
                          "✅ выбран" if c.get("chosen") else "✗ отклонён", why])
        md += D._md_table(
            ["Кандидат", "Юрисдикция", "Подтверждения", "Балл", "Итог", "Обоснование"],
            crows) + [""]
    if not chosen:
        md += ["**Вывод:** ⚠ юрлицо не опознано — ни один кандидат не набрал "
               "достаточных независимых подтверждений. Данные реестров ниже "
               "не приводятся: приписать цели чужое юрлицо хуже, чем признать "
               "пробел. Повторите запрос с точным юридическим названием или LEI.", ""]
    elif ident.get("confidence") != "высокая":
        md += [f"**Вывод:** ⚠ гипотеза — «{chosen}» подтверждено "
               f"{ident.get('confirms', 0)} источником; трактуйте корпоративный "
               f"слой как предварительный.", ""]
    return md


def _c_checko(data, ctx):
    """Карточка ЕГРЮЛ/ЕГРИП (Checko). Раньше ответ checko не разбирался вообще
    и попадал только в сырое приложение."""
    ck = data.get("checko")
    if not ck:
        return []
    md = ["## Реестр РФ (ЕГРЮЛ / ЕГРИП)", ""] + D._src_line(data, "c_checko")
    md += D._md_table(["Параметр", "Значение"], [
        ["Наименование", ck.get("name")], ["ИНН", ck.get("inn")],
        ["ОГРН", ck.get("ogrn")], ["КПП", ck.get("kpp")],
        ["Статус", ck.get("status")], ["Дата регистрации", ck.get("registered")],
        ["Юр. адрес", ck.get("address")], ["ОКВЭД", ck.get("okved")],
        ["Уставный капитал", str(ck.get("capital")) if ck.get("capital") else None],
        ["Руководитель", ck.get("director")],
        ["Учредители", ", ".join(ck.get("founders") or []) or None],
    ]) + [""]
    return md


def _fmt_money(v) -> str:
    """Крупные суммы — в млрд/млн: сырые 15 цифр в таблице нечитаемы."""
    if not isinstance(v, (int, float)):
        return "—"
    a = abs(v)
    if a >= 1e9:
        return f"{v / 1e9:,.2f} млрд".replace(",", " ")
    if a >= 1e6:
        return f"{v / 1e6:,.1f} млн".replace(",", " ")
    return f"{v:,.0f}".replace(",", " ")


def _c_financials(data, ctx):
    """Финансовые показатели: XBRL SEC (годовые) и/или рыночные котировки (Yahoo Finance)."""
    fin = data.get("financials")
    sq = data.get("stock_quote")
    fin_raw = data.get("financials_raw")
    ticker_cands = data.get("ticker_candidates") or []
    if not fin and not sq and not fin_raw and not ticker_cands:
        return []
    md = []
    # Рыночные данные (Yahoo Finance / stock_quote)
    if isinstance(sq, dict) and sq.get("price") is not None:
        def _m(v):
            if v is None:
                return "—"
            if isinstance(v, float) and v > 1e8:
                return f"{v/1e9:.2f} B"
            if isinstance(v, (int, float)) and v > 1e5:
                return f"{v/1e6:.1f} M"
            return str(v)
        rows = []
        if sq.get("price") is not None:
            rows.append(["Цена", f"{sq['price']} {sq.get('currency', '')}"])
        if sq.get("market_cap"):
            rows.append(["Капитализация", _m(sq["market_cap"])])
        if sq.get("pe_ratio"):
            rows.append(["P/E (trailing)", str(round(sq["pe_ratio"], 2))])
        if sq.get("forward_pe"):
            rows.append(["P/E (forward)", str(round(sq["forward_pe"], 2))])
        if sq.get("52w_high") and sq.get("52w_low"):
            rows.append(["52W диапазон", f"{sq['52w_low']} – {sq['52w_high']}"])
        if sq.get("revenue"):
            rows.append(["Выручка", _m(sq["revenue"])])
        if sq.get("ebitda"):
            rows.append(["EBITDA", _m(sq["ebitda"])])
        if sq.get("net_income"):
            rows.append(["Чистая прибыль", _m(sq["net_income"])])
        if sq.get("employees"):
            rows.append(["Сотрудников", str(sq["employees"])])
        if rows:
            md += [f"## Финансовые показатели — {sq.get('name', sq.get('ticker', ''))} "
                   f"({sq.get('ticker', '')} · {sq.get('exchange', '')})", ""]
            md += D._src_line(data, "c_financials")
            md += D._md_table(["Показатель", "Значение"], rows) + [""]
    # Годовая отчётность SEC
    if isinstance(fin, dict) and fin.get("metrics"):
        years = [str(y) for y in (fin.get("years") or [])]
        if years:
            md += [f"## Финансовые показатели ({fin.get('currency', 'USD')}, "
                   f"годовая отчётность)", ""] + D._src_line(data, "c_financials")
            rows = []
            for label, series in (fin.get("metrics") or {}).items():
                rows.append([label] + [_fmt_money(series.get(y)) for y in years])
            md += D._md_table(["Показатель"] + years, rows) + [""]
            md += [f"_Источник: {fin.get('source', 'SEC XBRL')}; "
                   f"эмитент {fin.get('name')} (CIK {fin.get('cik')})._", ""]
    # Биржевые данные от StockScope (когда SEC/Yahoo Finance недоступны)
    if fin_raw and not fin and not sq:
        md += ["## Финансовые данные (биржа)", "", "```", str(fin_raw).strip()[:1800], "```", ""]
    # Тикеры-кандидаты (когда котировки не получены)
    if ticker_cands and not sq:
        tickers = [c.get("ticker") or c.get("symbol") or "" for c in ticker_cands if c]
        tickers = [t for t in tickers if t]
        if tickers:
            md += [f"**Возможные биржевые тикеры:** {', '.join(tickers)}", ""]
    return md


def _c_companyscope(data, ctx):
    """Сводка из открытых источников (CompanyScope). Извлекалась и никем
    не рисовалась — чистый потерянный слой."""
    cs = data.get("companyscope")
    if not cs:
        return []
    return (["## Сводка из открытых источников", ""] + D._src_line(data, "c_companyscope")
            + ["```", str(cs).strip()[:2000], "```", ""])


def _c_filings(data, ctx):
    """Лента отчётности (FilingFirehose). Тоже извлекалась и не рисовалась."""
    f = data.get("filings")
    if not f:
        return []
    return ["## Отчётность (лента)", "", "```", str(f).strip()[:1800], "```", ""]


def _c_org(data, ctx):
    name = ctx.get("target", "")
    g = data.get("gleif")
    md = D._gleif_org_section(g, (data.get("_sources") or {}).get("org"))
    # Добавляем CIF, если нашли в CSE-результатах и GLEIF его не вернул.
    cif = data.get("cif")
    if cif and md:
        md.insert(-1, f"_CIF/NIF: {cif} (из веб-поиска)_")
        md.insert(-1, "")
    # Юрлицо не опознано — честно, с подсказками (не подставляем чужое).
    if not g and data.get("gleif_hint"):
        hints = (data["gleif_hint"].get("did_you_mean") or [])[:5]
        md += ["## Организация (реестр LEI / GLEIF)", "",
               f"Точного совпадения с юридическим названием по запросу «{name}» "
               f"в GLEIF не найдено — данные реестра не приводятся, чтобы не "
               f"приписать цели чужое юрлицо.", ""]
        if hints:
            md += ["Похожие юрлица в реестре (проверьте вручную): "
                   + ", ".join(f"«{h}»" for h in hints) + ".", "",
                   "_Повторите запрос с точным юридическим названием или 20-значным LEI._", ""]
    if cif and not g:
        md += [f"_CIF/NIF: {cif} (из веб-поиска)_", ""]
    return md


def _c_structure(data, ctx):
    g = data.get("gleif")
    if not (g and (g.get("ultimate_parent") or g.get("direct_children"))):
        return []
    md = ["## Корпоративная структура", ""]
    if g.get("ultimate_parent"):
        md += [f"- **Материнская компания:** {g['ultimate_parent']}"]
    kids = g.get("direct_children") or []
    if kids:
        md += [f"- **Дочерние ({len(kids)}):** " + ", ".join(kids)]
    md += [""]
    return md + D._mermaid_org(ctx.get("target", ""), g) + [""]


def _c_officers(data, ctx):
    off = data.get("officers")
    if not (off and off.get("officers")):
        # Источник упал ≠ должностных лиц нет. Раньше Connectify/401 у
        # OpenCorporates молча превращался в утверждение «руководство
        # отсутствует» — фабрикация отрицательного факта из сбоя инструмента.
        why = next((f["reason"] for f in (data.get("_failed") or [])
                    if f.get("tool") == "opencorporates_officers"), None)
        if why:
            return ["## Руководство и должностные лица", "",
                    f"_Данные не получены: источник недоступен ({why}). "
                    f"Это НЕ означает, что должностных лиц нет._", ""]
        return []
    rows = [[o.get("name") or "—", o.get("position") or "—",
             o.get("start_date") or "—", o.get("end_date") or "—"]
            for o in off["officers"][:40]]
    md = [f"## Руководство и должностные лица — {off.get('officers_count', len(rows))} "
          f"(OpenCorporates, {off.get('jurisdiction', '?')})", ""]
    md += D._md_table(["Имя", "Должность", "С", "По"], rows) + [""]
    if off.get("registry_url"):
        md += [f"_Источник в реестре: {off['registry_url']}_", ""]
    return md


def _c_borme(data, ctx):
    borme = data.get("borme")
    if not borme:
        return []
    md = ["## Реестр Испании (BORME / Registro Mercantil)", ""]
    rows = [
        ["Наименование", borme.get("name")],
        ["CIF/NIF", borme.get("nif")],
        ["Дата регистрации", borme.get("date_constitution")],
        ["Последнее обновление", borme.get("date_updated")],
        ["Число актов BORME", borme.get("num_announcements")],
        ["Адрес", borme.get("address")],
        ["Капитал", borme.get("capital")],
    ]
    md += D._md_table(["Параметр", "Значение"],
                      [[k, v] for k, v in rows if v]) + [""]
    if borme.get("scope"):
        md += [f"_{borme['scope']}._", ""]
    events = borme.get("officer_events") or []
    if events:
        md += [f"_Показано {min(100, len(events))} из {len(events)} извлечённых событий._", ""]
        md += ["## Представители и apoderados — события BORME", "",
               "Назначение в отдельном бюллетене не доказывает действующие полномочия: "
               "для этого нужна полная история последующих отзывов.", ""]
        md += D._md_table(["Имя", "Роль", "Событие", "Дата регистрации", "Акт"], [
            [p["name"], p["role"], p["event"], p.get("date"),
             f"[{p['act']}]({p['url']})"] for p in events[:100]]) + [""]
        md += ["## Виды представительских полномочий", "",
               "- **Apoderado:** представитель по доверенности; не обязательно член совета.",
               "- **Apoderado solidario (Apo.Sol.):** самостоятельное действие в пределах доверенности.",
               "- **Apoderado mancomunado:** совместное действие с другими уполномоченными.",
               "- **Mancomunado/solidario:** условия зависят от конкретной доверенности.",
               "Должность, подразделение и область ответственности из одной доверенности не выводятся.", ""]
    acts = borme.get("announcements") or []
    if acts:
        md += [f"_Показано {min(18, len(acts))} из {len(acts)} актов; выдержки до 700 символов._", ""]
        md += ["## Корпоративные события в официальных бюллетенях", ""]
        md += D._md_table(["Акт", "Дата регистрации", "Содержание (выдержка)"], [
            [f"[{a['number']}]({a['url']})", a.get("registry_date"), a["text"][:700]]
            for a in acts[:18]]) + [""]
    officers = borme.get("officers") or []
    if officers:
        # Сортируем по дате последнего упоминания (свежие — первыми)
        officers = sorted(officers, key=lambda o: o.get("last_seen") or "", reverse=True)
        md += [f"**Должностные лица и апoderados — {len(officers)}**", ""]
        md += D._md_table(
            ["Имя", "Роли", "Первое упоминание", "Последнее упоминание"],
            [[o.get("name") or "—",
              ", ".join(o.get("roles") or []) or "—",
              o.get("first_seen") or "—",
              o.get("last_seen") or "—"]
             for o in officers[:40]],
        ) + [""]
    if borme.get("url"):
        md += [f"_Источник: [{borme['url']}]({borme['url']})_", ""]
    return md


def _c_sec(data, ctx):
    sec = data.get("sec")
    if not sec:
        return []
    md = ["## Юр. сведения и отчётность (SEC EDGAR, США)", ""]
    md += D._md_table(["Параметр", "Значение"], [
        ["Наименование", sec.get("name")], ["CIK", sec.get("cik")],
        ["Тикеры", ", ".join(sec.get("tickers") or []) or None],
        ["Биржи", ", ".join(sec.get("exchanges") or []) or None],
        ["Отрасль (SIC)", f"{sec.get('sic') or ''} {sec.get('sic_description') or ''}".strip()],
        ["Штат регистрации", sec.get("state_of_incorporation")],
        ["Тип лица", sec.get("entity_type")], ["Адрес", sec.get("address")],
    ])
    fil = sec.get("recent_filings") or []
    if fil:
        md += ["", "**Последние отчёты SEC:**", ""]
        md += D._md_table(["Форма", "Дата", "Документ"],
                          [[f.get("form"), f.get("date"), f.get("doc")] for f in fil[:12]])
    if sec.get("edgar_url"):
        md += ["", f"_Профиль: {sec['edgar_url']}_"]
    return md + [""]


def _c_wikipedia(data, ctx):
    wiki = data.get("wikipedia")
    if not wiki:
        return []
    md = [f"## Контекст (Wikipedia, {wiki.get('lang', '')})", ""]
    if wiki.get("description"):
        md += [f"*{wiki['description']}*", ""]
    if wiki.get("extract"):
        md += [wiki["extract"], ""]
    doms = wiki.get("external_domains") or []
    if doms:
        md += [f"**Ссылочный профиль статьи** ({wiki.get('external_link_count', 0)} внешних "
               f"ссылок; топ-домены):", ""]
        md += D._md_table(["Домен", "Ссылок"],
                          [[d.get("domain"), str(d.get("count"))] for d in doms[:15]])
    if wiki.get("url"):
        md += ["", f"_Статья: {wiki['url']}_"]
    return md + [""]


def _c_sanctions(data, ctx):
    if not data.get("sanctions"):
        return []
    return ["## Санкционный скрининг (The Stall / OFAC)", "",
            "```", data["sanctions"].strip()[:1000], "```", ""]


def _c_uk_ch(data, ctx):
    """Реестр Великобритании (Companies House API)."""
    ch = data.get("uk_ch")
    if not ch:
        return []
    items = (ch.get("items") or [])[:10]
    if not items:
        return []
    md = [f"## Реестр Великобритании (Companies House) — {ch.get('total_results', len(items))} совпадений",
          ""] + D._src_line(data, "c_uk_ch")
    rows = []
    for it in items:
        addr = it.get("address") or ""
        if isinstance(addr, dict):
            addr = ", ".join(x for x in [
                addr.get("address_line_1"), addr.get("locality"),
                addr.get("postal_code"), addr.get("country")] if x)
        rows.append([
            it.get("title") or "—",
            it.get("company_number") or "—",
            it.get("company_status") or "—",
            it.get("company_type") or "—",
            it.get("date_of_creation") or "—",
            str(addr) or "—",
        ])
    md += D._md_table(["Наименование", "Номер", "Статус", "Тип", "Дата рег.", "Адрес"], rows)
    return md + [""]


def _c_aleph(data, ctx):
    """OCCRP Aleph — сущности из утечек, структурированных данных, санкционных списков."""
    aleph = data.get("aleph")
    if not aleph:
        return []
    results = (aleph.get("results") or [])[:12]
    if not results:
        return []
    md = [f"## OCCRP Aleph — {aleph.get('total', {}).get('value', len(results))} сущностей",
          ""] + D._src_line(data, "c_aleph")
    md += ["_Источники: утечки, структурированные реестры, санкционные списки OCCRP._", ""]
    rows = []
    for r in results:
        caption = (r.get("caption") or "—")[:60]
        schema = r.get("schema") or "—"
        collection = (r.get("collection") or {}).get("label") or "—"
        countries = ", ".join(r.get("countries") or [])[:40] or "—"
        rows.append([caption, schema, collection, countries])
    md += D._md_table(["Сущность", "Тип", "Коллекция", "Страны"], rows)
    return md + [""]


# ------------------------ упорядоченный реестр секций -----------------------
_D = frozenset({DOMAIN})
_DI = frozenset({DOMAIN, IP})
_C = frozenset({COMPANY})
SECTIONS: list[Section] = [
    # --- корпоративный слой: идентификация ПЕРВОЙ. Пока не установлено, кто
    # цель, остальные разделы нечего утверждать.
    Section("c_identity", _C, _c_identity),
    # --- доменный/IP слой ---
    Section("org", _D, _org),
    Section("whois", _D, _whois),
    Section("whois_contacts", _D, _whois_contacts),
    Section("dns", _D, _dns),
    Section("dns_infra", _D, _dns_infra),
    Section("mail", _D, _mail),
    Section("ips", _DI, _ips),
    Section("ranges", _DI, _ranges),
    Section("reverse_cohost", _DI, _reverse_cohost),
    Section("geo", _DI, _geo),
    Section("certs", _DI, _certs),
    Section("subdomains", _D, _subdomains),
    Section("subdomain_ips", _D, _subdomain_ips),
    Section("files", _DI, _files),
    Section("shodan", _DI, _shodan),
    Section("whois_history", _D, _whois_history),
    Section("typosquat", _D, _typosquat),
    Section("voidly_status", _D, _voidly_status),
    Section("voidly_history", _D, _voidly_history),
    Section("reputation", _DI, _reputation),
    Section("web_inspect", _D, _web_inspect),
    Section("tech_stack", _D, _tech_stack),
    Section("webrefs", _D, _webrefs),
    Section("related_domains", _D, _related_domains),
    Section("cse", _D, _cse),
    Section("cse_social", _D, _cse_social),
    Section("cse_news", _D, _cse_news),
    Section("cse_leaks", _D, _cse_leaks),
    # --- корпоративный слой (kind=company; порядок как в прежнем render_company_sections) ---
    Section("c_official", _C, official.render),
    Section("c_org", _C, _c_org),
    Section("c_checko", _C, _c_checko),
    Section("c_structure", _C, _c_structure),
    Section("c_officers", _C, _c_officers),
    Section("c_borme", _C, _c_borme),
    Section("c_sec", _C, _c_sec),
    Section("c_financials", _C, _c_financials),
    Section("c_filings", _C, _c_filings),
    Section("c_companyscope", _C, _c_companyscope),
    Section("c_wikipedia", _C, _c_wikipedia),
    Section("c_cse", _C, _cse),
    Section("c_sanctions", _C, _c_sanctions),
    Section("c_uk_ch", _C, _c_uk_ch),
    Section("c_aleph", _C, _c_aleph),
]
