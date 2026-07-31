"""Детерминированная сборка ГЛУБОКОГО досье по домену.

Ключевая идея: таблицы данных (поддомены, пассивный DNS, сертификаты, DNS,
WHOIS, IP/AS) строятся КОДОМ из ответов источников — точно и плотно, без
выдумывания и без зависимости от силы LLM. LLM пишет только повествование
(резюме + выводы) поверх уже извлечённых структур.

Парсит: directapi (чистый JSON) + текстовые ответы VirusTotal (resolutions /
subdomains / historical_ssl_certificates / communicating_files / отчёт).
"""
from __future__ import annotations

import json
import re

# ------------------------- эвристика группировки поддоменов ------------------
_FUNC_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Почта", ("mail", "mx", "smtp", "imap", "pop", "webmail", "owa", "exchange",
               "correo", "zimbra", "mailhost")),
    ("Аутентификация / SSO", ("sso", "auth", "login", "adfs", "idp", "oauth",
                              "saml", "sts", "account", "identity", "acs")),
    ("Удалённый доступ / VPN", ("vpn", "remote", "gw", "gateway", "access",
                                "citrix", "rdp", "anyconnect")),
    ("Мониторинг", ("monitor", "grafana", "nagios", "zabbix", "status", "health",
                    "metrics", "prometheus", "kibana", "splunk")),
    ("Бизнес-приложения / ERP", ("erp", "sap", "portal", "crm", "hr", "rrhh",
                                 "intranet", "workspace", "sharepoint", "confluence",
                                 "jira", "auraportal", "onevision")),
    ("API / сервисы", ("api", "ws", "rest", "service", "svc", "gql", "graphql")),
    ("Разработка / тест", ("dev", "test", "staging", "stage", "qa", "uat", "lab",
                           "demo", "pre", "sandbox", "ibedev")),
    ("CDN / статика", ("cdn", "static", "assets", "img", "images", "cache", "media")),
    ("Веб-сайт", ("www", "web", "web2", "portal2")),
]


def classify_subdomain(host: str) -> str:
    low = host.lower()
    label = low.split(".")[0]
    for func, keys in _FUNC_RULES:
        if any(k in label for k in keys):
            return func
    return "Прочее"


# ------------------------------- парсеры VT ---------------------------------
def _vt_resolutions(text: str) -> list[tuple[str, str]]:
    """[(ip, date)] из VT resolutions."""
    out = []
    for m in re.finditer(r"IP:\s*([0-9a-fA-F:.]+)\s*(?:\(([^)]+)\))?", text):
        ip = m.group(1).strip().rstrip(".")
        if re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$", ip) or ":" in ip:
            out.append((ip, (m.group(2) or "").strip()))
    return out


def _vt_subdomains(text: str) -> list[str]:
    """Поддомены из строк '• host'."""
    out = []
    for ln in text.splitlines():
        s = ln.strip().lstrip("•").strip()
        if re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+\.[a-z]{2,}", s, re.I):
            out.append(s.lower())
    return out


_CERT_KEYS = ("Subject", "Issuer", "Valid From", "Valid Until", "Serial",
              "Fingerprint", "Thumbprint")


def _cert_field(block: str, key: str) -> str:
    """Значение поля сертификата, останавливаясь у следующего ключа или переноса
    строки (работает и для многострочного, и для однострочного формата VT)."""
    others = "|".join(re.escape(k) for k in _CERT_KEYS if k != key)
    m = re.search(rf"{re.escape(key)}:\s*(.+?)(?=\s*(?:{others})\s*:|\n|$)", block)
    return m.group(1).strip() if m else ""


def _vt_certs(text: str) -> list[dict]:
    """SSL-сертификаты из historical_ssl_certificates (Subject/Issuer/Valid…)."""
    out = []
    for block in re.split(r"•\s*SSL Certificate", text)[1:]:
        subj = _cert_field(block, "Subject")
        iss = _cert_field(block, "Issuer")
        if subj or iss:
            out.append({
                "subject": subj[:80],
                "issuer": iss[:80],
                "valid_from": _cert_field(block, "Valid From")[:40],
                "valid_until": _cert_field(block, "Valid Until")[:40],
                "thumbprint": (_cert_field(block, "Thumbprint")
                               or _cert_field(block, "Fingerprint"))[:60],
            })
    return out


def _vt_files(text: str) -> list[dict]:
    """Связанные (communicating) файлы: имя/тип/дата — best-effort."""
    out = []
    for block in re.split(r"\n\s*•\s*", text)[1:]:
        typ = re.search(r"Type:\s*(.+)", block)
        seen = re.search(r"First Seen:\s*(.+)", block)
        name = block.strip().splitlines()[0].strip()[:60] if block.strip() else ""
        if typ or seen:
            out.append({"name": name, "type": typ.group(1).strip()[:40] if typ else "",
                        "first_seen": seen.group(1).strip()[:30] if seen else ""})
    return out[:15]


def _vt_whois_history(text: str) -> list[dict]:
    """Исторические WHOIS-снимки из VT (best-effort по блокам)."""
    out = []
    for block in re.split(r"\n\s*•\s*", text)[1:]:
        reg = re.search(r"Registrar(?:\s*Name)?:\s*(.+)", block)
        created = re.search(r"(?:Created|Creation)(?:\s*Date)?:\s*(.+)", block)
        updated = re.search(r"(?:Updated|Last Updated)(?:\s*Date)?:\s*(.+)", block)
        if reg or created:
            out.append({"registrarName": reg.group(1).strip()[:60] if reg else "",
                        "createdDate": created.group(1).strip()[:40] if created else "",
                        "updatedDate": updated.group(1).strip()[:40] if updated else ""})
    return out[:10]


def _vt_reputation(text: str) -> dict | None:
    rep = re.search(r"Reputation Score:\s*(-?\d+)", text)
    mal = re.search(r"Malicious:\s*(\d+)", text)
    sus = re.search(r"Suspicious:\s*(\d+)", text)
    clean = re.search(r"(?:Clean|Harmless):\s*(\d+)", text)
    if not (rep or mal or clean):
        return None
    return {"reputation": rep.group(1) if rep else None,
            "malicious": mal.group(1) if mal else "0",
            "suspicious": sus.group(1) if sus else "0",
            "clean": clean.group(1) if clean else None}


def _load_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


# --------------------------- Shodan → таблица активов -----------------------
# Порты, к которым привязываем типовые риск-заметки (для колонки «риски»).
_PORT_RISK = {
    23: "Telnet — открытый нешифрованный доступ",
    161: "SNMP — раскрытие конфигурации/усиление DDoS",
    179: "BGP — маршрутизатор виден извне",
    123: "NTP — усиление DDoS при monlist",
    445: "SMB — историческая поверхность атак",
    3389: "RDP — брутфорс/эксплойты",
    21: "FTP — часто анонимный/устаревший",
    3306: "MySQL — БД доступна извне",
    5432: "PostgreSQL — БД доступна извне",
    6379: "Redis — часто без аутентификации",
    9200: "Elasticsearch — часто без аутентификации",
}


def _banner_label(service: str) -> str:
    """Короткая метка сервиса из баннера Shodan (первая осмысленная строка)."""
    for ln in (service or "").splitlines():
        ln = ln.strip()
        if ln:
            return ln[:60]
    return ""


def _shodan_assets(text: str) -> list[dict]:
    """Разбор ответа Shodan ip_lookup в список сервисов (актив на порт). Понимает
    формат mcp-shodan ('IP Information'/'Location'/'Services') и чистый JSON API
    ('ip_str'/'data'). Best-effort — JSON может быть внутри текста."""
    j = _load_json(text)
    if not isinstance(j, dict):
        a, b = text.find("{"), text.rfind("}")
        if a >= 0 and b > a:
            j = _load_json(text[a:b + 1])
    if not isinstance(j, dict):
        return []
    out: list[dict] = []
    # --- формат mcp-shodan (@burtthecoder): "IP Information" / "Services" ---
    if "IP Information" in j or "Services" in j:
        info = j.get("IP Information") or {}
        loc = j.get("Location") or {}
        ip = info.get("IP Address")
        org = info.get("Organization") or info.get("ISP")
        asn = info.get("ASN")
        country = loc.get("Country")
        for s in (j.get("Services") or [])[:25]:
            if not isinstance(s, dict):
                continue
            port = s.get("Port")
            http = s.get("HTTP") or {}
            banner = _banner_label(s.get("Service") or "")
            out.append({
                "ip": ip, "org": org, "asn": asn, "country": country, "port": port,
                "service": (s.get("Protocol") or "") + (f" · {banner}" if banner else ""),
                "product": http.get("Server") or "",
                "version": "",
                "http": banner[:40] if banner else "",
                "risk": _PORT_RISK.get(port, ""),
            })
        return out
    # --- чистый Shodan REST: ip_str / data[] ---
    ip = j.get("ip_str") or j.get("ip")
    org = j.get("org") or j.get("isp")
    asn = j.get("asn")
    country = j.get("country_name") or j.get("country_code")
    services = j.get("data") if isinstance(j.get("data"), list) else []
    if not services and (j.get("ports") or ip):
        for p in (j.get("ports") or [])[:20]:
            out.append({"ip": ip, "org": org, "asn": asn, "country": country,
                        "port": p, "service": "", "product": "", "version": "",
                        "http": "", "risk": _PORT_RISK.get(p, "")})
        return out
    for s in services[:25]:
        if not isinstance(s, dict):
            continue
        port = s.get("port")
        http = s.get("http") or {}
        ssl = s.get("ssl") or {}
        out.append({
            "ip": ip, "org": org, "asn": asn, "country": country, "port": port,
            "service": s.get("transport") or "",
            "product": (s.get("product") or "")[:40],
            "version": str(s.get("version") or "")[:20],
            "http": str(http.get("status") or "") if http else ("TLS" if ssl else ""),
            "risk": _PORT_RISK.get(port, ""),
        })
    return out


# --------------------------- извлечение структуры ---------------------------
def extract_domain_data(results: list[dict]) -> dict:
    """Свести ответы всех источников в структурированное досье (без выдумывания)."""
    d: dict = {"whois": None, "dns": None, "mail": {}, "ips": {}, "certs": [],
               "subdomains": set(), "files": [], "reputation": None,
               "gleif": None, "ip_info": {}, "shodan_assets": [],
               "whois_history": [], "webpages": [], "_sources": {}}
    # Провенанс: какой источник (отображаемое имя + инструмент) наполнил каждую
    # секцию. Из него render_sections печатает «_Источник: …_» под заголовком —
    # чтобы было видно, что таблицы построены из реальных ответов инструментов.
    def prov(cat: str, r: dict, tool: str = "") -> None:
        nm = r.get("name") or r.get("server") or "?"
        label = f"{nm} ({tool})" if tool else nm
        d["_sources"].setdefault(cat, [])
        if label not in d["_sources"][cat]:
            d["_sources"][cat].append(label)

    for r in results:
        if not r.get("ok"):
            continue
        sid = r.get("server")
        tool = r.get("tool", "")
        text = r.get("text", "") or ""
        # directapi — чистый JSON
        if sid == "directapi":
            j = _load_json(text)
            if not isinstance(j, dict):
                continue
            if tool == "rdap_domain" and not j.get("error"):
                d["whois"] = j; prov("whois", r, "rdap_domain")
            elif tool == "rdap_ip" and not j.get("error"):
                ip = j.get("ip")
                if ip:
                    d["ip_info"][ip] = j; prov("ips", r, "rdap_ip")
            elif tool == "dns_records" and not j.get("error"):
                d["dns"] = j; prov("dns", r, "dns_records")
                for k in ("SPF", "DMARC", "MTA_STS", "BIMI", "DKIM"):
                    if j.get(k):
                        d["mail"][k] = j[k]
                if d["mail"]:
                    prov("mail", r, "dns_records")
                for ip in (j.get("A") or []):
                    d["ips"].setdefault(ip, "")
            elif tool == "crtsh" and not j.get("error"):
                if j.get("subdomains"):
                    prov("subdomains", r, "crtsh")
                for s in (j.get("subdomains") or []):
                    d["subdomains"].add(s)
            elif tool == "gleif_entity" and not j.get("error"):
                d["gleif"] = j; prov("org", r, "gleif_entity")
            elif tool == "whois_history" and not j.get("error"):
                if j.get("records"):
                    prov("whois_history", r, "whois_history")
                d["whois_history"].extend(j.get("records") or [])
        # Shodan — карточка хоста (порты/сервисы/баннеры) → таблица активов.
        elif sid == "shodan":
            got = _shodan_assets(text)
            if got:
                prov("shodan", r, "ip_lookup")
            d["shodan_assets"].extend(got)
        # Bright Data — контент страниц сайта (для секции «внешние связи»).
        elif sid == "brightdata":
            if text.strip():
                d["webpages"].append(text)
                prov("webrefs", r, "scrape_as_markdown")
        # VirusTotal — текст. Триггерим по ТОЧНОМУ заголовку секции VT
        # ("… — <relationship>"), иначе имя связи, упомянутое в другом ответе,
        # ложно наполняет секцию (напр. пустые communicating_files).
        elif sid == "virustotal":
            if "— resolutions" in text:
                for ip, dt in _vt_resolutions(text):
                    if ip not in d["ips"] or not d["ips"][ip]:
                        d["ips"][ip] = dt
                prov("ips", r, "resolutions")
            if "— subdomains" in text:
                for s in _vt_subdomains(text):
                    d["subdomains"].add(s)
                prov("subdomains", r, "subdomains")
            if "SSL Certificate" in text and "ssl_certificates" in text:
                d["certs"].extend(_vt_certs(text)); prov("certs", r, "ssl_certificates")
            if "— communicating_files" in text:
                d["files"].extend(_vt_files(text)); prov("files", r, "communicating_files")
            if "— historical_whois" in text:
                d["whois_history"].extend(_vt_whois_history(text))
                prov("whois_history", r, "historical_whois")
            rep = _vt_reputation(text)
            if rep and not d["reputation"]:
                d["reputation"] = rep; prov("reputation", r, "get_domain_report")
        # subfinder / contrastapi — вытащим поддомены из текста
        elif sid in ("vulneramcp", "contrastapi"):
            before = len(d["subdomains"])
            for s in _vt_subdomains(text):
                d["subdomains"].add(s)
            j = _load_json(text)
            if isinstance(j, dict):
                for key in ("subdomains", "sub_domains"):
                    for s in (j.get(key) or []):
                        if isinstance(s, str):
                            d["subdomains"].add(s.lower())
            if len(d["subdomains"]) > before:
                prov("subdomains", r, tool)
    return d


# ------------------------------- рендер таблиц ------------------------------
def _src_line(data: dict, cat: str) -> list[str]:
    """Строка провенанса «_Источник: …_» под заголовком секции (какие инструменты
    дали эти данные). Пусто, если провенанс не записан."""
    srcs = (data.get("_sources") or {}).get(cat) or []
    if not srcs:
        return []
    return [f"_Источник: {', '.join(srcs)}_", ""]


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join((c or "—").replace("|", "\\|") for c in row) + " |")
    return out


def _gleif_org_section(g: dict | None, sources: list | None = None) -> list[str]:
    """Таблица юр. идентичности из GLEIF (общая для домен- и компания-досье)."""
    if not (g and g.get("legal_name")):
        return []
    addr = g.get("address") or {}
    addr_s = ", ".join(x for x in [
        " ".join(addr.get("lines") or []), addr.get("city"),
        addr.get("postal_code"), addr.get("country")] if x)
    md = ["## Организация (реестр LEI / GLEIF)", ""]
    if sources:
        md += [f"_Источник: {', '.join(sources)}_", ""]
    md += _md_table(["Параметр", "Значение"], [
        ["Юридическое название", g.get("legal_name")],
        ["LEI", g.get("lei")],
        ["Адрес", addr_s],
        ["Юрисдикция", g.get("jurisdiction")],
        ["Правовая форма", g.get("legal_form")],
        ["Рег. номер", g.get("registration_number")],
        ["Статус", g.get("entity_status")],
        ["Материнская компания", g.get("ultimate_parent")],
        ["Дочерние", ", ".join(g.get("direct_children") or []) or None],
    ])
    return md + [""]


def render_sections(domain: str, data: dict) -> tuple[list[str], dict]:
    """Детерминированные секции-таблицы. Возвращает (markdown-строки, счётчики)."""
    md: list[str] = []
    counts = {"subdomains": 0, "ips": 0, "certs": 0}

    # Организация (GLEIF)
    md += _gleif_org_section(data.get("gleif"),
                             (data.get("_sources") or {}).get("org"))

    # WHOIS / RDAP
    w = data.get("whois")
    if w:
        md += ["## Регистрация домена (WHOIS / RDAP)", ""] + _src_line(data, "whois")
        md += _md_table(["Параметр", "Значение"], [
            ["Регистратор", w.get("registrar")],
            ["Создан", w.get("registration")],
            ["Истекает", w.get("expiration")],
            ["Изменён", w.get("last_changed")],
            ["Статусы", ", ".join(w.get("status") or [])],
            ["NS", ", ".join(w.get("nameservers") or [])],
        ])
        md += [""]

    # DNS-записи
    dns = data.get("dns")
    if dns:
        rows = []
        for rt in ("A", "AAAA", "MX", "NS", "TXT"):
            vals = dns.get(rt) or []
            if vals:
                rows.append([rt, ", ".join(str(v) for v in vals[:12])])
        if rows:
            md += ["## DNS-записи", ""] + _src_line(data, "dns")
            md += _md_table(["Тип", "Значения"], rows) + [""]

    # Почтовая безопасность
    mail = data.get("mail") or {}
    if any(mail.get(k) for k in ("SPF", "DMARC", "MTA_STS", "BIMI", "DKIM")):
        md += ["## Почтовая безопасность (SPF / DMARC / DKIM)", ""] + _src_line(data, "mail")
        if mail.get("SPF"):
            pol = "жёсткая (-all)" if "-all" in mail["SPF"] else (
                "мягкая (~all)" if "~all" in mail["SPF"] else "нестрогая")
            md += [f"- **SPF** ({pol}): `{mail['SPF']}`"]
        if mail.get("DMARC"):
            m = re.search(r"p=(\w+)", mail["DMARC"])
            pol = {"reject": "reject — отклонять", "quarantine": "quarantine — карантин",
                   "none": "none — только мониторинг"}.get(m.group(1) if m else "", "—")
            md += [f"- **DMARC** (политика: {pol}): `{mail['DMARC']}`"]
        if mail.get("DKIM"):
            md += [f"- **DKIM**: найдены селекторы — {', '.join(sorted(mail['DKIM']))}"]
        if mail.get("MTA_STS"):
            md += [f"- **MTA-STS**: `{mail['MTA_STS']}`"]
        if mail.get("BIMI"):
            md += [f"- **BIMI**: `{mail['BIMI']}`"]
        md += [""]

    # IP-адреса и сети (пассивный DNS + reverse RDAP)
    ips = data.get("ips") or {}
    info = data.get("ip_info") or {}
    if ips:
        counts["ips"] = len(ips)
        rows = []
        for ip in sorted(ips):
            ii = info.get(ip) or {}
            rows.append([ip, ips.get(ip) or "—",
                         ii.get("name") or ii.get("organization") or "—",
                         (ii.get("range") or "—"), ii.get("country") or "—"])
        md += [f"## IP-адреса и сети (пассивный DNS + RDAP) — {len(ips)}", ""]
        md += _src_line(data, "ips")
        md += _md_table(["IP", "Дата (VT)", "Сеть/Организация", "Диапазон", "Страна"], rows)
        md += [""]

    # Сводка по сетям/диапазонам (группировка reverse-RDAP: как в референс-отчёте)
    md += _ranges_section(info)

    # SSL-сертификаты (активные vs исторические)
    certs = data.get("certs") or []
    if certs:
        seen, uniq = set(), []
        for c in certs:
            k = (c.get("subject"), c.get("issuer"), c.get("valid_until"))
            if k not in seen:
                seen.add(k)
                uniq.append(c)
        counts["certs"] = len(uniq)
        active = [c for c in uniq if _cert_active(c.get("valid_until"))]
        historical = [c for c in uniq if not _cert_active(c.get("valid_until"))]
        md += [f"## SSL-сертификаты — {len(uniq)} "
               f"(активных: {len(active)}, исторических: {len(historical)})", ""]
        md += _src_line(data, "certs")
        for title, group in (("Активные", active), ("Исторические / истёкшие", historical)):
            if not group:
                continue
            rows = [[c.get("subject"), c.get("issuer"), c.get("valid_from"),
                     c.get("valid_until"), c.get("thumbprint") or "—"]
                    for c in group[:25]]
            md += [f"**{title}:**", ""]
            md += _md_table(["Subject", "Issuer", "Действует с", "по", "Отпечаток"],
                            rows) + [""]

    # Поддомены (сгруппированы по функции)
    subs = sorted(s for s in data.get("subdomains", set())
                  if s.endswith(domain) and s != domain)
    if subs:
        counts["subdomains"] = len(subs)
        groups: dict[str, list[str]] = {}
        for s in subs:
            groups.setdefault(classify_subdomain(s), []).append(s)
        md += [f"## Поддомены — {len(subs)} (сгруппированы по функции)", ""]
        md += _src_line(data, "subdomains")
        order = [f for f, _ in _FUNC_RULES] + ["Прочее"]
        rows = []
        for func in order:
            if func in groups:
                items = groups[func]
                rows.append([func, str(len(items)), ", ".join(items[:20]) +
                             (f" … +{len(items) - 20}" if len(items) > 20 else "")])
        md += _md_table(["Функция", "Кол-во", "Поддомены"], rows) + [""]

    # Связанные файлы
    files = data.get("files") or []
    if files:
        rows = [[f.get("name"), f.get("type"), f.get("first_seen")] for f in files[:15]]
        md += ["## Связанные (communicating) файлы", ""] + _src_line(data, "files")
        md += _md_table(["Файл", "Тип", "Первое появление"], rows) + [""]

    # Живые активы (Shodan): порты/сервисы/баннеры + риск-заметки
    assets = data.get("shodan_assets") or []
    if assets:
        rows = []
        for a in assets[:25]:
            rows.append([str(a.get("ip") or "—"), str(a.get("port") or "—"),
                         (a.get("product") or a.get("service") or "—"),
                         a.get("version") or "—", str(a.get("http") or "—"),
                         a.get("org") or "—", a.get("risk") or "—"])
        md += [f"## Живые активы (Shodan) — {len(assets)}", ""] + _src_line(data, "shodan")
        md += _md_table(["IP", "Порт", "Сервис", "Версия", "HTTP/TLS", "Организация",
                         "Потенциальные риски"], rows) + [""]

    # Историческая регистрация (WHOIS History / VT historical_whois)
    hist = data.get("whois_history") or []
    if hist:
        seen_h, rows = set(), []
        for h in hist:
            key = (h.get("registrarName"), h.get("createdDate"), h.get("updatedDate"))
            if key in seen_h:
                continue
            seen_h.add(key)
            rows.append([h.get("createdDate") or h.get("createdDateNormalized") or "—",
                         h.get("updatedDate") or "—",
                         h.get("registrarName") or "—",
                         h.get("registrant") or "—"])
        if rows:
            md += ["## Историческая регистрация (WHOIS History)", ""]
            md += _src_line(data, "whois_history")
            md += _md_table(["Создан", "Изменён", "Регистратор", "Регистрант"],
                            rows[:15]) + [""]

    # Репутация
    rep = data.get("reputation")
    if rep:
        md += ["## Репутация (VirusTotal)", ""] + _src_line(data, "reputation")
        md += _md_table(["Показатель", "Значение"], [
            ["Reputation score", rep.get("reputation")],
            ["Вредоносные", rep.get("malicious")],
            ["Подозрительные", rep.get("suspicious")],
            ["Чистые", rep.get("clean")],
        ]) + [""]

    # Внешние связи по контенту сайта (почтовые домены, партнёры/владельцы)
    md += _webrefs_section(domain, data)

    return md, counts


# Ключевые слова аффилированности — предложения с ними выносим как «связи».
_AFFIL_RE = re.compile(
    r"[^.!?\n]{0,150}(?:официальн\w*\s+(?:партн|дилер|представит|реселлер)"
    r"|партн[её]р\w*|дилер\w*|реселлер\w*|принадлеж\w*|правообладат\w*"
    r"|входит\s+в\s+(?:груп|состав)|группа?\s+компаний|\bГК\s+[«\"А-ЯA-Z]"
    r"|дочерн\w*|аффилир\w*)[^.!?\n]{0,150}", re.I)


def _webrefs_section(domain: str, data: dict) -> list[str]:
    """Детерминированные внешние связи из контента сайта: почтовые домены (не свои),
    и цитаты с признаками аффилированности (партнёр/дилер/ГК/принадлежит). Именно
    здесь всплывает, например, «официальный партнёр АО …» и почты чужого домена."""
    pages = data.get("webpages") or []
    if not pages:
        return []
    text = "\n".join(pages)
    base = ".".join(domain.split(".")[-2:])
    # почтовые домены
    emails = {e.lower() for e in re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text, re.I)}
    ext_mail = sorted({e.split("@", 1)[1] for e in emails
                       if not e.split("@", 1)[1].endswith(base)})
    # цитаты аффилированности (сжатые, дедуп)
    quotes, seen = [], set()
    for m in _AFFIL_RE.finditer(text):
        s = " ".join(m.group(0).split())
        key = s.lower()[:60]
        if len(s) > 25 and key not in seen:
            seen.add(key)
            quotes.append(s)
    if not ext_mail and not quotes:
        return []
    md = ["## Внешние связи по контенту сайта", ""] + _src_line(data, "webrefs")
    if ext_mail:
        md += [f"- **Почтовые домены (не {base}):** " + ", ".join(ext_mail)]
    if quotes:
        md += ["", "**Упоминания аффилированности/партнёрства на сайте:**", ""]
        md += [f"> {q}" for q in quotes[:8]]
    return md + [""]


def _cert_active(valid_until: str | None) -> bool:
    """True, если срок действия сертификата не истёк (best-effort по дате в тексте).
    Неизвестная/непарсируемая дата → считаем активным (не прячем данные)."""
    if not valid_until:
        return True
    m = re.search(r"(20\d{2})", valid_until)
    if not m:
        return True
    from datetime import datetime, timezone
    return int(m.group(1)) >= datetime.now(timezone.utc).year


def _ranges_section(ip_info: dict) -> list[str]:
    """Сводная таблица IP-диапазонов/сетей (группировка reverse-RDAP по диапазону)."""
    ranges: dict[str, dict] = {}
    for ii in (ip_info or {}).values():
        rng = ii.get("range")
        if not rng or "None" in str(rng):
            continue
        cidr = ", ".join(ii.get("cidr") or []) if isinstance(ii.get("cidr"), list) else (ii.get("cidr") or "")
        r = ranges.setdefault(rng, {"cidr": cidr,
                                    "owner": ii.get("name") or ii.get("organization") or "—",
                                    "country": ii.get("country") or "—", "n": 0})
        r["n"] += 1
    if not ranges:
        return []
    rows = [[cidr_or_range, v["cidr"] or "—", v["owner"], v["country"], str(v["n"])]
            for cidr_or_range, v in sorted(ranges.items())]
    md = [f"## IP-диапазоны и сети (сводка) — {len(ranges)}", ""]
    md += _md_table(["Диапазон", "CIDR", "Владелец/Сеть", "Страна", "IP в наборе"], rows)
    return md + [""]


def data_for_llm(domain: str, data: dict) -> dict:
    """Компактная структура для LLM (для резюме/выводов) — без «сырья»."""
    subs = sorted(s for s in data.get("subdomains", set()) if s.endswith(domain))
    groups: dict[str, int] = {}
    for s in subs:
        groups[classify_subdomain(s)] = groups.get(classify_subdomain(s), 0) + 1
    g = data.get("gleif") or {}
    return {
        "domain": domain,
        "organization": {"name": g.get("legal_name"), "country": g.get("jurisdiction"),
                         "reg_no": g.get("registration_number"), "status": g.get("entity_status")}
        if g.get("legal_name") else None,
        "whois": data.get("whois"),
        "mail": data.get("mail"),
        "ip_count": len(data.get("ips") or {}),
        "ips": list((data.get("ips") or {}).keys())[:15],
        "ip_networks": [ (v.get("name") or v.get("organization")) for v in (data.get("ip_info") or {}).values() ],
        "cert_count": len(data.get("certs") or []),
        "subdomain_count": len(subs),
        "subdomain_groups": groups,
        "reputation": data.get("reputation"),
        "files_count": len(data.get("files") or []),
        "shodan_ports": sorted({a.get("port") for a in (data.get("shodan_assets") or [])
                                if a.get("port")}),
        "web_external_signals": _web_signals(domain, data),
    }


def _web_signals(domain: str, data: dict) -> dict:
    """Компактные внешние сигналы для LLM: чужие почтовые домены + цитаты партнёрства."""
    pages = data.get("webpages") or []
    if not pages:
        return {}
    text = "\n".join(pages)
    base = ".".join(domain.split(".")[-2:])
    emails = {e.lower() for e in re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text, re.I)}
    ext_mail = sorted({e.split("@", 1)[1] for e in emails
                       if not e.split("@", 1)[1].endswith(base)})
    quotes, seen = [], set()
    for m in _AFFIL_RE.finditer(text):
        s = " ".join(m.group(0).split())
        if len(s) > 25 and s.lower()[:60] not in seen:
            seen.add(s.lower()[:60])
            quotes.append(s)
    out = {}
    if ext_mail:
        out["external_mail_domains"] = ext_mail[:8]
    if quotes:
        out["affiliation_quotes"] = quotes[:5]
    return out


# ============================ КОМПАНИЯ-досье ================================
def extract_company_data(results: list[dict]) -> dict:
    """Свести «корпоративный» слой ответов (без выдумывания): GLEIF, должностные
    лица (OpenCorporates), сводка companyscope, SEC-отчёты, санкции."""
    d: dict = {"gleif": None, "officers": None, "companyscope": None,
               "filings": None, "sanctions": None, "_sources": {}}
    for r in results:
        if not r.get("ok"):
            continue
        sid, tool, text = r.get("server"), r.get("tool", ""), r.get("text", "") or ""
        nm = r.get("name") or sid
        if sid == "directapi" and tool == "gleif_entity":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("legal_name"):
                d["gleif"] = j
                d["_sources"]["org"] = [f"{nm} (gleif_entity)"]
            elif isinstance(j, dict) and j.get("did_you_mean"):
                # Точного юрлица не нашли — сохраняем подсказки, чтобы аналитик
                # мог переспросить по юридическому имени (а не гадал молча).
                d["gleif_hint"] = j
        elif sid == "directapi" and tool == "opencorporates_officers":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("officers"):
                d["officers"] = j
        elif sid == "companyscope" and text.strip():
            d["companyscope"] = text[:2000]
        elif sid == "filingfirehose" and text.strip():
            d["filings"] = text[:1800]
        elif sid == "the-stall" and text.strip():
            d["sanctions"] = text[:1500]
    return d


def render_company_sections(name: str, data: dict) -> list[str]:
    """Детерминированные секции корпоративного слоя (юр. идентичность, структура,
    руководство, санкции). Инфраструктура доменов добавляется отдельно в server.py."""
    md: list[str] = []
    g = data.get("gleif")
    md += _gleif_org_section(g, (data.get("_sources") or {}).get("org"))
    # Юрлицо не опознано: честно говорим об этом и даём похожие названия —
    # НЕ подставляем «похожую» компанию в досье.
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

    # Корпоративная структура (материнская/дочерние) + Mermaid-граф
    if g and (g.get("ultimate_parent") or g.get("direct_children")):
        md += ["## Корпоративная структура", ""]
        if g.get("ultimate_parent"):
            md += [f"- **Материнская компания:** {g['ultimate_parent']}"]
        kids = g.get("direct_children") or []
        if kids:
            md += [f"- **Дочерние ({len(kids)}):** " + ", ".join(kids)]
        md += [""]
        md += _mermaid_org(name, g) + [""]

    # Должностные лица (OpenCorporates)
    off = data.get("officers")
    if off and off.get("officers"):
        rows = [[o.get("name") or "—", o.get("position") or "—",
                 o.get("start_date") or "—", o.get("end_date") or "—"]
                for o in off["officers"][:40]]
        md += [f"## Руководство и должностные лица — {off.get('officers_count', len(rows))} "
               f"(OpenCorporates, {off.get('jurisdiction', '?')})", ""]
        md += _md_table(["Имя", "Должность", "С", "По"], rows) + [""]
        if off.get("registry_url"):
            md += [f"_Источник в реестре: {off['registry_url']}_", ""]

    # SEC-отчётность / санкции (текст-снипеты)
    if data.get("filings"):
        md += ["## Отчётность (SEC / FilingFirehose)", "",
               "```", data["filings"].strip()[:1200], "```", ""]
    if data.get("sanctions"):
        md += ["## Санкционный скрининг (The Stall / OFAC)", "",
               "```", data["sanctions"].strip()[:1000], "```", ""]
    return md


def company_data_for_llm(name: str, data: dict, infra: list[dict]) -> dict:
    """Компактные факты для LLM-нарратива по компании (без сырья)."""
    g = data.get("gleif") or {}
    off = data.get("officers") or {}
    return {
        "company": name,
        "organization": {
            "legal_name": g.get("legal_name"), "lei": g.get("lei"),
            "jurisdiction": g.get("jurisdiction"), "status": g.get("entity_status"),
            "reg_no": g.get("registration_number"),
            "parent": g.get("ultimate_parent"),
            "subsidiaries": g.get("direct_children") or [],
        } if g.get("legal_name") else None,
        "officers_count": off.get("officers_count", 0),
        "officers_sample": [o.get("name") for o in (off.get("officers") or [])[:8]],
        "domains": [f["domain"] for f in infra],
        "infrastructure": infra,
        "sanctions_present": bool(data.get("sanctions")),
    }


# ------------------------------ Mermaid-диаграммы ---------------------------
def _mm_id(s: str) -> str:
    """Безопасный идентификатор узла Mermaid из строки."""
    return "n" + re.sub(r"[^a-zA-Z0-9]", "", (s or "x"))[:24] or "nX"


def _mm_label(s: str) -> str:
    return (s or "").replace('"', "'").replace("[", "(").replace("]", ")")[:40]


def _mermaid_org(name: str, g: dict) -> list[str]:
    """Граф корпоративной структуры: материнская → компания → дочерние."""
    lines = ["```mermaid", "graph TD"]
    cid = _mm_id(name)
    lines.append(f'  {cid}["{_mm_label(g.get("legal_name") or name)}"]')
    if g.get("ultimate_parent"):
        pid = _mm_id(g["ultimate_parent"])
        lines.append(f'  {pid}["{_mm_label(g["ultimate_parent"])}"] --> {cid}')
    for kid in (g.get("direct_children") or [])[:12]:
        kid_id = _mm_id(kid)
        lines.append(f'  {cid} --> {kid_id}["{_mm_label(kid)}"]')
    lines.append("```")
    return lines


def _mermaid_dns_topology(domain: str, dns: dict) -> list[str]:
    """Граф DNS-топологии: домен → NS/MX/A."""
    if not dns:
        return []
    lines = ["```mermaid", "graph LR", f'  D["{_mm_label(domain)}"]']
    for ns in (dns.get("NS") or [])[:6]:
        lines.append(f'  D -->|NS| {_mm_id("ns" + ns)}["{_mm_label(ns)}"]')
    for mx in (dns.get("MX") or [])[:4]:
        host = mx.split()[-1] if isinstance(mx, str) else str(mx)
        lines.append(f'  D -->|MX| {_mm_id("mx" + host)}["{_mm_label(host)}"]')
    lines.append("```")
    return lines


# ------------------------------ Ограничения --------------------------------
_MISSING_HINT = {
    "virustotal": "VirusTotal (пассивный DNS, историч. SSL, связанные файлы, репутация) — задайте VIRUSTOTAL_API_KEY",
    "censys": "Censys (порты/сервисы/сертификаты) — задайте CENSYS_PAT + CENSYS_ORG_ID",
    "whoisxml": "WhoisXML (история WHOIS) — задайте WHOISXML_API_KEY",
    "opencorporates": "OpenCorporates (должностные лица) — задайте OPENCORPORATES_API_KEY",
}


def render_limitations(results: list[dict], catalog: dict) -> list[str]:
    """Честный раздел «Ограничения данных»: какие источники не дали данных и почему
    (нужен ключ/баланс/недоступен). Ничего не выдумываем — прямо перечисляем пробелы."""
    reasons: list[str] = []
    seen_reason: set[tuple[str, str]] = set()
    for r in results:
        if r.get("ok"):
            continue
        name = r.get("name", r.get("server", "?"))
        why = (r.get("text") or "").replace("источник недоступен", "").strip(" :()")
        # Обрезаем длинные технические сообщения до сути и дедупим по (имя, причина).
        why = re.sub(r"\s+", " ", why)[:100]
        key = (name, why[:40])
        if why and key not in seen_reason:
            seen_reason.add(key)
            reasons.append(f"- **{name}**: {why}")
    # Отсутствующие в каталоге ключевые источники глубины.
    absent = []
    if "virustotal" not in catalog:
        absent.append(_MISSING_HINT["virustotal"])
    if "directapi" in catalog:
        # Censys/WhoisXML/OpenCorporates обёрнуты в directapi — судим по ответам.
        txts = " ".join((r.get("text") or "") for r in results).lower()
        if "нужен ключ censys" in txts:
            absent.append(_MISSING_HINT["censys"])
        if "нужен ключ whoisxml" in txts:
            absent.append(_MISSING_HINT["whoisxml"])
        if "нужен ключ opencorporates" in txts:
            absent.append(_MISSING_HINT["opencorporates"])
    if not reasons and not absent:
        return []
    md = ["## Ограничения данных", "",
          "Досье собрано по доступным открытым источникам. Не удалось получить:"]
    md += reasons
    for a in dict.fromkeys(absent):
        md.append(f"- {a}")
    md += ["",
           "_Данные о совете директоров / доверенных лицах (apoderados) в полном объёме "
           "требуют национального реестра (напр. Registro Mercantil/BORME для Испании), "
           "который в наборе источников не подключён — приведено только то, что дал "
           "GLEIF/OpenCorporates._", ""]
    return md
