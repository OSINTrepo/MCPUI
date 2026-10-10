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
import html
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
              "Fingerprint", "Thumbprint", "Alt Names")


def _cert_field(block: str, key: str) -> str:
    """Значение поля сертификата, останавливаясь у следующего ключа или переноса
    строки (работает и для многострочного, и для однострочного формата VT)."""
    others = "|".join(re.escape(k) for k in _CERT_KEYS if k != key)
    m = re.search(rf"{re.escape(key)}:\s*(.+?)(?=\s*(?:{others})\s*:|\n|$)", block)
    return m.group(1).strip() if m else ""


def _vt_certs(text: str) -> list[dict]:
    """SSL-сертификаты из historical_ssl_certificates (Subject/Issuer/Valid…).
    VT-формат: Subject/Issuer/Valid From/Valid Until/Serial/Alt Names — без отпечатка."""
    out = []
    for block in re.split(r"•\s*SSL Certificate", text)[1:]:
        subj = _cert_field(block, "Subject")
        iss = _cert_field(block, "Issuer")
        if subj or iss:
            serial = (_cert_field(block, "Serial") or "")[:40]
            out.append({
                "subject": subj[:80],
                "issuer": iss[:80],
                "valid_from": _cert_field(block, "Valid From")[:40],
                "valid_until": _cert_field(block, "Valid Until")[:40],
                # VT text format выводит Serial, но не fingerprint.
                "thumbprint": (_cert_field(block, "Thumbprint")
                               or _cert_field(block, "Fingerprint")
                               or serial)[:128],
                "san": _cert_field(block, "Alt Names")[:200],
            })
    return out


def _vt_files(text: str) -> list[dict]:
    """Связанные (communicating) файлы: имя/тип/дата — best-effort."""
    out = []
    for block in re.split(r"\n\s*•\s*", text)[1:]:
        typ = re.search(r"Type:\s*(.+)", block)
        seen = re.search(r"First Seen:\s*(.+)", block)
        # 128: у части файлов «имя» — это SHA-256 (64 симв.), и обрезка до 60
        # ломала хеш, делая его непригодным как IOC.
        name = block.strip().splitlines()[0].strip()[:128] if block.strip() else ""
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
def _current_whois_data(record: dict) -> dict:
    """Привести ответ WhoisXML к схеме RDAP без дат из исторических записей."""
    def values(value):
        if isinstance(value, list):
            return value
        return [value] if value else []

    nameservers = record.get("nameservers") or record.get("nameServers") or []
    if isinstance(nameservers, dict):
        nameservers = nameservers.get("hostNames") or []
    registrant = record.get("registrant")
    if isinstance(registrant, dict):
        registrant = registrant.get("organization") or registrant.get("name")
    return {
        "domain_name": record.get("domain_name") or record.get("domain"),
        "registrar": record.get("registrar") or record.get("registrarName"),
        "registration": record.get("registration") or record.get("createdDate"),
        "expiration": record.get("expiration") or record.get("expiresDate"),
        "last_changed": record.get("last_changed") or record.get("updatedDate"),
        "status": values(record.get("status")),
        "nameservers": values(nameservers),
        "registrant": registrant,
        "entities": record.get("entities") or ([{"roles": ["registrant"], "name": registrant}] if registrant else []),
        "domainAvailability": record.get("domainAvailability"),
        "dataError": record.get("dataError"),
        "parseCode": record.get("parseCode"),
    }


def _history_domain_key(domain) -> str:
    """Сопоставить Unicode-имя с ASCII/IDNA-именем ответа провайдера."""
    value = str(domain or "").strip().rstrip(".")
    try:
        return value.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return value.lower()


def whois_history_facts(data: dict, limit: int = 24) -> dict | None:
    """Компактные группы наблюдений, сохраняющие старые и новые регистранты."""
    records = [r for r in (data.get("whois_history") or []) if isinstance(r, dict)]
    if not records:
        return None
    groups: dict = {}
    all_dates = []
    for record in records:
        audit = record.get("audit") if isinstance(record.get("audit"), dict) else {}
        observed = audit.get("createdDate") or audit.get("updatedDate") or record.get("observedDate")
        fields = {
            "registrar": record.get("registrarName"),
            "registrant": record.get("registrant"),
            "registrant_name": record.get("registrantName"),
            "registrant_organization": record.get("registrantOrganization"),
            "domain_created": record.get("createdDate") or record.get("createdDateNormalized"),
            "provider_event_type": record.get("domainType"),
        }
        if not observed and not any(fields.values()):
            continue
        key = json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)
        group = groups.setdefault(key, {**fields, "record_count": 0, "_dates": set(), "_expires": set()})
        group["record_count"] += 1
        if observed:
            group["_dates"].add(str(observed))
            all_dates.append(str(observed))
        if record.get("expiresDate"):
            group["_expires"].add(str(record["expiresDate"]))
    observations = []
    for group in groups.values():
        dates = sorted(group.pop("_dates"))
        expirations = sorted(group.pop("_expires"))
        observations.append({**group, "first_observed": dates[0] if dates else None,
                             "last_observed": dates[-1] if dates else None,
                             "expiry_first": expirations[0] if expirations else None,
                             "expiry_last": expirations[-1] if expirations else None})
    observations.sort(key=lambda group: (str(group["first_observed"] or "~"), str(group["registrant"] or "")))
    total = len(observations)
    limit = max(1, limit)
    if total > limit:
        first_count = (limit + 1) // 2
        last_count = limit - first_count
        observations = observations[:first_count] + (observations[-last_count:] if last_count else [])
    return {
        "records_count": len(records), "groups_count": total,
        "first_snapshot": min(all_dates) if all_dates else None,
        "last_snapshot": max(all_dates) if all_dates else None,
        "observations": observations, "omitted_groups": max(0, total - len(observations)),
        "sources": data.get("whois_history_sources") or [],
        "scope": "Исторические наблюдения WHOIS. Первая/последняя дата — даты зафиксированных снимков, а не непрерывный период владения. cache.fetched_at — дата получения истории у источника; response_returned_at — время ответа инструмента, которое при cache.status=hit не означает новый запрос источника. Регистрант и контактное имя не подтверждают личность человека, гражданство, текущее владение или конкретное юридическое лицо. Тип события — классификация провайдера; dropped не означает ликвидацию компании.",
    }


def extract_domain_data(results: list[dict]) -> dict:
    """Свести ответы всех источников в структурированное досье (без выдумывания)."""
    d: dict = {"whois": None, "dns": None, "mail": {}, "ips": {}, "certs": [],
               "subdomains": set(), "files": [], "reputation": None,
               "gleif": None, "ip_info": {}, "shodan_assets": [],
               "whois_history": [], "whois_history_sources": [], "webpages": [], "web_inspect": None,
               "cse": [], "asn_by_ip": {}, "cohost": {}, "subdomain_ips": {},
               "subdomain_src": {}, "_sources": {}}

    def _sub(s: str, src: str):
        """Добавить поддомен + запомнить источник (для кросс-корреляции)."""
        s = (s or "").strip().lower().lstrip("*.")
        if not s:
            return
        d["subdomains"].add(s)
        d["subdomain_src"].setdefault(s, set()).add(src)
    # Провенанс: какой источник (отображаемое имя + инструмент) наполнил каждую
    # секцию. Из него render_sections печатает «_Источник: …_» под заголовком —
    # чтобы было видно, что таблицы построены из реальных ответов инструментов.
    def prov(cat: str, r: dict, tool: str = "") -> None:
        # Имя шага уже вида «Direct Lookups · sec_edgar» — берём базовую часть,
        # иначе провенанс дублирует инструмент дважды.
        nm = (r.get("name") or r.get("server") or "?").split(" · ")[0]
        label = f"{nm} ({tool})" if tool else nm
        d["_sources"].setdefault(cat, [])
        if label not in d["_sources"][cat]:
            d["_sources"][cat].append(label)

    history_payloads_seen, history_sources_seen = set(), set()

    def history(r: dict, payload: dict) -> None:
        """Сохранить историю и дату исходного запроса независимо от выдачи кэша."""
        requested = (r.get("args") or {}).get("domain") or (
            r.get("target_value") if r.get("target_type") == "domain" else None)
        domain = payload.get("domain") or requested
        if requested and domain and _history_domain_key(requested) != _history_domain_key(domain):
            return  # Чужой ответ не становится доказательством по запрошенному домену.
        records = payload.get("records") or []
        cache = payload.get("cache") if isinstance(payload.get("cache"), dict) else {}
        source = {
            "server": r.get("server"), "tool": "whois_history", "domain": domain,
            "provider": payload.get("source") or r.get("server"),
            "records_count": len(records) if isinstance(records, list) else 0,
            "cache": {key: cache[key] for key in ("status", "fetched_at", "expires_at", "age_seconds", "ttl_seconds")
                      if key in cache},
        }
        source_key = json.dumps(source, sort_keys=True, ensure_ascii=False, default=str)
        if source_key not in history_sources_seen:
            history_sources_seen.add(source_key)
            source["response_returned_at"] = r.get("retrieved_at")
            d["whois_history_sources"].append(source)
        if not r.get("ok") or payload.get("error") or not isinstance(records, list):
            return
        if records:
            prov("whois_history", r, "whois_history (" + str(source["provider"]) + ")")
        # Оба MCP-алиаса могут вернуть одну купленную историю. Повторный набор
        # не удваиваем, но сохраняем все записи первого ответа, включая
        # одинаковые после нормализации: «получено» должно совпадать с API.
        payload_key = json.dumps({"domain": _history_domain_key(domain),
                                  "provider": source["provider"], "records": records},
                                 sort_keys=True, ensure_ascii=False, default=str)
        if payload_key not in history_payloads_seen:
            history_payloads_seen.add(payload_key)
            d["whois_history"].extend(record for record in records if isinstance(record, dict))

    for r in results:
        if r.get("server") in ("directapi", "whoisxml") and r.get("tool") == "whois_history":
            payload = _load_json(r.get("text") or "")
            if isinstance(payload, dict):
                history(r, payload)
            continue
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
                queried_domain = (r.get("args") or {}).get("domain") or ""
                if "_domainkey." in queried_domain:
                    # DKIM-зонд: ищем v=DKIM1 в TXT-записях
                    selector = queried_domain.split("._domainkey.")[0]
                    for rec in (j.get("TXT") or []):
                        val = rec if isinstance(rec, str) else (rec.get("value") or rec.get("txt") or "")
                        if "v=DKIM1" in val or "k=rsa" in val or "k=ed25519" in val:
                            d["mail"].setdefault("dkim_selectors", {})[selector] = val[:120]
                            prov("mail", r, "dns_records")
                else:
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
                src = "crt.sh/certspotter" if j.get("source") else "crt.sh"
                for s in (j.get("subdomains") or []):
                    _sub(s, src)
            elif tool == "gleif_entity" and not j.get("error"):
                d["gleif"] = j; prov("org", r, "gleif_entity")
            elif tool == "web_inspect" and not j.get("error"):
                d["web_inspect"] = j
                prov("web_inspect", r, "web_inspect")
            elif tool == "google_cse" and not j.get("error") and j.get("results"):
                d["cse"].append(j)
                prov("cse", r, "google_cse:" + str(j.get("engine", "")))
            elif tool in ("subdomain_ips", "resolve_hosts") and not j.get("error"):
                d["subdomain_ips"].update(j.get("map") or {})
                # Повторный таймаут не стирает ранее полученный ответ.
                d["dns_unresolved"] = sorted((set(d.get("dns_unresolved") or []) |
                                              set(j.get("unresolved") or [])) - set(d["subdomain_ips"]))
                d["dns_failures"] = j.get("failures") or []
                d.setdefault("subdomain_addresses", {}).update(j.get("addresses") or {})
                for ip in (j.get("map") or {}).values():
                    d["ips"].setdefault(ip, "")
                if j.get("map"):
                    prov("subdomain_ips", r, "dns_records")
        # Shodan — карточка хоста (порты/сервисы/баннеры) → таблица активов + ASN + co-host.
        elif sid == "shodan":
            got = _shodan_assets(text)
            if got:
                prov("shodan", r, "ip_lookup")
            d["shodan_assets"].extend(got)
            sj = _load_json(text)
            if isinstance(sj, dict):
                info = sj.get("IP Information") or {}
                loc = sj.get("Location") or {}
                ip0 = info.get("IP Address")
                if ip0 and info.get("ASN"):
                    d["asn_by_ip"][ip0] = info["ASN"]
                # Обогащаем ip_info данными Shodan — заполняет пробелы, когда rdap_ip
                # не вызывался для этого IP (домен-расследование вместо IP-расследования).
                if ip0 and not d["ip_info"].get(ip0):
                    org = info.get("Organization") or info.get("ISP") or ""
                    d["ip_info"][ip0] = {
                        "ip": ip0,
                        "name": org,
                        "organization": org,
                        "country": loc.get("Country") or info.get("Country") or "",
                        "range": "",
                        "cidr": [],
                    }
                hosts = sj.get("Hostnames") or []
                if ip0 and hosts:
                    d["cohost"].setdefault(ip0, [])
                    for h in hosts:
                        if h not in d["cohost"][ip0]:
                            d["cohost"][ip0].append(h)
                    prov("cohost", r, "ip_lookup")
        # Bright Data — контент страниц сайта (для секции «внешние связи»).
        elif sid == "brightdata":
            if text.strip():
                d["webpages"].append(text)
                prov("webrefs", r, "scrape_as_markdown")
        # VirusTotal — текст. Триггерим по ТОЧНОМУ заголовку секции VT
        # ("… — <relationship>"), иначе имя связи, упомянутое в другом ответе,
        # ложно наполняет секцию (напр. пустые communicating_files).
        elif sid == "virustotal":
            # Источник сам сообщает, что урезал выдачу («Showing 40 of 200») —
            # запоминаем, чтобы заголовок таблицы не выдавал срез за полноту.
            shown = _vt_shown(text)

            def _trunc(cat: str, _shown=shown) -> None:
                if _shown and _shown[1] > _shown[0]:
                    d.setdefault("_truncation", {})[cat] = {
                        "shown": _shown[0], "total": _shown[1], "source": "VirusTotal"}

            if "— resolutions" in text:
                for ip, dt in _vt_resolutions(text):
                    if ip not in d["ips"] or not d["ips"][ip]:
                        d["ips"][ip] = dt
                prov("ips", r, "resolutions"); _trunc("ips")
            if "— subdomains" in text:
                for s in _vt_subdomains(text):
                    _sub(s, "VirusTotal")
                prov("subdomains", r, "subdomains"); _trunc("subdomains")
            if "SSL Certificate" in text and "ssl_certificates" in text:
                d["certs"].extend(_vt_certs(text))
                prov("certs", r, "ssl_certificates"); _trunc("certs")
            if "— communicating_files" in text:
                d["files"].extend(_vt_files(text))
                prov("files", r, "communicating_files"); _trunc("files")
            if "— historical_whois" in text:
                d["whois_history"].extend(_vt_whois_history(text))
                prov("whois_history", r, "historical_whois")
            rep = _vt_reputation(text)
            if rep and not d["reputation"]:
                d["reputation"] = rep; prov("reputation", r, "get_domain_report")
        # subfinder — вытащим поддомены из текста
        elif sid == "vulneramcp":
            before = len(d["subdomains"])
            for s in _vt_subdomains(text):
                _sub(s, "subfinder")
            j = _load_json(text)
            if isinstance(j, dict):
                for key in ("subdomains", "sub_domains"):
                    payload = j.get("data") if isinstance(j.get("data"), dict) else j
                    for s in (payload.get(key) or []):
                        if isinstance(s, str):
                            _sub(s, "subfinder")
            if len(d["subdomains"]) > before:
                prov("subdomains", r, tool)
        # ContrastAPI — поддомены + WAF/CDN/TLS в web_inspect
        elif sid == "contrastapi":
            before = len(d["subdomains"])
            for s in _vt_subdomains(text):
                _sub(s, "ContrastAPI")
            j = _load_json(text)
            if isinstance(j, dict):
                for key in ("subdomains", "sub_domains"):
                    for s in (j.get(key) or []):
                        if isinstance(s, str):
                            _sub(s, "ContrastAPI")
            if len(d["subdomains"]) > before:
                prov("subdomains", r, tool)
            # WAF/CDN/TLS — в web_inspect (не перебиваем данные от directapi/web_inspect)
            if isinstance(j, dict):
                wi = d.setdefault("web_inspect", {}) if not d.get("web_inspect") else d["web_inspect"]
                if j.get("waf_present") and not wi.get("waf"):
                    wi["waf"] = "да"
                    detected = j.get("detected") or []
                    if detected:
                        wi["cdn"] = ", ".join(str(x) for x in detected)
                    prov("web_inspect", r, "domain_report")
                if j.get("grade") and not wi.get("tls_grade"):
                    wi["tls_grade"] = str(j["grade"])
                if j.get("tls_version") and not wi.get("tls_version"):
                    wi["tls_version"] = str(j["tls_version"])
                if j.get("cipher") and not wi.get("cipher"):
                    wi["cipher"] = str(j["cipher"])
                if isinstance(j.get("security_headers"), dict) and not wi.get("security_headers"):
                    wi["security_headers"] = j["security_headers"]
        # Censys — порты/сервисы (→ shodan_assets), IP/ASN, сертификаты, поддомены
        elif sid == "censys":
            j = _load_json(text)
            if not isinstance(j, dict):
                continue
            if tool == "censys_host":
                ip = j.get("ip")
                org = j.get("autonomous_system", {}).get("name") or j.get("org")
                asn = j.get("autonomous_system", {}).get("asn") or j.get("asn")
                country = j.get("location", {}).get("country") or j.get("country")
                if ip:
                    d["ips"].setdefault(ip, "")
                    if asn:
                        d["asn_by_ip"][ip] = str(asn)
                for svc in (j.get("services") or [])[:25]:
                    port = svc.get("port")
                    transport = svc.get("transport_protocol") or ""
                    product = svc.get("service_name") or ""
                    banner = (svc.get("banner") or "")[:60]
                    d["shodan_assets"].append({
                        "ip": ip, "org": org, "asn": asn, "country": country,
                        "port": port, "service": transport, "product": product,
                        "version": "", "http": banner, "risk": _PORT_RISK.get(port, ""),
                    })
                if j.get("services"):
                    prov("shodan", r, "censys_host")
            elif tool == "censys_domain":
                # v3 API возвращает hits[] с полями ip/asn/as_name/country/services
                for host in (j.get("hits") or [])[:30]:
                    ip = host.get("ip")
                    if ip:
                        d["ips"].setdefault(ip, "")
                        asn = host.get("asn")
                        if asn:
                            d["asn_by_ip"][ip] = str(asn)
                        # Обогащаем ip_info данными Censys — иначе колонки «Сеть» и «Страна»
                        # таблицы IP пустые при домен-расследовании (rdap_ip там не вызывается).
                        if not d["ip_info"].get(ip):
                            org = host.get("as_name") or ""
                            d["ip_info"][ip] = {
                                "ip": ip,
                                "name": org,
                                "organization": org,
                                "country": host.get("country") or "",
                                "range": "",
                                "cidr": [],
                            }
                        # Censys-хиты → в shodan_assets для таблицы живых активов
                        if host.get("services"):
                            for port in (host.get("services") or []):
                                d["shodan_assets"].append({
                                    "ip": ip, "org": host.get("as_name"),
                                    "asn": host.get("asn"),
                                    "country": host.get("country"), "city": host.get("city"),
                                    "port": port, "service": "", "product": "",
                                    "version": "", "http": "", "risk": _PORT_RISK.get(port, ""),
                                })
                if j.get("hits"):
                    prov("ips", r, "censys_domain")
                    prov("shodan", r, "censys_domain")
            elif tool == "censys_cert":
                parsed = j.get("parsed") or {}
                d["certs"].append({
                    "subject": (parsed.get("subject_dn") or "")[:80],
                    "issuer": (parsed.get("issuer_dn") or "")[:80],
                    "valid_from": (parsed.get("validity") or {}).get("start", "")[:40],
                    "valid_until": (parsed.get("validity") or {}).get("end", "")[:40],
                    "thumbprint": (j.get("fingerprint_sha256") or "")[:128],
                })
                prov("certs", r, "censys_cert")
        # WhoisXML / Whoxy — история WHOIS и текущий WHOIS
        elif sid == "whoisxml":
            j = _load_json(text)
            if not isinstance(j, dict):
                continue
            if tool == "whois_current":
                # Используем как фолбэк, если rdap_domain не ответил
                if not d["whois"] and not j.get("error") and (j.get("domain_name") or j.get("domain")):
                    d["whois"] = _current_whois_data(j)
                    prov("whois", r, "whois_current")
        # Googlesearch — тематический веб-поиск (домены: новости/утечки/соцсети)
        elif sid == "googlesearch":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("results"):
                d["cse"].append(j)
                prov("cse", r, f"web_search:{j.get('engine', '')}")
        # Voidly — доступность домена по странам (119+ стран)
        # Сервер возвращает plain-text Markdown (не JSON), парсим вручную.
        elif sid == "voidly":
            j = _load_json(text)
            if tool == "get_domain_status":
                if isinstance(j, dict) and not j.get("error"):
                    # JSON-путь (на случай если API изменится)
                    results = j.get("results") or j.get("data") or j.get("checks") or []
                    if results:
                        d.setdefault("voidly_status", []).extend(results[:30])
                        prov("voidly_status", r, "get_domain_status")
                elif text.strip():
                    # Plain-text Markdown формат: парсим статус и счётчики
                    import re as _re
                    status_line = _re.search(r"##\s*Status:\s*(.+)", text)
                    blocked_n = _re.search(r"Blocked in:\s*(\d+)", text)
                    isps_n = _re.search(r"By\s+(\d+)\s+ISP", text)
                    status_str = (status_line.group(1) if status_line else "").strip()
                    is_blocked = bool(blocked_n and int(blocked_n.group(1)) > 0)
                    parsed = {
                        "status": "blocked" if is_blocked else "accessible",
                        "status_label": status_str,
                        "blocked_countries": int(blocked_n.group(1)) if blocked_n else 0,
                        "blocking_isps": int(isps_n.group(1)) if isps_n else 0,
                        "summary": text.strip()[:400],
                    }
                    d.setdefault("voidly_status", []).append(parsed)
                    prov("voidly_status", r, "get_domain_status")
            elif tool == "get_domain_history":
                if isinstance(j, dict) and not j.get("error"):
                    hist = j.get("results") or j.get("data") or j.get("history") or []
                    if hist:
                        d.setdefault("voidly_history", []).extend(hist[:20])
                        prov("voidly_history", r, "get_domain_history")
        # DNSTwist — домены-двойники (тайпсквоттинг, фишинг)
        elif sid == "dnstwist":
            raw = _load_json(text)
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                items = (raw.get("domains") or raw.get("results")
                         or ([] if raw.get("error") else []))
            else:
                items = []
            # фильтруем: оставляем только зарегистрированные (есть dns_a или dns_ns)
            items = [i for i in items if isinstance(i, dict)
                     and (i.get("dns_a") or i.get("dns_ns") or i.get("dns-a"))]
            if items:
                d.setdefault("typosquat", []).extend(items[:50])
                prov("typosquat", r, "fuzz_domain")
        # OpenOSINT — агрегация IP/поддоменов/WHOIS по домену
        elif sid == "openosint":
            j = _load_json(text)
            if not isinstance(j, dict) or j.get("error"):
                continue
            before_ips = len(d["ips"])
            for ip in (j.get("ip_addresses") or j.get("ips") or []):
                if isinstance(ip, str):
                    d["ips"].setdefault(ip, "")
                elif isinstance(ip, dict) and ip.get("ip"):
                    d["ips"].setdefault(ip["ip"], "")
            before_subs = len(d["subdomains"])
            for s in (j.get("subdomains") or []):
                if isinstance(s, str):
                    _sub(s, "OpenOSINT")
            if len(d["ips"]) > before_ips:
                prov("ips", r, tool)
            if len(d["subdomains"]) > before_subs:
                prov("subdomains", r, tool)
        # ZoomEye — хосты/порты по домену/IP (дорк-поиск)
        elif sid == "zoomeye":
            j = _load_json(text)
            if not isinstance(j, dict):
                continue
            for m in (j.get("matches") or [])[:25]:
                pi = m.get("portinfo") or {}
                geo = m.get("geoinfo") or {}
                ip = m.get("ip")
                if not ip:
                    continue
                d["ips"].setdefault(ip, "")
                port = pi.get("port")
                if port:
                    country_info = geo.get("country") or {}
                    city_info = geo.get("city") or {}
                    d["shodan_assets"].append({
                        "ip": ip, "org": m.get("isp"), "asn": None,
                        "country": (country_info.get("names") or {}).get("en")
                                   or str(country_info)[:20],
                        "city": (city_info.get("names") or {}).get("en")
                                or str(city_info)[:20],
                        "port": port, "service": pi.get("service") or "",
                        "product": pi.get("app") or "", "version": pi.get("version") or "",
                        "http": (pi.get("banner") or "")[:60],
                        "risk": _PORT_RISK.get(port, ""),
                    })
            if j.get("matches"):
                prov("shodan", r, "zoomeye_search")
                prov("ips", r, "zoomeye_search")

    # Постобработка: связанные домены из DNS NS/MX-хостов и редиректа.
    # Делается ПОСЛЕ основного цикла, когда dns и web_inspect уже заполнены.
    _related: list[dict] = []
    _seen_rel: set[str] = set()

    def _add_related(domain_val: str, rel: str):
        k = domain_val.lower()
        if k not in _seen_rel:
            _seen_rel.add(k)
            _related.append({"domain": domain_val, "relationship": rel, "whois": {}})

    dns_data = d.get("dns") or {}
    ns_hosts = dns_data.get("NS") or []
    mx_list = dns_data.get("MX") or []
    mx_hosts = []
    for mx in mx_list:
        if isinstance(mx, str):
            parts = mx.strip().split()
            host = parts[-1] if parts else ""
        elif isinstance(mx, dict):
            host = mx.get("exchange") or mx.get("host") or ""
        else:
            host = str(mx)
        mx_hosts.append(host.rstrip(".").lower())

    related_hostnames = [h.rstrip(".").lower() for h in ns_hosts if h] + mx_hosts
    parent_domains_seen: set[str] = set()
    for h in related_hostnames:
        parts = h.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            if parent not in parent_domains_seen:
                parent_domains_seen.add(parent)
                _add_related(parent, "NS/MX-хост")

    wi = d.get("web_inspect") or {}
    final_url = wi.get("final_url") or ""
    if final_url:
        m_url = re.search(r"https?://(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})", final_url, re.I)
        if m_url:
            redirect_dom = m_url.group(1).lower()
            _add_related(redirect_dom, f"редирект → {final_url[:70]}")

    if _related:
        d["related_domains"] = _related

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
    def cell(value):
        text = str(value) if value is not None and value != "" else "—"
        # <title> в подписи иначе поглощает оставшийся HTML и все скрипты отчёта.
        return html.escape(text, quote=False).replace("|", "\\|").replace("\n", "<br>")
    out = ["| " + " | ".join(cell(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    return out



_SHOWING_RE = re.compile(r"Showing\s+(\d+)\s+of\s+(\d+)\s+items", re.I)


def _vt_shown(text: str) -> tuple[int, int] | None:
    """«Showing 40 of 200 items» → (40, 200). VirusTotal режет выдачу, а заголовки
    секций печатали плоское «— 40», выдавая срез за полноту: в отчёте стояло
    «SSL-сертификаты — 40», хотя источник прямо сообщал о 200."""
    m = _SHOWING_RE.search(text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def cap_note(data: dict, cat: str) -> list[str]:
    """Строка «показаны N из M» под таблицей, если источник урезал выдачу."""
    t = (data.get("_truncation") or {}).get(cat)
    if not t or t.get("total", 0) <= t.get("shown", 0):
        return []
    return [f"_Показаны первые {t['shown']} из {t['total']} — ограничение выдачи "
            f"{t.get('source', 'источника')}._", ""]


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
    reg_num = g.get("registration_number") or ""
    # Если GLEIF хранит испанский CIF (буква + 8 цифр) — показываем как CIF.
    reg_label = ("CIF/NIF" if re.fullmatch(r"[A-Z]\d{8}", reg_num)
                 else "Рег. номер GLEIF" if reg_num else "Рег. номер")
    md += _md_table(["Параметр", "Значение"], [
        ["Юридическое название", g.get("legal_name")],
        ["LEI", g.get("lei")],
        ["Адрес", addr_s],
        ["Юрисдикция", g.get("jurisdiction")],
        ["Правовая форма", g.get("legal_form")],
        [reg_label, reg_num or None],
        ["Статус юрлица", g.get("entity_status")],
        # registration_status приходил в JSON и молча выбрасывался, а именно он
        # выдаёт протухшую запись: LAPSED = сведения давно не обновлялись.
        ["Статус записи LEI", g.get("registration_status")],
        ["Запись обновлена", g.get("last_update")],
        ["Материнская компания", g.get("ultimate_parent")],
        ["Дочерние", ", ".join(g.get("direct_children") or []) or None],
    ])
    if (g.get("registration_status") or "").upper() in (
            "LAPSED", "RETIRED", "ANNULLED", "DUPLICATE", "MERGED"):
        md += ["", f"⚠ _Регистрация LEI в статусе **{g['registration_status']}** — "
               f"запись не поддерживается в актуальном состоянии, сведения могут "
               f"быть устаревшими._"]
    if g.get("other_matches"):
        md += ["", "_Похожие юрлица в реестре (омонимы, проверьте вручную): "
               + ", ".join(f"«{m}»" for m in g["other_matches"][:5]) + "._"]
    return md + [""]


def render_sections(domain: str, data: dict) -> tuple[list[str], dict]:
    """Детерминированные секции-таблицы для домена. Тонкая обёртка: рендер делегирован
    реестру секций (sections.SECTIONS) — единому источнику правды по разделам.
    Возвращает (markdown-строки, счётчики). Локальный импорт — против циклической
    зависимости (sections импортирует dossier)."""
    import sections
    md = sections.render_target("domain", data, {"target": domain, "kind": "domain"})
    subs = [s for s in data.get("subdomains", set())
            if s.endswith(domain) and s != domain]
    certs_uniq = {(c.get("subject"), c.get("issuer"), c.get("valid_until"))
                  for c in (data.get("certs") or [])}
    counts = {"subdomains": len(subs), "ips": len(data.get("ips") or {}),
              "certs": len(certs_uniq)}
    return md, counts


# Шаблонный текст паст-сайтов, который поисковик отдаёт вместо сниппета. Это не
# данные о цели, а описание самого сервиса.
_CSE_BOILERPLATE = (
    "pastebin.com is the number one paste tool",
    "is a website where you can store text online",
    "it unlocks many cool features",
    "by using pastebin.com you agree",
)


def _cse_terms(identity: dict | None, target: str = "") -> dict:
    """Термины для оценки релевантности результата веб-поиска.

    Разделены на РАЗЛИЧАЮЩИЕ (домен, полное юр. название, тикер) и просто бренд.
    Одного бренда мало, когда он — распространённое слово: по токену «meta»
    в досье приезжали Meta Financial Group, Meta Health и годовой отчёт Zoom,
    где слово «Meta» попалось в предложении про ИИ."""
    import entity as E
    ident = identity or {}
    domains = {d.lower() for d in (ident.get("domains") or []) if d}
    if target and "." in target:
        domains.add(target.lower())
    phrases: set[str] = set()
    for src in (ident.get("legal_name"), ident.get("query"), target):
        norm = E._norm(src or "")
        if norm and " " in norm:            # фраза из 2+ слов уже различает
            phrases.add(norm)
    tickers = {str(t).upper() for t in (ident.get("tickers") or []) if t}
    brand = set(E._tokens(ident.get("legal_name") or ident.get("query") or target or ""))
    brand |= {d.split(".")[0] for d in domains}
    brand = {b for b in brand if len(b) > 1 and b not in ("com", "net", "org")}
    # Название из нескольких значащих слов ⇒ голый бренд НЕ идентифицирует цель.
    name_toks = E._tokens(ident.get("legal_name") or "")
    return {"domains": domains, "phrases": phrases, "tickers": tickers,
            "brand": brand, "ambiguous": len(name_toks) > 1 or (bool(domains) and not ident.get("legal_name"))}


def _cse_relevant(item: dict, terms: dict) -> bool:
    """Относится ли результат веб-поиска к цели. Без этого фильтра «Веб-поиск»
    занимал треть тела досье и состоял из чужих паст и однофамильцев."""
    title = (item.get("title") or "").strip()
    # Заголовок-разметка: поисковик матчил литеральный тег <meta …> в HTML пасты.
    low_title = title.lower()
    if title.startswith("<") or "<!doctype" in low_title or "<meta" in low_title:
        return False
    snip = item.get("snippet") or ""
    if any(b in snip.lower() for b in _CSE_BOILERPLATE):
        return False
    link = (item.get("link") or "").lower()
    hay = f"{title} {snip} {link}".lower()
    if not (terms["domains"] or terms["phrases"] or terms["brand"]):
        return True
    # 1) различающие признаки — принимаем сразу
    if any(re.search(r'(?<![\w.-])' + re.escape(d) + r'(?![\w.-])', hay)
           for d in terms["domains"]):
        return True
    if any(p in hay for p in terms["phrases"]):
        return True
    if any(re.search(rf"\b{re.escape(t)}\b", f"{title} {snip}") for t in terms["tickers"]):
        return True
    # 2) остался только голый бренд — для многословного названия этого мало
    if terms["ambiguous"]:
        return False
    return any(b in hay for b in terms["brand"])


def _cse_section(data: dict, identity: dict | None = None,
                 target: str = "") -> list[str]:
    """Находки веб-поиска, сгруппированные по движку (title/ссылка/сниппет),
    с отсевом нерелевантного. Объём отсева печатается явно — фильтрация не должна
    быть невидимой."""
    cse = data.get("cse") or []
    hits = [c for c in cse if c.get("results")]
    if not hits:
        return []
    terms = _cse_terms(identity, target)
    md = ["## Веб-поиск", ""] + _src_line(data, "cse")
    dropped, shown_any = 0, False
    seen_links: set[str] = set()
    body: list[str] = []
    for c in hits:
        eng = c.get("engine", "?")
        rows = []
        for it in (c.get("results") or []):
            link = it.get("link") or ""
            if link in seen_links:      # один и тот же URL из двух движков
                dropped += 1
                continue
            if not _cse_relevant(it, terms):
                dropped += 1
                continue
            seen_links.add(link)
            rows.append(it)
            if len(rows) >= 8:
                break
        if not rows:
            continue
        shown_any = True
        body += [f"**Движок «{eng}»** — найдено ~{c.get('total_results', '?')}, "
                 f"релевантных показано {len(rows)}:", ""]
        for it in rows:
            title = (it.get("title") or it.get("link") or "—")[:100]
            snip = (it.get("snippet") or "")[:200]
            body.append(f"- [{title}]({it.get('link')})" + (f" — {snip}" if snip else ""))
        body += [""]
    if not shown_any:
        if not dropped:
            return []
        return md + [f"_Релевантных результатов нет: отсеяно {dropped} "
                     f"(однофамильцы, шаблонные сниппеты паст-сайтов)._", ""]
    if dropped:
        body += [f"_Отфильтровано нерелевантных: {dropped}._", ""]
    return md + body


def _webinspect_section(data: dict) -> list[str]:
    """Секция web-check-инспекции: сервер/технологии, заголовки безопасности,
    HSTS/DNSSEC/robots/security.txt, cookies, цепочка редиректов."""
    w = data.get("web_inspect")
    if not w:
        return []
    md = ["## Веб-инспекция (безопасность и технологии)", ""] + _src_line(data, "web_inspect")
    rows = [
        ["HTTP-статус", str(w.get("http_status") or "—")],
        ["Финальный URL", w.get("final_url") or "—"],
        ["Сервер", w.get("server") or "—"],
        ["X-Powered-By", w.get("powered_by") or "—"],
        ["CMS/Generator", w.get("generator") or "—"],
        ["Заголовок <title>", w.get("title") or "—"],
        ["HSTS", "да" if w.get("hsts") else "нет"],
        ["DNSSEC", "да" if w.get("dnssec") else "нет"],
        ["robots.txt", "есть" if w.get("robots_txt") else "нет"],
        ["security.txt", "есть" if w.get("security_txt") else "нет"],
    ]
    # WAF/CDN/TLS от ContrastAPI (если есть — добавляем к таблице)
    if w.get("waf"):
        rows.append(["WAF", w["waf"]])
    if w.get("cdn"):
        rows.append(["CDN", w["cdn"]])
    if w.get("tls_grade"):
        rows.append(["TLS-оценка", w["tls_grade"]])
    if w.get("tls_version"):
        rows.append(["Протокол TLS", w["tls_version"]])
    md += _md_table(["Параметр", "Значение"], rows) + [""]
    missing = w.get("security_headers_missing") or []
    present = [k for k, v in (w.get("security_headers") or {}).items() if v]
    if present or missing:
        md += [f"- **Заголовки безопасности присутствуют:** {', '.join(present) or '—'}",
               f"- **Отсутствуют:** {', '.join(missing) or '—'}", ""]
    chain = w.get("redirect_chain") or []
    if len(chain) > 1:
        md += ["- **Цепочка редиректов:** " + " → ".join(chain[:6]), ""]
    cookies = w.get("cookies") or []
    if cookies:
        crows = [[c.get("name"), "да" if c.get("secure") else "нет",
                  "да" if c.get("httponly") else "нет",
                  "да" if c.get("samesite") else "нет"] for c in cookies[:12]]
        md += _md_table(["Cookie", "Secure", "HttpOnly", "SameSite"], crows) + [""]
    return md


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


def _cert_date(value):
    """UTC-время либо календарная дата; один год не позволяет определить статус."""
    from datetime import datetime, timezone
    value = str(value or "").strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", value):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        for fmt in ("%m/%d/%Y", "%m/%d/%Y, %I:%M:%S %p", "%b %d %H:%M:%S %Y GMT"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    except ValueError:
        pass
    return None


def cert_status(cert: dict, now=None) -> str:
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    end = _cert_date(cert.get("valid_until"))
    start = _cert_date(cert.get("valid_from"))
    if end is None:
        return "unknown"
    # При отсутствии времени сравниваем календарные даты, не выдумываем час.
    date_only = bool(re.fullmatch(r"(?:\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})",
                                  str(cert.get("valid_until") or "")))
    if (end.date() < now.date()) if date_only else (end <= now):
        return "expired"
    if start and start > now:
        return "future"
    return "active"


def _cert_active(valid_until: str | None) -> bool:
    return cert_status({"valid_until": valid_until}) == "active"


def unique_certs(data: dict) -> list[dict]:
    out = {}
    for c in data.get("certs") or []:
        out.setdefault((c.get("subject"), c.get("issuer"), c.get("valid_until")), c)
    return list(out.values())


def domain_subdomains(domain: str, data: dict) -> list[str]:
    domain = domain.lower().rstrip(".")
    return sorted({s.lower().rstrip(".") for s in data.get("subdomains", set())
                   if s.lower().rstrip(".").endswith("." + domain)})


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
    subs = domain_subdomains(domain, data)
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
        "whois_history": whois_history_facts(data),
        "mail": data.get("mail"),
        "ip_count": len(data.get("ips") or {}),
        "ips": list((data.get("ips") or {}).keys())[:15],
        "ip_networks": [ (v.get("name") or v.get("organization")) for v in (data.get("ip_info") or {}).values() ],
        "dns": data.get("dns"),
        "cert_count": len(unique_certs(data)),
        "cert_status_counts": {state: sum(cert_status(c) == state for c in unique_certs(data))
                               for state in ("active", "expired", "future", "unknown")},
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
def _checko_facts(text: str) -> dict | None:
    """Карточка из ответа Checko (РФ ЕГРЮЛ/ЕГРИП). Раньше checko не разбирался
    вообще — его ответ уходил только в сырое приложение, и российские цели
    оставались без юр. идентичности и руководства."""
    j = _load_json(text)
    if not isinstance(j, dict):
        return None
    data = j.get("data")
    if isinstance(data, dict) and isinstance(data.get("Записи"), list):
        recs = data["Записи"]
        if len(recs) != 1:
            return None
        data = recs[0]
    if not isinstance(data, dict) or not data:
        return None
    rukov = data.get("Руковод")
    if isinstance(rukov, list):
        rukov = ", ".join(str((x or {}).get("ФИО") or x) for x in rukov[:5]) or None
    elif isinstance(rukov, dict):
        rukov = rukov.get("ФИО")
    uchr = data.get("Учред")
    founders: list[str] = []
    if isinstance(uchr, dict):
        for grp in uchr.values():
            if isinstance(grp, list):
                founders += [str((x or {}).get("ФИО") or (x or {}).get("НаимСокр") or x)
                             for x in grp[:8]]
    okved = data.get("ОКВЭД")
    if isinstance(okved, dict):
        okved = f"{okved.get('Код', '')} {okved.get('Наим', '')}".strip()
    out = {
        "name": data.get("НаимПолн") or data.get("НаимСокр") or data.get("Наим"),
        "inn": data.get("ИНН"), "ogrn": data.get("ОГРН"), "kpp": data.get("КПП"),
        "status": (data.get("Статус") or {}).get("Наим")
        if isinstance(data.get("Статус"), dict) else data.get("Статус"),
        "registered": data.get("ДатаРег"),
        "address": (data.get("ЮрАдрес") or {}).get("АдресРФ")
        if isinstance(data.get("ЮрАдрес"), dict) else data.get("ЮрАдрес"),
        "okved": okved, "director": rukov, "founders": founders[:8],
        "capital": (data.get("УстКап") or {}).get("Сумма")
        if isinstance(data.get("УстКап"), dict) else data.get("УстКап"),
    }
    return out if any(out.get(k) for k in ("name", "inn", "ogrn")) else None



def _checko_financials(text: str, identity: dict | None) -> dict | None:
    """РСБУ конкретного юрлица; Checko возвращает рубли, не тысячи рублей.

    Формат: https://checko.ru/integration/api/finances (обычная версия).
    Консолидированная МСФО группы должна собираться отдельным источником.
    """
    j = _load_json(text)
    if not isinstance(j, dict) or not identity or not identity.get("inn"):
        return None
    company, records = j.get("company"), j.get("data")
    if not isinstance(company, dict) or not isinstance(records, dict):
        return None
    if str(company.get("ИНН")) != str(identity["inn"]):
        return None
    if (j.get("meta") or {}).get("status") == "error":
        return None
    years = sorted((y for y, v in records.items() if re.fullmatch(r"20\d{2}", y)
                    and isinstance(v, dict)), reverse=True)[:5]
    metrics = {}
    for code, label in (("2110", "Выручка"), ("2400", "Чистая прибыль (убыток)"),
                        ("1600", "Активы"), ("1300", "Капитал и резервы"),
                        ("1400", "Долгосрочные обязательства"), ("1500", "Краткосрочные обязательства")):
        values = {y: records[y].get(code) for y in years}
        values = {y: v.get("СумОтч") if isinstance(v, dict) else v for y, v in values.items()}
        series = {y: v for y, v in values.items() if type(v) in (int, float)}
        if series:
            metrics[label] = series
    if not metrics:
        return None
    bfo = j.get("bo.nalog.ru") or {}
    return {"name": company.get("НаимСокр") or company.get("НаимПолн"),
            "inn": str(identity["inn"]), "currency": "RUB", "years": years,
            "metrics": metrics, "source": "Checko / ФНС / Росстат, РСБУ",
            "scope": "Отдельное юридическое лицо (РСБУ); это не консолидированная отчётность группы по МСФО.",
            "source_url": "https://checko.ru/integration/api/finances",
            "documents": {y: u for y, u in (bfo.get("Отчет") or {}).items()
                          if y in years and isinstance(u, str) and u.startswith("https://bo.nalog.")}}


def failed_sources(results: list[dict]) -> list[dict]:
    """Список сбойных вызовов — чтобы нарратив НЕ выдавал недоступность источника
    за отрицательный факт («должностных лиц нет» при ConnectError у OpenCorporates)."""
    out, seen = [], set()
    for r in results:
        if r.get("ok"):
            continue
        key = (r.get("server"), r.get("tool"))
        if key in seen:
            continue
        seen.add(key)
        why = re.sub(r"\s+", " ", (r.get("text") or "")).replace(
            "источник недоступен", "").strip(" :()")
        out.append({"name": r.get("name") or r.get("server"), "tool": r.get("tool"),
                    "reason": why[:100]})
    return out


def extract_company_data(results: list[dict], identity: dict | None = None) -> dict:
    """Свести «корпоративный» слой ответов (без выдумывания): GLEIF, должностные
    лица (OpenCorporates), сводка companyscope, SEC-отчёты, ЕГРЮЛ, санкции."""
    d: dict = {"gleif": None, "officers": None, "borme": None, "companyscope": None,
               "filings": None, "sanctions": None, "sec": None, "wikipedia": None,
               "checko": None, "financials": None, "cse": [], "uk_ch": None,
               "aleph": None, "stock_quote": None, "ticker_candidates": [],
               "cif": None, "_sources": {}}
    for r in results:
        if r.get('tool') == 'fi_company_records':
            j = _load_json(r.get('text', ''))
            if isinstance(j, dict):
                d['fi_registry'] = j
            continue
        if r.get('tool') == 'organization_research':
            j = _load_json(r.get('text', ''))
            if isinstance(j, dict):
                d['organization_research'] = j
            continue
        if r.get("phase") == "russia_newdb":
            j = _load_json(r.get("text", ""))
            if isinstance(j, dict): d["russia_newdb"] = j
            continue
        if r.get("tool") == "russia_connections":
            j = _load_json(r.get("text", "")) if r.get("ok") else None
            d["russia_connections"] = j if isinstance(j, dict) and j.get("company") else {"unavailable": True}
            continue
        if not r.get("ok"):
            continue
        sid, tool, text = r.get("server"), r.get("tool", ""), r.get("text", "") or ""
        # Базовое имя источника: метка шага уже содержит «· инструмент».
        nm = (r.get("name") or sid or "?").split(" · ")[0]
        if sid == "directapi" and tool == "uz_company_records":
            j = _load_json(text)
            if (isinstance(j, dict) and j.get("matched") and identity
                    and identity.get("jurisdiction") == "UZ"
                    and identity.get("inn") == j.get("tax_id")):
                d["uz_directory"] = j
                d["_sources"]["c_uz"] = [rec["source_url"] for rec in j.get("records", [])]
            continue
        # Вызовы фазы 0 сделаны РАЗГОВОРНОЙ строкой запроса и служили только для
        # выбора кандидата. Их карточка не должна становиться утверждённым
        # юрлицом — иначе отвергнутый кандидат (датская META) вернулся бы сюда.
        if r.get("phase") == "resolve":
            # Wikipedia и GLEIF: данные не зависят от фазы вызова.
            # Сохраняем как запасной вариант — если основная фаза не успеет ответить.
            if sid == "directapi" and tool == "wikipedia_summary":
                j = _load_json(text)
                if isinstance(j, dict) and not j.get("error") and j.get("title"):
                    d.setdefault("_probe_wikipedia", j)
            elif sid == "directapi" and tool == "gleif_entity":
                j = _load_json(text)
                if isinstance(j, dict) and not j.get("error") and j.get("legal_name"):
                    d.setdefault("_probe_gleif", (j, nm))
            elif sid == "directapi" and tool == "sec_edgar":
                j = _load_json(text)
                if isinstance(j, dict) and not j.get("error") and identity and identity.get("cik") == j.get("cik"):
                    d["sec"] = j
            elif sid == "checko" and identity and identity.get("inn"):
                ck = _checko_facts(text)
                if ck and str(ck.get("inn")) == str(identity["inn"]):
                    d["checko"] = ck
                    d["_sources"]["c_checko"] = [f"{nm} ({tool}/probe)"]
            continue
        if sid == "directapi" and tool == "gleif_entity":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("legal_name"):
                d["gleif"] = j
                d["_sources"]["org"] = [f"{nm} (gleif_entity)"]
            elif isinstance(j, dict) and j.get("did_you_mean"):
                # Точного юрлица не нашли — сохраняем подсказки, чтобы аналитик
                # мог переспросить по юридическому имени (а не гадал молча).
                d["gleif_hint"] = j
        elif sid == "directapi" and tool == "sec_edgar":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("name"):
                d["sec"] = j
        elif sid == "directapi" and tool == "wikipedia_summary":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("title"):
                d["wikipedia"] = j
        elif sid == "directapi" and tool == "google_cse":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("results"):
                d["cse"].append(j)
                d["_sources"].setdefault("cse", []).append(
                    f"{nm} (google_cse:{j.get('engine', '')})")
                # Извлекаем CIF/NIF из URL и сниппетов (испанский налоговый номер).
                if not d.get("cif"):
                    for res in (j.get("results") or []):
                        m = re.search(r'\b(?:nif|cif)[=:\s]+([AB]\d{8})\b',
                                      (res.get("link") or "") + " " + (res.get("snippet") or ""),
                                      re.I)
                        if m:
                            d["cif"] = m.group(1).upper()
        elif (sid == "directapi" and tool == "corporate_website") or (sid == "official-import" and tool == "official_pages"):
            j = _load_json(text)
            if isinstance(j, dict) and j.get("pages"):
                d["official"] = j
        elif sid in ("directapi", "opencorporates") and tool == "opencorporates_officers":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("officers"):
                d["officers"] = j
        elif sid == "directapi" and tool in ("borme_company", "borme_publications"):
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("name"):
                d["borme"] = j
                d["_sources"].setdefault("c_borme", []).append(f"{nm} (borme_company)")
        elif sid == "googlesearch" and tool == "web_search":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("results"):
                d["cse"].append(j)
                d["_sources"].setdefault("cse", []).append(
                    f"{nm} (web_search:{j.get('engine', '')})")
        elif sid == "companyscope" and text.strip():
            d["companyscope"] = text[:2000]
            d["_sources"].setdefault("c_companyscope", []).append(f"{nm} ({tool})")
        elif sid == "filingfirehose" and text.strip():
            d["filings"] = text[:1800]
        elif sid == "directapi" and tool == "sec_financials":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("metrics"):
                d["financials"] = j
                d["_sources"].setdefault("c_financials", []).append(f"{nm} ({tool})")
        elif sid == "directapi" and tool == "stock_quote":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("price") is not None:
                d["stock_quote"] = j
                d["_sources"].setdefault("c_financials", []).append(
                    f"{nm} (stock_quote:{j.get('ticker', '')})")
        elif sid == "directapi" and tool == "stock_ticker_lookup":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("results"):
                d["ticker_candidates"].extend(j["results"][:5])
        elif sid == "stockscope" and text.strip():
            d.setdefault("financials_raw", text[:2500])
        elif sid == "checko" and tool == "get_finances":
            fin = _checko_financials(text, identity)
            if fin:
                d["financials"] = fin
                d["_sources"].setdefault("c_financials", []).append(f"{nm} ({tool})")
        elif sid == "checko" and tool in ("get_company", "search"):
            ck = _checko_facts(text)
            if ck and (identity is None or (identity.get("inn") and str(ck.get("inn")) == str(identity["inn"]))):
                d["checko"] = ck
                d["_sources"].setdefault("c_checko", []).append(f"{nm} ({tool})")
        elif sid == "the-stall" and text.strip():
            d["sanctions"] = text[:1500]
        elif sid == "directapi" and tool == "uk_companies_house":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("items"):
                d["uk_ch"] = j
                d["_sources"].setdefault("c_uk_ch", []).append(f"{nm} (uk_companies_house)")
        elif sid == "directapi" and tool == "aleph_search":
            j = _load_json(text)
            if isinstance(j, dict) and not j.get("error") and j.get("results"):
                d["aleph"] = j
                d["_sources"].setdefault("c_aleph", []).append(f"{nm} (aleph_search)")
    # Запасные данные probe-фазы, если основная фаза не успела ответить.
    if not d.get("wikipedia") and d.get("_probe_wikipedia"):
        d["wikipedia"] = d.pop("_probe_wikipedia")
    else:
        d.pop("_probe_wikipedia", None)
    if not d.get("gleif") and d.get("_probe_gleif"):
        gleif_j, gleif_nm = d.pop("_probe_gleif")
        # Проба допустима лишь если резолвер подтвердил именно эту запись.
        if identity and identity.get("lei") == gleif_j.get("lei") and identity.get("legal_name"):
            d["gleif"] = gleif_j
            d["_sources"]["org"] = [f"{gleif_nm} (gleif_entity/probe)"]
    else:
        d.pop("_probe_gleif", None)
    if identity is not None and d.get("gleif"):
        import entity
        if (not identity.get("legal_name") or
                entity._norm(d["gleif"].get("legal_name", "")) != entity._norm(identity["legal_name"])):
            d["gleif"] = None
            d["_sources"].pop("org", None)
    if identity is not None and d.get("wikipedia"):
        import entity
        name = identity.get("legal_name") or identity.get("query") or ""
        if not entity._wiki_supports({"name": name}, d["wikipedia"]):
            d["wikipedia"] = None
    return d


def render_company_sections(name: str, data: dict) -> list[str]:
    """Секции корпоративного слоя. Тонкая обёртка над реестром секций
    (sections.render_target('company', …)) — единым источником правды."""
    import sections
    return sections.render_target("company", data, {"target": name, "kind": "company"})


def company_data_for_llm(name: str, data: dict, infra: list[dict],
                         identity: dict | None = None,
                         failed: list[dict] | None = None) -> dict:
    """Компактные факты для LLM-нарратива по компании (без сырья).

    Передаём ВСЕ извлечённые слои и список сбойных источников: раньше сюда
    уходили только GLEIF и officers, поэтому упавший OpenCorporates превращался
    в утверждение «компания не имеет известных должностных лиц»."""
    g = data.get("gleif") or {}
    off = data.get("officers") or {}
    borme = data.get("borme") or {}
    sec = data.get("sec") or {}
    ck = data.get("checko") or {}
    ident = identity or {}
    return {
        "company": name,
        "organization_research": __import__('organization_research').facts_for_llm(data['organization_research'])
            if data.get('organization_research') else None,
        "fi_registry": {key: value for key, value in (data.get('fi_registry') or {}).items()
                        if key not in ('records', 'addresses', 'registered_entries')},
        "russia_connections": ({
            "relations": (data.get("russia_connections") or {}).get("relations", []),
            "citizenship": "not_established",
            "scope": "Сообщения источников требуют независимой проверки; отсутствие связей не установлено",
            "unavailable": (data.get("russia_connections") or {}).get("unavailable", False),
        } if data.get("russia_connections") else None),
        "official_claims": (data.get("official") or {}).get("claims", []),
        "official_metrics": (data.get("official") or {}).get("metrics", []),
        "official_business": (data.get("official") or {}).get("businesses", []),
        "official_projects": (data.get("official") or {}).get("projects", []),
        "official_people": (data.get("official") or {}).get("people", [])[:18],
        "identity": {
            "query": ident.get("query"), "legal_name": ident.get("legal_name"),
            "confidence": ident.get("confidence"), "lei": ident.get("lei"),
            "cik": ident.get("cik"), "tickers": ident.get("tickers") or [],
            "inn": ident.get("inn"), "ogrn": ident.get("ogrn"),
            "jurisdiction": ident.get("jurisdiction"),
        } if ident else None,
        "organization": {
            "legal_name": g.get("legal_name"), "lei": g.get("lei"),
            "jurisdiction": g.get("jurisdiction"), "status": g.get("entity_status"),
            "registration_status": g.get("registration_status"),
            "reg_no": g.get("registration_number"),
            "parent": g.get("ultimate_parent"),
            "subsidiaries": g.get("direct_children") or [],
        } if g.get("legal_name") else None,
        "sec": {"name": sec.get("name"), "cik": sec.get("cik"),
                "tickers": sec.get("tickers"), "exchanges": sec.get("exchanges"),
                "sic": sec.get("sic_description"), "address": sec.get("address"),
                "filings_count": len(sec.get("recent_filings") or [])} if sec else None,
        "checko": ck or None,
        "uz_directory": {k: v for k, v in (data.get("uz_directory") or {}).items()
                         if k not in ("records", "evidence_text")},
        "directory_sources": [{"name": r.get("source_url", "").split("/")[2],
                               "url": r.get("source_url"), "source_dates": r.get("source_dates"),
                               "retrieved_at": r.get("retrieved_at")}
                              for r in (data.get("uz_directory") or {}).get("records", [])],
        "web_search": [{"engine": c.get("engine"), "results": c.get("results", [])[:10]}
                       for c in data.get("cse") or []],
        "wikipedia": (data.get("wikipedia") or {}).get("extract"),
        "companyscope": data.get("companyscope"),
        "financials": data.get("financials"),
        "opencorporates_officers_count": off.get("officers_count"),
        "registry_director": ck.get("director"),
        "directory_director": (data.get("uz_directory") or {}).get("director"),
        "officers_sample": [o.get("name") for o in (off.get("officers") or [])[:8]],
        "borme": {
            "name": borme.get("name"), "nif": borme.get("nif"),
            "date_constitution": borme.get("date_constitution"),
            "officers": (borme.get("officers") or [])[:20],
            "announcements_count": len(borme.get("announcements") or []),
            "officer_events_count": len(borme.get("officer_events") or []),
            "announcements_sample": (borme.get("announcements") or [])[:10],
            "officer_events_sample": (borme.get("officer_events") or [])[:20],
            "scope": borme.get("scope") or "Исторические события, не список действующих полномочий",
            "source_url": borme.get("url"),
            "failures_count": len(borme.get("failures") or []),
        } if borme else None,
        "domains": [f["domain"] for f in infra],
        "infrastructure": infra,
        "sanctions": ({"status": "source_response_available", "text": data["sanctions"]}
                      if data.get("sanctions") else {"status": "not_collected"}),
        "sources_failed": failed or [],
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


# Национальный реестр по юрисдикции — подсказка «где искать то, чего у нас нет».
# Раньше вместо этого в КАЖДОМ отчёте стояла захардкоженная фраза про испанский
# Registro Mercantil/BORME — она уезжала дословно и в досье по Meta, и по Apple.
_REGISTRY_HINT: dict[str, str] = {
    # ES убран: borme_company (libreborme.net, keyless) покрывает этот реестр напрямую.
    "RU": "ЕГРЮЛ / ФНС (Россия)",
    "US": "SEC EDGAR + реестр Secretary of State штата",
    "GB": "Companies House (Великобритания)",
    "DE": "Handelsregister / Unternehmensregister (Германия)",
    "FR": "Infogreffe / RCS (Франция)",
    "DK": "CVR (Дания)", "NL": "KvK (Нидерланды)", "IT": "Registro Imprese (Италия)",
    "SE": "Bolagsverket (Швеция)", "PL": "KRS (Польша)", "CH": "Zefix (Швейцария)",
}


def render_limitations(results: list[dict], catalog: dict,
                       identity: dict | None = None) -> list[str]:
    """Честный раздел «Ограничения данных»: какие источники не дали данных и почему
    (нужен ключ/баланс/недоступен). Ничего не выдумываем — прямо перечисляем пробелы."""
    reasons: list[str] = []
    seen_reason: set[tuple[str, str]] = set()
    for r in results:
        if r.get("ok"):
            continue
        # Указываем ИНСТРУМЕНТ, а не только сервер: «Direct Lookups: ReadTimeout»
        # четыре раза подряд не давало понять, что отвалился именно sec_edgar —
        # самый важный вызов для досье по компании.
        name = r.get("name", r.get("server", "?"))
        tool = r.get("tool")
        if tool and tool not in str(name):
            name = f"{name} · {tool}"
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
    # Подсказка по национальному реестру — ТОЛЬКО когда юрисдикция известна.
    jur = ((identity or {}).get("jurisdiction") or "").upper().split("-")[0]
    hint = _REGISTRY_HINT.get(jur)
    if not reasons and not absent and not hint:
        return []
    md = ["## Ограничения данных", "",
          "Досье собрано по доступным открытым источникам. Не удалось получить:"]
    md += reasons
    for a in dict.fromkeys(absent):
        md.append(f"- {a}")
    if hint:
        md += ["",
               f"_Полный состав совета директоров и учредительные документы требуют "
               f"национального реестра ({hint}) — он в наборе источников не подключён; "
               f"приведено только то, что дали GLEIF/OpenCorporates/SEC._", ""]
    else:
        md += [""]
    return md
