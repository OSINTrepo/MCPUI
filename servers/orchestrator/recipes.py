"""Определение типа цели и маршрутизация на серверы.

- detect_targets(task): вытаскивает цели (username/email/domain/ip/hash/inn/url/ticker).
- CURATED: проверенные рецепты (сервер+инструмент+аргументы) с известными схемами.
- Для остального — generic-путь в server.py (tools/list + эвристика/LLM).
"""
from __future__ import annotations

import base64
import re

# --- Регэкспы типов целей (порядок важен: специфичное раньше общего) ---
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(r"\bhttps?://[^\s]+", re.I)
RE_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
RE_INN = re.compile(r"\b\d{10}\b|\b\d{12}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
RE_TICKER = re.compile(r"\$([A-Z]{1,5})\b")
# Тикер словами: «тикер AAPL», «ticker aapl» (без $ — так пишут чаще).
RE_TICKER_KW = re.compile(r"(?:тикер|ticker)\s+\$?([A-Za-z]{1,5})\b", re.I)

# Компания по названию: «компания Сбербанк», «ООО Ромашка», «ПАО «Газпром»».
# Без этого путь company→checko/companyscope был недостижим (6 серверов вхолостую).
RE_ORG = re.compile(
    r"\b((?:ООО|ОАО|ПАО|ЗАО|АО|ИП)\s+[«\"']?[\w\-]+(?:\s+[\w\-]+){0,3})", re.I)
RE_COMPANY_KW = re.compile(
    r"(?:компани[июяе]|фирм[ауые]|организаци[июяе]|company)\s+"
    r"[«\"']?([\w\-]+(?:\s+[\w\-]+){0,3})", re.I)

# Стоп-слова в «имени компании»: предлоги/служебные, которые ошибочно попадают в
# захват из фраз вроде «компанию ПО ИНН 7707083893» → бракованное имя.
_COMPANY_STOP = {"по", "с", "на", "об", "о", "из", "для", "к", "у", "при", "за",
                 "инн", "огрн", "огрнип", "кпп", "названию", "имени", "номеру"}


def _clean_company(name: str) -> str | None:
    """Чистит захваченное имя компании: убирает ведущие предлоги/служебные слова
    и обрывает на длинном числе (ИНН/ОГРН — не часть названия). None, если после
    чистки ничего осмысленного не осталось (тогда это не имя компании)."""
    out: list[str] = []
    for tok in name.strip(" «»\"'").split():
        if re.fullmatch(r"\d{6,}", tok):          # длинное число = ИНН/ОГРН
            break
        if not out and tok.lower().strip(".,") in _COMPANY_STOP:
            continue                               # ведущие предлоги/служебные
        out.append(tok)
    cleaned = " ".join(out).strip(" «»\"'")
    return cleaned if len(cleaned) >= 2 else None

# Идентификаторы, под которые НЕТ ни одного сервера в реестре. Ловим их явно,
# чтобы честно сказать «не поддерживается», а не гонять общий веб-поиск и
# выдавать правдоподобный, но бесполезный отчёт.
RE_PHONE = re.compile(r"(?:\+7|\b8)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}\b"
                      r"|\+\d{10,15}\b")
RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Голый ник: «проверь durov», «кто такой durov». Берём латинский токен, если в
# запросе не нашлось ничего более конкретного и токен не служебное слово.
RE_LATIN_TOKEN = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_.\-]{2,29})\b")
_STOPWORDS = {
    "check", "find", "lookup", "search", "about", "info", "report", "osint",
    "domain", "site", "email", "mail", "user", "username", "nickname", "company",
    "phone", "hash", "url", "profile", "profiles", "social", "accounts", "account",
    "the", "and", "for", "please", "give", "show", "make", "what", "who", "is",
    "ip", "dns", "whois", "data", "all", "any", "new", "get",
}


def detect_targets(task: str) -> list[dict]:
    """Список целей [{'type','value'}] по тексту задачи (без дублей типов-значений)."""
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(t: str, v: str):
        key = (t, v.lower())
        if key not in seen:
            seen.add(key)
            found.append({"type": t, "value": v})

    for v in RE_URL.findall(task):
        add("url", v.rstrip(".,);"))
    for v in RE_EMAIL.findall(task):
        add("email", v)
    for v in RE_HASH.findall(task):
        add("hash", v)
    # Криптокошельки → блокчейн-OSINT (twzrd; лучше всего Solana). До домена/ИНН.
    for v in RE_BTC.findall(task) + RE_ETH.findall(task):
        add("crypto", v)
    # Телефон — до ИНН/домена: номер не должен утечь в другие регэкспы.
    # Нормализуем к E.164-подобному виду (API ждёт номер без разделителей).
    for v in RE_PHONE.findall(task):
        norm = re.sub(r"[^\d+]", "", v)
        if norm.startswith("8") and len(norm) == 11:
            norm = "+7" + norm[1:]
        elif not norm.startswith("+"):
            norm = "+" + norm
        add("phone", norm)
    # домены — но не части e-mail/url уже добавленных
    emails = " ".join(x["value"] for x in found if x["type"] == "email")
    urls = " ".join(x["value"] for x in found if x["type"] == "url")
    for v in RE_DOMAIN.findall(task):
        if v in emails or v in urls:
            continue
        if RE_IPV4.fullmatch(v):
            continue
        add("domain", v)
    for v in RE_IPV4.findall(task):
        parts = v.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            add("ip", v)
    for v in RE_INN.findall(task):
        add("inn", v)
    for v in RE_TICKER.findall(task):
        add("ticker", v)
    for v in RE_TICKER_KW.findall(task):
        add("ticker", v.upper())

    # Компания по названию (ООО/ПАО/… или «компания X»). Чистим захват, чтобы
    # «компанию по ИНN 7707083893» не превращалось в компанию «по ИНН …».
    for rx in (RE_ORG, RE_COMPANY_KW):
        for v in rx.findall(task):
            name = _clean_company(v)
            if name:
                add("company", name)

    # Явный username: "username X", "ник X", "@handle"
    m = re.search(r"(?:username|ник|никнейм|user)\s+@?([a-zA-Z0-9_.]{2,30})", task, re.I)
    if m:
        add("username", m.group(1))
    for m in re.finditer(r"(?<!\S)@([a-zA-Z0-9_.]{2,30})", task):
        add("username", m.group(1))

    # Голый ник: ничего конкретного не нашли, но есть латинский токен —
    # для OSINT это почти всегда username («проверь durov», «кто такой durov»).
    if not found:
        for tok in RE_LATIN_TOKEN.findall(task):
            if tok.lower() in _STOPWORDS:
                continue
            add("username", tok)
            break

    return found


# Явно вредоносные намерения. Отказ дублируется на уровне оркестратора, а не
# только в системном промпте: промпт можно обойти или сменить модель, а этот
# гейт срабатывает всегда. Список намеренно узкий — законный OSINT не блокируем.
RE_HARM = re.compile(
    r"взлом|взломать|hack\s+(?:account|into)|подобрать\s+пароль|брутфорс|brute\s*force"
    r"|следить\s+за|слежка|stalk"
    r"|домашний\s+адрес|адрес\s+проживания|где\s+жив[её]т"
    r"|паспортны[ех]\s+данны|номер\s+карты|снилс",
    re.I)

# Вопросы «что ты умеешь» — на них отвечает catalog(), а не веб-поиск.
RE_META = re.compile(
    r"что\s+ты\s+умеешь|что\s+умеет|какие\s+(?:источники|серверы|инструменты)"
    r"|твои\s+возможности|список\s+инструментов|what\s+can\s+you\s+do", re.I)


def harm_notice(task: str) -> str | None:
    """Отказ на явно вредоносные запросы (преследование, взлом, деанон ради вреда)."""
    if not RE_HARM.search(task):
        return None
    return ("Отказ: запрос выходит за рамки законной OSINT-аналитики по открытым "
            "источникам (взлом, преследование, поиск домашнего адреса/личных "
            "документов). Такие задачи здесь не выполняются. "
            "Сформулируйте цель в рамках открытых данных — например, проверка "
            "домена, компании, публичных профилей по username.")


def unsupported_notice(task: str) -> str | None:
    """Явное «не поддерживается» для целей, под которые нет ни одного сервера.

    Честный отказ лучше общего веб-поиска, который вернёт правдоподобный,
    но бесполезный отчёт (и создаст ложное впечатление проверки)."""
    kinds = []
    if re.search(r"\bФИО\b|\b(?:фамили|отчеств)", task, re.I):
        kinds.append("поиск по ФИО")
    if not kinds:
        return None
    return ("Не поддерживается: " + ", ".join(kinds) + ". "
            "В подключённом наборе источников нет ни одного сервера для таких "
            "целей — искать по ним нечем. Доступные типы целей: username, email, "
            "домен, IP, URL, хеш файла, компания/ИНН, тикер, телефон, "
            "криптокошелёк (Solana).")


def guess_target_type(task: str) -> list[dict]:
    """Если явных целей нет — пусто (задачу решит LLM-путь по каталогу)."""
    return detect_targets(task)


# --- Компания → домены: эвристические кандидаты для проверки резолвингом --------
# Юридические формы/суффиксы, которые НЕ входят в доменное имя бренда.
_ORG_SUFFIX = {
    "sa", "s", "a", "sl", "sau", "slu", "sас", "inc", "llc", "ltd", "limited",
    "corp", "corporation", "co", "company", "gmbh", "ag", "plc", "group", "grupo",
    "holding", "holdings", "spa", "srl", "bv", "nv", "oy", "ab", "as", "pao",
    "oao", "ooo", "zao", "ip", "пао", "оао", "ооо", "зао", "ао", "ип",
}
_BRAND_TLDS = ("com", "net", "org", "io", "es", "eu", "co", "group", "tech")


def company_domain_candidates(name: str, limit: int = 8) -> list[str]:
    """Кандидаты доменов из названия компании (детерминированно, без ключей).

    Берём значащие токены (без юр. форм), склеиваем слитно и через дефис,
    навешиваем частые TLD. Кандидаты потом ПРОВЕРЯЮТСЯ резолвингом (server.py) —
    сюда попадают только реально существующие домены, ничего не выдумывается."""
    toks = [re.sub(r"[^a-z0-9]", "", t.lower())
            for t in re.split(r"[\s.,«»\"'()]+", name or "") if t.strip()]
    toks = [t for t in toks if t and t not in _ORG_SUFFIX and not t.isdigit()]
    if not toks:
        return []
    joined = "".join(toks)
    stems: list[str] = []
    for s in (joined, "-".join(toks), toks[0], "".join(toks[:2])):
        if 2 <= len(s) <= 40 and s not in stems:
            stems.append(s)
    out: list[str] = []
    for stem in stems:
        for tld in _BRAND_TLDS:
            cand = f"{stem}.{tld}"
            if cand not in out:
                out.append(cand)
    return out[:limit]


# --- Проверенные рецепты: (target_type, server_id) -> (tool, args_fn) ---
# args_fn(value) -> dict. Схемы подтверждены тестами предыдущего этапа.
CURATED: dict[tuple[str, str], tuple[str, object]] = {
    ("username", "maigret"): ("search_username", lambda v: {"username": v, "tags": ["social"]}),
    ("email", "maigret"): ("search_username", lambda v: {"username": v.split("@")[0], "tags": ["social"]}),
    ("email", "openosint"): ("search_email", lambda v: {"email": v}),
    ("username", "openosint"): ("search_username", lambda v: {"username": v}),
    ("domain", "shodan"): ("dns_lookup", lambda v: {"hostnames": [v]}),
    ("domain", "virustotal"): ("get_domain_report", lambda v: {"domain": v}),
    ("domain", "openosint"): ("search_domain", lambda v: {"domain": v}),
    ("domain", "dnstwist"): ("fuzz_domain", lambda v: {"domain": v, "registered_only": True}),
    ("ip", "shodan"): ("ip_lookup", lambda v: {"ip": v}),
    ("ip", "virustotal"): ("get_ip_report", lambda v: {"ip": v}),
    ("ip", "openosint"): ("search_ip", lambda v: {"ip": v}),
    ("hash", "virustotal"): ("get_file_report", lambda v: {"hash": v}),
    ("url", "virustotal"): ("get_url_report", lambda v: {"url": v}),
    # ИНН → прямая карточка по ИНН (search умеет только by name/okved, поэтому
    # раньше по ИНН возвращалась 1000 чужих компаний). 10 цифр = юрлицо
    # (get_company), 12 = ИП (get_entrepreneur). __tool__ переопределяет инструмент.
    ("inn", "checko"): ("get_company",
        lambda v: {"inn": v} if len(v) == 10 else {"__tool__": "get_entrepreneur", "inn": v}),
    # Компания по НАЗВАНИЮ — поиск по наименованию (это корректно для имени).
    ("company", "checko"): ("search", lambda v: {"by": "name", "obj": "org", "query": v}),
    ("company", "companyscope"): ("lookup_company", lambda v: {"query": v}),
    ("inn", "companyscope"): ("lookup_company", lambda v: {"query": v}),
    ("ticker", "stockscope"): ("stock_financials", lambda v: {"query": v}),
    # Домен — дополнительные углы (не только Shodan/VirusTotal):
    ("domain", "crawlgraph"): ("backlinks", lambda v: {"domain": v}),        # входящие ссылки
    ("domain", "voidly"): ("get_domain_status", lambda v: {"domain": v}),    # блокировки по странам
    ("domain", "brightdata"): ("search_engine", lambda v: {"query": v}),     # веб-присутствие (Google)
    ("url", "brightdata"): ("scrape_as_markdown", lambda v: {"url": v}),     # содержимое страницы
    # vulneramcp — ТОЛЬКО пассивная разведка (публичные источники, без активных
    # сканов/атак). Активные проверки (xss/sqli/порты) НЕ запускаем автоматически
    # против произвольных доменов — это несанкционированное сканирование.
    ("domain", "vulneramcp"): ("recon.subfinder", lambda v: {"domain": v, "silent": True}),
    # ZoomEye v2: поиск-дорк в base64 (нужны кредиты аккаунта, иначе 402).
    ("ip", "zoomeye"): ("zoomeye_search",
        lambda v: {"qbase64": base64.b64encode(f'ip="{v}"'.encode()).decode()}),
    ("domain", "zoomeye"): ("zoomeye_search",
        lambda v: {"qbase64": base64.b64encode(f'domain="{v}"'.encode()).decode()}),
    # Свободный запрос — новости и оценка предвзятости источников.
    ("query", "helium"): ("search_news", lambda v: {"query": v, "limit": 5}),
    # Тикер/компания — лента свежих SEC-отчётов США (по РЫНКУ, не по конкретной цели).
    ("ticker", "filingfirehose"): ("search_8k_filings", lambda v: {"limit": 5}),
    ("company", "filingfirehose"): ("search_8k_filings", lambda v: {"limit": 5}),
    # the-stall (платный x402: часто «нужна оплата»). Кошелёк — security-скрин;
    # тикер — оценка качества эмитента; санкции по имени компании.
    ("crypto", "the-stall"): ("address-security", lambda v: {"address": v}),
    ("ticker", "the-stall"): ("equity-quality-screen", lambda v: {"ticker": v}),
    ("company", "the-stall"): ("sanctions-screening", lambda v: {"name": v, "type": "entity"}),
    # Криптокошелёк → twzrd (бесплатный intel-score; лучше всего для Solana).
    ("crypto", "twzrd"): ("score_wallet_for_intel", lambda v: {"wallet": v}),
    # ContrastAPI: метаданные номера (страна, оператор, тип, таймзона).
    # Владельца не раскрывает — это и не задача открытых источников.
    ("phone", "contrastapi"): ("phone_lookup", lambda v: {"number": v}),
    ("domain", "contrastapi"): ("domain_report", lambda v: {"domain": v}),
    ("ip", "contrastapi"): ("ip_lookup", lambda v: {"ip": v}),
    # directapi — прямые публичные API (RDAP/GLEIF). Домен/IP в авто-режиме идут
    # глубоким веером (DEEP_DOMAIN/DEEP_IP ниже); эти записи — для ручного вызова
    # и не-deep режима. Компания → глобальный реестр LEI (GLEIF).
    ("domain", "directapi"): ("rdap_domain", lambda v: {"domain": v}),
    ("ip", "directapi"): ("rdap_ip", lambda v: {"ip": v}),
    ("company", "directapi"): ("gleif_entity", lambda v: {"query": v}),
}

# --- Глубокое досье по домену/IP: набор ПРИКреплённых вызовов (server, tool, args) ---
# Разворачивается в server.py в отдельные шаги, обходя лимит «1 инструмент на
# (тип,сервер)» из CURATED (VirusTotal зовём несколько раз — по каждой связи).
# Серверы, которых нет в каталоге (напр. ключ не введён), пропускаются в build_plan.
VT_DOMAIN_RELATIONSHIPS = [
    "resolutions",                    # пассивный DNS (домены/IP на диапазоне)
    "subdomains",                     # поддомены
    "historical_ssl_certificates",    # исторические SSL-сертификаты
    "communicating_files",            # общающиеся файлы (malware)
    "historical_whois",               # исторический WHOIS
]


def deep_domain_steps(v: str, vt_rel_cap: int) -> list[tuple[str, str, dict]]:
    """Батарея вызовов для глубокого досье по домену (как в референс-отчёте)."""
    steps: list[tuple[str, str, dict]] = [
        ("virustotal", "get_domain_report", {"domain": v}),
    ]
    # VT-связи — по одной на вызов; на free-тарифе (4 req/min) режем cap'ом.
    for rel in VT_DOMAIN_RELATIONSHIPS[:max(0, vt_rel_cap)]:
        steps.append(("virustotal", "get_domain_relationship",
                      {"domain": v, "relationship": rel, "limit": 40}))
    steps += [
        ("contrastapi", "domain_report", {"domain": v}),           # WHOIS/SSL/DNS/поддомены
        ("vulneramcp", "recon.subfinder", {"domain": v, "silent": True}),  # пассивные поддомены
        ("directapi", "rdap_domain", {"domain": v}),               # регистрация/NS/статусы
        ("directapi", "crtsh", {"domain": v}),                     # CT-поддомены (best-effort)
        ("directapi", "dns_records", {"domain": v}),               # A/MX/NS/TXT + SPF/DMARC
        ("directapi", "whois_history", {"domain": v}),             # WhoisXML (ключ) — история
        ("directapi", "censys_domain", {"domain": v}),             # Censys (ключ) — инфраструктура
    ]
    return steps


def deep_ip_steps(v: str, vt_rel_cap: int) -> list[tuple[str, str, dict]]:
    """Батарея вызовов для глубокого досье по IP."""
    steps: list[tuple[str, str, dict]] = [
        ("shodan", "ip_lookup", {"ip": v}),
        ("virustotal", "get_ip_report", {"ip": v}),
        ("directapi", "rdap_ip", {"ip": v}),                       # сеть/AS/организация
        ("directapi", "censys_host", {"ip": v}),                   # Censys (ключ) — порты/сервисы
    ]
    for rel in ["resolutions", "communicating_files"][:max(0, vt_rel_cap)]:
        steps.append(("virustotal", "get_ip_relationship",
                      {"ip": v, "relationship": rel, "limit": 40}))
    return steps


def deep_company_steps(name: str) -> list[tuple[str, str, dict]]:
    """Батарея вызовов «корпоративного» слоя досье по компании (юр. идентичность,
    структура, должностные лица, санкции, отчётность). Инфраструктурный слой
    (домены → deep_domain_steps) добавляется отдельно в server.py после резолвинга
    доменов. Серверы не из каталога пропускаются в build_plan."""
    # Прим.: filingfirehose (SEC 8-K) НЕ включаем — его search_8k_filings отдаёт
    # свежие отчёты ПО РЫНКУ, а не по конкретной компании (был бы шум чужих эмитентов).
    return [
        ("directapi", "gleif_entity", {"query": name}),            # LEI: идентичность + связи
        # opencorporates_officers здесь НЕ зовём: без юрисдикции одно и то же имя
        # ловит чужую регистрацию (INDRA SISTEMAS есть и в ES, и в ca_qc). Его
        # вызывает вторая волна в server.py — по ЮРИДИЧЕСКОМУ имени и стране из GLEIF.
        ("companyscope", "lookup_company", {"query": name}),        # сводка из открытых источников
        ("checko", "search", {"by": "name", "obj": "org", "query": name}),  # РФ ЕГРЮЛ (если RU)
        ("the-stall", "sanctions-screening", {"name": name, "type": "entity"}),  # санкции OFAC
    ]

# Предпочтительный порядок серверов на тип цели (curated сначала). Ограничивает
# веер, чтобы не звать каждый сервер и не плодить ошибки платных без ключа.
# Только быстрые и надёжные серверы через оркестратор (авто-режим). Медленные
# (dnstwist — фаззит тысячи доменов) и «капризные» (zoomeye 402, domscan WAF)
# остаются в РУЧНОМ режиме — их можно подключить в выпадашке MCP.
# ЛИН-режим: только БЫСТРЫЕ и НАДЁЖНЫЕ серверы на тип цели. Раньше веер шёл на
# все 22 сервера — на этом хосте (7.7 ГБ) это переполняло память, плодило
# docker-run-контейнеры и делало каждый запрос 60–110 с (investigate ждёт самый
# медленный источник). Теперь domain/ip/company/hash/phone/ticker/crypto — это
# чистые API-вызовы (~5–20 с). docker-run остаётся только у maigret (username/
# email). Остальные серверы доступны ВРУЧНУ в панели MCP (call_server).
PREFERRED: dict[str, list[str]] = {
    "username": ["maigret"],            # единственный источник; ~60с (docker run)
    "email": ["maigret", "openosint"],  # openosint(holehe) быстрый
    # domain/ip в авто-режиме идут ГЛУБОКИМ веером (deep_domain_steps/deep_ip_steps
    # в server.py). PREFERRED здесь — фолбэк на случай выключенного deep-режима.
    "domain": ["shodan", "virustotal", "directapi"],
    "ip": ["shodan", "virustotal", "directapi"],
    "url": ["virustotal"],
    "hash": ["virustotal"],
    "phone": ["contrastapi"],
    "inn": ["checko"],
    "company": ["checko", "directapi"],  # ЕГРЮЛ/ЕГРИП (RU) + GLEIF (глобальный реестр LEI)
    "ticker": ["stockscope", "the-stall"],  # оба API; the-stall даёт данные
    "crypto": ["twzrd"],                # Solana intel-score
    "query": ["datanexus", "bgpt"],     # быстрый общий поиск
}
