"""Определение типа цели и маршрутизация на серверы.

- detect_targets(task): вытаскивает цели (username/email/domain/ip/hash/inn/url/ticker).
- CURATED: проверенные рецепты (сервер+инструмент+аргументы) с известными схемами.
- Для остального — generic-путь в server.py (tools/list + эвристика/LLM).
"""
from __future__ import annotations

import base64
import russia_links
import re

# --- Регэкспы типов целей (порядок важен: специфичное раньше общего) ---
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(r"\bhttps?://[^\s]+", re.I)
RE_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
RE_INN = re.compile(r"\b\d{10}\b|\b\d{12}\b")
RE_CIK = re.compile(r"\bCIK[\s:#№=-]*(\d{1,10})\b", re.I)
RE_COMPANY_REGISTRATION = re.compile(r"\b(?:OC|SC|SO|NI|LP)\d{6,}\b", re.I)
RE_FI_BUSINESS_ID = re.compile(r"\b\d{7}-\d\b")
RE_EXPLICIT_COMPANY_TARGET = re.compile(
    r"(?im)(?:^|[.\n;])\s*(?:цель(?: расследования)?|целевая компания|"
    r"основная компания|target|primary company)\s*[:=—-]\s*([^\n;|]+)"
)


def country_hint(text: str) -> str:
    """Явно указанная страна важнее общего для СНГ обозначения «ООО».
    При нескольких странах не выбираем одну по порядку перечисления.
    """
    text = russia_links.target_context(text)
    # Названия доменов вроде bbg-russia.trade — это идентификаторы сайта,
    # а не заявление о стране регистрации компании.
    text = RE_URL.sub(" ", text or "")
    text = RE_EMAIL.sub(" ", text)
    text = RE_DOMAIN.sub(" ", text)
    patterns = {
        "UZ": r"\b(?:узбекистан\w*|узбекск\w*|uzbekistan|o.zbekiston|mchj)\b",
        "RU": r"\b(?:росси[яию]\w*|российск\w*|russia|рф)\b",
        "US": r"\b(?:сша|американск\w*|united states|usa)\b",
        "GB": r"\b(?:великобритани\w*|united kingdom)\b",
        "ES": r"\b(?:испанск\w*|испани[яию]|spain)\b",
        "FI": r"\b(?:финлянд\w*|финск\w*|finland|finnish|suomi|y[- ]tunnus)\b",
        "KZ": r"\b(?:казахстан\w*|казахск\w*|kazakhstan)\b",
        "BY": r"\b(?:беларус\w*|белорус\w*|belarus)\b",
        "KG": r"\b(?:кыргыз\w*|киргиз\w*|kyrgyzstan)\b",
        "UA": r"\b(?:украин\w*|ukraine)\b",
    }
    found = [code for code, pattern in patterns.items() if re.search(pattern, text or "", re.I)]
    return found[0] if len(found) == 1 else ""


def inn_values(text: str) -> list[str]:
    """Десятизначный CIK SEC не является российским ИНН."""
    return RE_INN.findall(RE_CIK.sub(" ", text or ""))


def company_registration_values(text: str) -> list[str]:
    """UK company/LLP numbers supplied in a task (e.g. OC401309)."""
    return list(dict.fromkeys(x.upper() for x in RE_COMPANY_REGISTRATION.findall(text or "")))


def fi_business_id_values(text: str) -> list[str]:
    """Finnish Business IDs are not Russian INNs or British registration numbers."""
    return list(dict.fromkeys(RE_FI_BUSINESS_ID.findall(text or "")))


def explicit_company_target(task: str) -> str | None:
    """Явная метка «Цель: …» важнее упоминаний кандидатов в пояснении.

    Иначе формулировка вроде «проверить Boston Brokerage Group и британское
    LLP OC401309» могла выбрать описательный хвост «британское LLP» как компанию.
    """
    text = russia_links.target_context(task or "")
    matches = list(RE_EXPLICIT_COMPANY_TARGET.finditer(text))
    if not matches:
        return None
    value = matches[-1].group(1).strip().rstrip(" \t\r\n.,;:!?—–-")
    return _clean_company(value)

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
# Международные правовые формы: «Indra Sistemas SA», «Siemens AG», «Apple Inc».
# Матчит: имя (≥1 слова с заглавной) + правовая форма в конце.
RE_INT_ORG = re.compile(
    r"\b([A-ZА-Я][a-zA-Zа-яёА-ЯЁ0-9\-\.&]{1,30}"
    r"(?:\s+[A-ZА-Яa-zа-яё0-9\-\.&]{1,30}){0,5})"
    r"\s+\b(S\.?A\.?U?\.?|S\.?L\.?U?\.?|GmbH(?:\s*&\s*Co\.?\s*K\.?G\.?)?|A\.?G\.?|"
    r"Plc\.?|Ltd\.?|Limited|Inc\.?|Incorporated|Corp\.?|Corporation|"
    r"N\.?V\.?|B\.?V\.?|AB|Oyj|Oy|ry|rf|S\.?R\.?L\.?|Sp\.?A\.?|SE|SAS|SARL|SAU|"
    r"S\.A\.\s*de\s*C\.V\.|LLC|L\.?L\.?C\.?|LLP|L\.?L\.?P\.?)\b",
    re.I
)

# Стоп-слова в «имени компании»: предлоги/служебные, которые ошибочно попадают в
# захват из фраз вроде «компанию ПО ИНН 7707083893» → бракованное имя.
# Стоп-слова: ведущие — пропускаются; терминирующие — обрывают захват.
_COMPANY_STOP = {"по", "с", "на", "об", "о", "из", "для", "к", "у", "при", "за",
                 "инн", "огрн", "огрнип", "кпп", "названию", "имени", "номеру"}
_COMPANY_TERM = {"сайт", "сайте", "site", "website", "домен", "domain", "url",
                 "адрес", "address", "телефон", "phone", "email", "почта", "cif", "nif",
                 "инн", "огрн", "кпп", "тикер", "ticker", "cik", "y-tunnus"}


def _clean_company(name: str) -> str | None:
    """Чистит захваченное имя компании: убирает ведущие предлоги/служебные слова
    и обрывает на длинном числе (ИНН/ОГРН — не часть названия) или терминирующем
    слове ('сайт', 'site', 'домен'). None, если после чистки ничего осмысленного
    не осталось (тогда это не имя компании)."""
    out: list[str] = []
    for tok in name.strip(" «»\"'").split():
        low = tok.lower().strip(".,:;")
        if re.fullmatch(r"\d{6,}", tok):          # длинное число = ИНН/ОГРН
            break
        if low in _COMPANY_TERM:                  # терминирующее слово
            break
        if not out and low in _COMPANY_STOP:
            continue                               # ведущие предлоги/служебные
        out.append(tok)
    cleaned = " ".join(out).strip(" «»\"'").rstrip(".,;:!?")
    cleaned = cleaned.replace("«", "").replace("»", "")
    return cleaned if len(cleaned) >= 2 and cleaned.lower() not in _ORG_SUFFIX else None

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
    task = russia_links.target_context(task.replace('(.)', '.').replace('[.]', '.'))
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
    for v in inn_values(task):
        add("inn", v)
    for v in RE_TICKER.findall(task):
        add("ticker", v)
    for v in RE_TICKER_KW.findall(task):
        add("ticker", v.upper())

    # Этикетка задачи — авторитетная цель; сначала добавляем её, чтобы
    # primary_company в investigate не схватил упомянутый рядом реестровый тип
    # или одноимённую компанию-кандидата.
    explicit_target = explicit_company_target(task)
    if explicit_target:
        add("company", explicit_target)

    # Компания по названию (ООО/ПАО/… или «компания X»). Чистим захват, чтобы
    # «компанию по ИНN 7707083893» не превращалось в компанию «по ИНН …».
    for rx in (RE_ORG, RE_COMPANY_KW):
        for v in rx.findall(task):
            name = _clean_company(v)
            if rx is RE_COMPANY_KW and name and re.match(
                    r'^(?:за\s+)?(?:этими?\s+домен|этими?\s+сайт|владельц|за\s+домен|по\s+домен|по\s+сайт|связанн|behind\b|owning\b)', name, re.I):
                continue
            if name:
                add("company", name)

    # Международные правовые формы: «Indra Sistemas SA», «Siemens AG», «Apple Inc».
    # Не берём строки, которые уже ушли в домены/URL (напр. «indracompany.com»).
    _already_domain = {x["value"].lower() for x in found if x["type"] in ("domain", "url")}
    for m in RE_INT_ORG.finditer(task):
        full = m.group(0).strip(" ,;.")
        if not any(ad in full.lower() for ad in _already_domain):
            name = _clean_company(full)
            if name and len(name.split()) >= 2:
                # Международный regex не должен захватывать русскую вводную фразу.
                if not any(x["type"] == "company" and full.lower().endswith(x["value"].lower()) for x in found):
                    add("company", name)

    # Явный username: "username X", "ник X", "@handle"
    m = re.search(r"(?:username|ник|никнейм|user)\s+@?([a-zA-Z0-9_.]{2,30})", task, re.I)
    if m:
        add("username", m.group(1))
    for m in re.finditer(r"(?<!\S)@([a-zA-Z0-9_.]{2,30})", task):
        add("username", m.group(1))

    # Голый токен без явного типа («Meta», «Siemens», «durov») неоднозначен:
    # это может быть ник ЛИБО бренд/компания. Раньше брали только username — и на
    # «Meta» (модель часто обрезает «компанию Meta» до «Meta») выходил пустой отчёт.
    # Теперь исследуем и как username, и как company: реестры (GLEIF/SEC) строго
    # матчатся, домен проверяется резолвингом — для бренда это даёт богатое досье,
    # для ника «компания»-путь просто вернёт пусто (username через maigret работает).
    if not found:
        for tok in RE_LATIN_TOKEN.findall(task):
            if tok.lower() in _STOPWORDS:
                continue
            add("username", tok)
            add("company", tok)
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
    "holding", "holdings", "spa", "srl", "bv", "nv", "oy", "oyj", "ry", "rf", "ab", "as", "pao",
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
    ("domain", "dnstwist"): ("fuzz_domain", lambda v: {"domain": v, "registered_only": True, "mxcheck": False, "banners": False, "threads": 30}),
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
    ("company", "opencorporates"): ("opencorporates_search", lambda v: {"query": v}),
    ("company", "companyscope"): ("lookup_company", lambda v: {"query": v}),
    # Деловые СМИ (Reuters/Bloomberg/RBC) — новости и события по компании.
    ("company", "googlesearch"): ("web_search", lambda v: {"query": v, "engine": "news"}),
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
    # Google CSE под тип цели: ник→люди, почта→паст-сайты(утечки), запрос→сайты/соц/gov.
    ("username", "directapi"): ("google_cse", lambda v: {"query": v, "engine": "people"}),
    ("email", "directapi"): ("google_cse", lambda v: {"query": v, "engine": "pastebin"}),
    ("query", "directapi"): ("google_cse", lambda v: {"query": v, "engine": "sites_social_gov"}),
    # yfinance для европейских/мировых бирж (IBEX35, LSE, XETRA, Euronext).
    ("ticker", "directapi"): ("stock_quote", lambda v: {"ticker": v}),
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
        ("whoisxml", "whois_history", {"domain": v}),              # история WHOIS (выделенный сервер)
        ("whoisxml", "whois_current", {"domain": v}),              # текущий WHOIS (фолбэк для rdap)
        ("censys", "censys_domain", {"domain": v}),                # Censys (ключ) — инфраструктура
        ("directapi", "web_inspect", {"domain": v}),               # web-check: заголовки/безопасность
        ("directapi", "google_cse", {"query": v, "engine": "pastebin"}),  # утечки с упоминанием домена
        # ---- дополнительные источники ----
        ("voidly", "get_domain_status", {"domain": v}),            # блокировки/репутация по странам
        ("voidly", "get_domain_history", {"domain": v}),           # история инцидентов домена
        ("dnstwist", "fuzz_domain", {"domain": v, "registered_only": True, "mxcheck": False, "banners": False, "threads": 30}),  # тайпсквоттинг
        ("openosint", "search_domain", {"domain": v}),             # OpenOSINT агрегация
        ("zoomeye", "zoomeye_search",                              # ZoomEye — хосты домена
         {"qbase64": __import__("base64").b64encode(f'hostname="{v}"'.encode()).decode()}),
        ("googlesearch", "web_search", {"query": v, "engine": "news"}),    # деловые новости
        ("googlesearch", "web_search", {"query": v, "engine": "leaks"}),   # утечки/базы данных
        ("googlesearch", "web_search", {"query": v, "engine": "social"}),  # соцсети
    ]
    # dns_records уже проверяет стандартные DKIM-селекторы одним вызовом.
    return steps


def deep_ip_steps(v: str, vt_rel_cap: int) -> list[tuple[str, str, dict]]:
    """Батарея вызовов для глубокого досье по IP."""
    steps: list[tuple[str, str, dict]] = [
        ("shodan", "ip_lookup", {"ip": v}),
        ("virustotal", "get_ip_report", {"ip": v}),
        ("directapi", "rdap_ip", {"ip": v}),                       # сеть/AS/организация
        ("censys", "censys_host", {"ip": v}),                      # Censys (ключ) — порты/сервисы
    ]
    for rel in ["resolutions", "communicating_files"][:max(0, vt_rel_cap)]:
        steps.append(("virustotal", "get_ip_relationship",
                      {"ip": v, "relationship": rel, "limit": 40}))
    return steps


RE_CYRILLIC = re.compile(r"[а-яёА-ЯЁ]")


def looks_russian(name: str, task: str = "", jurisdiction: str = "") -> bool:
    """Есть ли смысл спрашивать российский ЕГРЮЛ. Checko платный и по зарубежной
    компании гарантированно отдаёт пустой результат — раньше он всё равно уходил
    в каждый веер и просто раздувал знаменатель «ответили N из M»."""
    jurisdiction = jurisdiction or country_hint(task)
    if jurisdiction:
        return jurisdiction.upper().startswith("RU")
    if RE_CYRILLIC.search(name or ""):
        return True
    # In a Russia-links focus task, unrelated candidate INNs and a foreign
    # legal-form mention must not reclassify the primary target as Russian.
    if russia_links.requested(task):
        return False
    return bool(inn_values(task)) or bool(RE_ORG.search(task or ""))


def deep_company_steps(name: str, identity: dict | None = None, *,
                       task: str = "", allow_paid: bool = False) -> list[tuple[str, str, dict]]:
    """Батарея вызовов «корпоративного» слоя досье по компании (юр. идентичность,
    структура, отчётность, финансы, санкции). Инфраструктурный слой (домены →
    deep_domain_steps) добавляется отдельно в server.py. Серверы не из каталога
    пропускаются в build_plan.

    name — КАНОНИЧЕСКОЕ юр. имя из entity.resolve (не разговорная строка запроса):
    реестры сравнивают имена буквально, и «Meta» находила датскую однодневку.
    identity даёт точные ключи (LEI/CIK/тикер/юрисдикция) — по ним реестр отвечает
    однозначно, без сопоставления строк."""
    ident = identity or {}
    lei, tickers = ident.get("lei"), (ident.get("tickers") or [])
    jur = ident.get("jurisdiction") or country_hint(task)
    # Прим.: filingfirehose (SEC 8-K) НЕ включаем — его search_8k_filings отдаёт
    # свежие отчёты ПО РЫНКУ, а не по конкретной компании (был бы шум чужих эмитентов).
    steps: list[tuple[str, str, dict]] = [
        # LEI-код точнее имени: прямая карточка вместо сопоставления строк.
        ("directapi", "gleif_entity", {"query": lei or name}),
        ("directapi", "sec_edgar", {"query": ident.get("cik") or (tickers[0] if tickers else name)}),
        ("directapi", "wikipedia_summary", {"query": name}),
        # Один веб-поиск на слой, и по СУЩНОСТИ, а не по паст-сайтам: движок
        # pastebin рассчитан на почты/ники, а на имени-существительном («Meta»)
        # давал десять страниц чужих паст. Доменный pastebin-дорк остаётся —
        # он привязан к проверенному домену и потому точен.
        ("directapi", "google_cse", {"query": name, "engine": "docs_orgs"}),
        # opencorporates_officers здесь НЕ зовём: без юрисдикции одно и то же имя
        # ловит чужую регистрацию (INDRA SISTEMAS есть и в ES, и в ca_qc). Его
        # вызывает вторая волна в server.py — по ЮРИДИЧЕСКОМУ имени и стране.
        ("companyscope", "lookup_company", {"query": name}),
        # Деловые новости: последние события, смены руководства, сделки (Serper/Google).
        ("googlesearch", "web_search", {"query": name, "engine": "news"}),
        # Международные реестры — компании с операциями в Великобритании + утечки OCCRP.
        ("directapi", "uk_companies_house", {"query": lei or name}),
        ("directapi", "aleph_search", {"query": lei or name}),
    ]
    # Испанский реестр (BORME) — CIF, директора, апoderados.
    # libreborme.net временно недоступен (Cloudflare), добавляем gov-docs поиск как фолбэк.
    if jur.lower().startswith("es"):
        steps.insert(0, ("directapi", "borme_publications", {"query": name}))
        steps.append(("googlesearch", "web_search",
                      {"query": f"{name} Consejo Administración directivos BOE BORME",
                       "engine": "docs_orgs"}))
    # Финансы по годам (выручка/прибыль/активы) из XBRL SEC — keyless.
    # stockscope сюда НЕ ставим: он на каждый запрос (включая AAPL) отвечает
    # «No SEC data found … Only US public companies are supported», т.е. как
    # источник финансов не работает. Тикер/имя даёт фаза резолвинга.
    if tickers or ident.get("cik"):
        steps.append(("directapi", "sec_financials",
                      {"query": ident.get("cik") or (tickers[0] if tickers else name)}))
    # Глобальные котировки (yfinance) — для бирж вне SEC (IBEX35, LSE, XETRA и т.д.).
    if tickers:
        steps.append(("directapi", "stock_quote", {"ticker": tickers[0]}))
    elif jur:
        # Авто-поиск тикера для публичных компаний без известного тикера.
        # Биржевой суффикс по юрисдикции: ES→.MC, DE→.DE, FR→.PA, GB→.L и т.д.
        _EXCHANGE_SUFFIX = {"es": ".MC", "de": ".DE", "fr": ".PA", "gb": ".L",
                            "it": ".MI", "nl": ".AS", "ch": ".SW", "au": ".AX"}
        jur2 = jur.lower()[:2]
        if jur2 in _EXCHANGE_SUFFIX:
            steps.append(("directapi", "stock_ticker_lookup", {"query": name}))
    if jur == "UZ" and not ident.get("directory_verified"):
        steps.append(("directapi", "uz_company_records", {"query": name}))
    if jur.upper() == "FI" and not ident.get("official_registry_verified"):
        args = {"query": name}
        bids = fi_business_id_values(task)
        business_id = ident.get("business_id") or (bids[0] if len(bids) == 1 else None)
        if business_id:
            args["business_id"] = business_id
        steps.append(("directapi", "fi_company_records", args))
    if looks_russian(name, task, jur):
        inn = ident.get("inn")
        if inn:
            steps.append(("checko", "get_company", {"inn": inn}))
            steps.append(("checko", "get_finances", {"inn": inn}))
        else:
            steps.append(("checko", "search", {"by": "name", "obj": "org", "query": name}))
    # Национальные реестры относятся к выбранному юрлицу, не к одноимённым филиалам.
    if jur and not jur.upper().startswith("GB"):
        steps = [st for st in steps if st[1] != "uk_companies_house"]
    if jur and not jur.upper().startswith("US") and not ident.get("cik"):
        steps = [st for st in steps if st[1] not in ("sec_edgar", "sec_financials")]
    if allow_paid:
        # x402: почти всегда «нужна оплата». Без ключа это гарантированный сбой,
        # который портил и статистику покрытия, и раздел «Ограничения данных».
        steps.append(("the-stall", "sanctions-screening", {"name": name, "type": "entity"}))
    return steps

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
    "username": ["maigret", "directapi"],       # аккаунты (maigret) + люди (Google CSE)
    "email": ["maigret", "openosint", "directapi"],  # + паст-сайты/утечки (Google CSE)
    # domain/ip в авто-режиме идут ГЛУБОКИМ веером (deep_domain_steps/deep_ip_steps
    # в server.py). PREFERRED здесь — фолбэк на случай выключенного deep-режима.
    "domain": ["shodan", "virustotal", "directapi"],
    "ip": ["shodan", "virustotal", "directapi"],
    "url": ["virustotal"],
    "hash": ["virustotal"],
    "phone": ["contrastapi"],
    "inn": ["checko"],
    "company": ["checko", "directapi", "opencorporates", "googlesearch"],  # RU + GLEIF + реестр + новости
    "ticker": ["stockscope", "directapi", "the-stall"],  # US (SEC) + глобальный (yfinance) + x402
    "crypto": ["twzrd"],                # Solana intel-score
    "query": ["datanexus", "bgpt", "directapi"],  # общий поиск + Google CSE (сайты/соц/gov)
}
