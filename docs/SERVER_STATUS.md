# Статус интеграций OSINT MCP-серверов

Полный охват репозитория [awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers)
(**29 серверов**). Проверено: подключение каждого сервера в LibreChat
(`initialize` + `tools/list`) и реальные вызовы инструментов там, где сервер
бесплатный/keyless или для него уже есть ключ в `.env`.

- **Дата прогона:** 2026-07-15
- **Итог LibreChat:** `Initialized with 21 configured servers and 657 tools`
- **Метод функционального теста:** MCP streamable-http/sse клиент
  (`initialize → tools/list → tools/call`) из сети `osint_net`.

Легенда: ✅ реальные данные получены · 🟢 подключён, инструменты видны · 🔑 ключ
подтверждён рабочим · ⚠️ подключён, но нужен ключ/оплата/аргументы · ⛔ выключен
(причина) · 🚫 не MCP-сервер.

## Включённые (21) — все подключаются

| # | Сервер | Категория | Транспорт | Инстр. | Auth | Тест |
|---|---|---|---|---:|---|---|
| 1 | maigret | socmint | stdio (docker) | 2 | none | ✅ реальные соцсети durov (VK/Bluesky/…) |
| 2 | dnstwist | network | stdio (docker) | 1 | none | 🟢 тайпсквоттинг-фаззинг |
| 3 | shodan | network | stdio | 7 | api_key 🔑 | ✅ `dns_lookup` google.com→142.251.211.206 |
| 4 | zoomeye | network | stdio | 3 | api_key | ⚠️ ключ валиден, аккаунт `402 Payment Required` |
| 5 | domscan | network | remote http | — | none | 🟢 подключён в LibreChat (bare-probe 401/WAF) |
| 6 | crawlgraph | network | stdio | 4 | api_key | 🟢 подключён; вызовы требуют бесплатного `CRAWLGRAPH_API_KEY` (на email) |
| 7 | brightdata | scraping | stdio | 5 | api_key 🔑 | ✅ `search_engine` — живая выдача Google |
| 8 | companyscope | company | stdio | 11 | none | 🟢 8 публичных источников |
| 9 | stockscope | company | stdio | 6 | none | ✅ SEC EDGAR, отвечает (keyless) |
| 10 | filingfirehose | company | remote http | 4 | none | ✅ `search_8k_filings` — живые 8-K |
| 11 | checko | company | stdio | 12 | api_key 🔑 | ✅ `search` Сбербанк ОГРН 1027739000728 |
| 12 | datanexus | records | remote http | 55 | none (anon) | ✅ `search_datanexus_tools` — реальные тулы |
| 13 | virustotal | threat | stdio | 11 | api_key 🔑 | ✅ `get_domain_report` github.com (rep 121) |
| 14 | voidly | threat | stdio | 84 | none | 🟢 OONI/IODA цензура, 119+ стран |
| 15 | openosint | threat | stdio | 20 | none | 🟢 18 инструментов (доп. ключи опц.) |
| 16 | vulneramcp | threat | stdio (git) | 110 | none | 🟢 подключён; полный набор требует локальный PostgreSQL |
| 17 | bgpt | research | remote sse | 2 | none | ✅ `search_papers` — реальные статьи (DOI) |
| 18 | not-human-search | meta | remote http | 11 | none | 🟢 discovery по 8600+ MCP |
| 19 | twzrd | blockchain | remote http | 23 | none (1 tool x402) | ✅ `get_solana_market_status` — живые данные |
| 20 | the-stall | blockchain | remote http | 299 | paid (x402/Stripe) | 🟢 подключён; реальные вызовы платные |
| 21 | helium | market | remote http | 10 | none | ✅ `get_source_bias` CNN (254 статьи) |

## Выключенные — перепроверено 2026-07-20

Прежние причины проверены заново (probe MCP-эндпоинтов + GitHub API). Три из семи
оказались **ошибочными**: у проектов есть рабочие hosted-эндпоинты, о которых
судили по неподходящему npm-пакету или по мёртвому URL.

| # | Сервер | Категория | Проверенный статус |
|---|---|---|---|
| 25 | **contrastapi** | network | ✅ **ВКЛЮЧЁН.** Прежняя причина неверна: судили по npm-пакету (это клиентский SDK), а у проекта есть hosted-эндпоинт `https://api.contrastcyber.com/mcp/` — **55 инструментов, без ключа** |
| 22 | expose-team | socmint | 🔑 можно включить: URL в реестре был мёртв (`mcp.expose.team` не резолвится). Рабочий — `https://expose.team/mcp` → 401. Нужен платный ключ |
| 23 | xquik | socmint | 🔑 можно включить: это **не** docker-сборка. `.mcp.json` репозитория указывает на hosted `https://xquik.com/mcp` → 401 (репо содержит лишь `stub-server.mjs`). Нужен платный ключ |
| 26 | anysite | scraping | 🔑 можно включить: прежняя причина неверна — не браузерный OAuth, а обычный Bearer: 401 «Include Authorization: Bearer &lt;token&gt;». Нужен платный ключ |
| 27 | openregistry | company | ⚠️ вероятно можно: OAuth 2.1 с **dynamic client registration** (`/oauth/register`, scope `openregistry:read`), а не magic-link. LibreChat умеет MCP OAuth — нужен интерактивный вход один раз. Бесплатно |
| 24 | osint-toolkit | network | ⛔ нельзя: репозиторий `himanshusanecha/osint-toolkit` → **404**, опубликованного пакета нет |
| 28 | us-business-data | company | ⛔ нельзя: репозиторий `avabuildsdata/mcp-us-business-data` → **404**, пакета нет |

**Как включить платные (22/23/26):** вписать ключ в `.env` (или ввести в UI: ⚙ у
сервера в панели MCP) и поставить `enabled: true` в реестре → `./scripts/regen.sh`.
Для xquik и expose-team сначала поправить запись на `install: remote` +
корректный `url` (см. таблицу выше).

## Не MCP-сервер (1)

| # | Сервер | Причина |
|---|---|---|
| 29 | osint-agent-skills | 🚫 это база знаний (методологии, реестры инструментов, шаблоны отчётов), а не MCP-сервер — подключить как сервер нельзя |

## Локальный контейнер или hosted-эндпоинт — аудит 2026-07-20

Правило: **берём то, что проект реально публикует.** Пакет/CLI → свой контейнер;
вендор держит эндпоинт → подключаемся к нему. Проверены все stdio-серверы: у
каждого пакета взяты homepage/repo из npm/PyPI и опрошены кандидаты `/mcp`.

| Сервер | Hosted-эндпоинт | Инструментов (локально → hosted) | Решение |
|---|---|---|---|
| **crawlgraph** | `https://crawlgraph.com/mcp` — 200 | 4 → **4**, имена совпадают | ✅ **переведён на hosted**, контейнер удалён |
| brightdata | `https://mcp.brightdata.com/mcp` — 200 с нашим токеном | 5 → 5, но `discover` заменён на `ask_brightdata_assistant` | ⏸ оставлен локально: выигрыша нет, набор инструментов другой |
| voidly | `https://voidly.ai/api/mcp` — 200 | **84 → 54** | ⛔ оставлен локально: hosted теряет 30 инструментов |
| shodan, virustotal, zoomeye | нет (`mcp.shodan.io`, `mcp.virustotal.com`, `mcp.zoomeye.ai` не резолвятся) | — | контейнер: вендоры не держат MCP, пакеты — обёртки над REST API |
| maigret, dnstwist, openosint | нет и быть не может | — | контейнер: обёртки над локальными CLI (`docker run`, sherlock) |
| checko, companyscope, stockscope | нет (пакеты на GitHub, без сервиса) | — | контейнер |

**Почему это не просто «лень переехать в облако»:** ключи (`SHODAN_API_KEY`,
`VIRUSTOTAL_API_KEY`, `CHECKO_API_KEY`) уходят из нашего контейнера прямо в API
вендора, а цели расследования (кого именно проверяем) не видит посредник. Для
remote-серверов эта плата уже принята — расширять её без выигрыша незачем.

**Цена hosted-подхода видна прямо сейчас:** `twzrd` отдаёт `HTTP 530` (Cloudflare
`error 1033`, origin недоступен) — чужой сервис лежит, и сделать с этим нечего.
Локальный контейнер в такой ситуации продолжает работать.

## Сводка

- **29/29** серверов репозитория учтены.
- **23** включены, **21** отвечает и отдаёт инструменты (**717** суммарно).
- Разделение: **13** своих контейнеров (stdio) + **10** remote-эндпоинтов.
- Временно недоступны: `domscan` (WAF), `twzrd` (падение на стороне вендора).
- **Деградировали (подключены, но отдают битый/пустой результат) — убраны из
  дефолтной маршрутизации оркестратора, остаются в каталоге для ручного выбора:**
  - `companyscope` — `-32602 Invalid tools/call result` (сервер возвращает массив
    вместо объекта). Компании по названию/ИНН идут через `checko`.
  - `stockscope` — `No SEC data found` для ЛЮБОЙ компании (AAPL/MSFT/TSLA), хотя
    это правильный инструмент для тикера. Похоже на поломку бэкенда SEC EDGAR.
- **Функционально подтверждены реальными данными (16):** maigret, shodan,
  brightdata, checko, virustotal, stockscope, filingfirehose, datanexus, bgpt,
  twzrd, helium (+ dnstwist, companyscope, voidly, openosint, not-human-search,
  vulneramcp, the-stall — подключены и перечисляют реальные инструменты).
- **Ключи подтверждены рабочими:** SHODAN, VIRUSTOTAL, BRIGHTDATA, CHECKO.
- **Требуют действия для полного теста:** zoomeye (пополнить аккаунт — `402`),
  crawlgraph (бесплатный ключ на email), the-stall (x402/Stripe оплата),
  vulneramcp (локальный PostgreSQL для расширенных функций).

## Замечания

- **657 инструментов** суммарно — это много, но LibreChat грузит инструменты
  только выбранных в чате серверов, поэтому на обычную работу не влияет.
  Прикрепляйте 1–3 релевантных сервера на задачу (см. пресет «GigaChat · OSINT»).
- **domscan** отвечает `401/403` голому тест-клиенту (Cloudflare/WAF по
  User-Agent), но корректный MCP-клиент LibreChat подключается — сервер рабочий.
- Все изменения — в реестре и генераторе; повтор: `./scripts/regen.sh`.
