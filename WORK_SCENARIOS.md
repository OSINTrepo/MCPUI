# Рабочие сценарии: полный прогон

Дамп всех проверенных сценариев работы с системой — что пользователь пишет,
как система это разбирает, куда маршрутизирует и что реально вернула.

Прогон выполнен **2026-07-20** на живом стенде (22 сервера, оркестратор
`investigate/plan/catalog/call_server`). Это не список намерений — все строки
ниже получены запуском, а не написаны «на глаз».

- Фаза A — 41 формулировка через `plan()` (разбор + маршрутизация, без запуска).
- Фаза B — 10 представительных сценариев через `investigate()` (сквозной цикл).
- Пользовательская (короткая, без результатов прогона) версия —
  [`docs/USER_SCENARIOS.md`](docs/USER_SCENARIOS.md).

---

## Итог

| Проверка | Результат |
|---|---|
| Доступность MCP-серверов | **21/22**, 685 инструментов (не отвечает только `domscan` — WAF) |
| Разбор формулировок (фаза A) | **41/41** обработаны корректно |
| Сквозные расследования (фаза B) | **10/10** успешно |
| Отчёты | все `.md` + `.pdf` созданы, HTTP 200, валидный PDF |
| Выдуманные ссылки | **0** |

До правок этого прогона 18 из 41 формулировок уходили в общий веб-поиск вместо
профильного источника (см. «Что было исправлено»).

---

## Фаза A — разбор формулировок

Формат: **вопрос пользователя** → распознанная цель → опрашиваемые источники.

### A. Username / человек в соцсетях

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь username durov | `username=durov` | Maigret, OpenOSINT |
| проверь durov | `username=durov` | Maigret, OpenOSINT |
| @durov | `username=durov` | Maigret, OpenOSINT |
| найди аккаунты пользователя durov в соцсетях | `username=durov` | Maigret, OpenOSINT |
| есть ли у durov профили в соцсетях? | `username=durov` | Maigret, OpenOSINT |
| кто такой durov | `username=durov` | Maigret, OpenOSINT |
| ник pavel_durov | `username=pavel_durov` | Maigret, OpenOSINT |

### B. Email

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь email test@example.com | `email=test@example.com` | OpenOSINT, Maigret |
| что известно про john.doe@gmail.com | `email=john.doe@gmail.com` | OpenOSINT, Maigret |
| пробей почту admin@company.ru | `email=admin@company.ru` | OpenOSINT, Maigret |

### C. Домен / сайт / URL

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь домен github.com | `domain=github.com` | Shodan, VirusTotal |
| собери досье на сайт example.com | `domain=example.com` | Shodan, VirusTotal |
| что за сайт vk.com | `domain=vk.com` | Shodan, VirusTotal |
| проверь https://example.com/page | `url=https://example.com/page` | VirusTotal |
| какие поддомены у github.com | `domain=github.com` | Shodan, VirusTotal |

### D. IP / инфраструктура

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь ip 8.8.8.8 | `ip=8.8.8.8` | Shodan, VirusTotal |
| что за адрес 1.1.1.1 | `ip=1.1.1.1` | Shodan, VirusTotal |
| какие порты открыты на 8.8.8.8 | `ip=8.8.8.8` | Shodan, VirusTotal |

### E. Компания / финансы

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь компанию по ИНН 7707083893 | `inn=7707083893` + `company` | Checko ×2, CompanyScope |
| проверь компанию Сбербанк | `company=Сбербанк` | Checko, CompanyScope |
| что известно о ООО Ромашка | `company=ООО Ромашка` | Checko, CompanyScope |
| проверь тикер AAPL | `ticker=AAPL` | StockScope, FilingFirehose |
| финансы компании Apple | `company=Apple` | Checko, CompanyScope |

### F. Угрозы / IOC

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь хеш 44d88612fea8a8f36de82e1278abb02f | `hash=44d88612…` | VirusTotal |
| это вирус? 44d88612fea8a8f36de82e1278abb02f | `hash=44d88612…` | VirusTotal |
| проверь ссылку на фишинг http://malware.example/x | `url=http://malware.example/x` | VirusTotal |

### G. Не поддерживается (нет ни одного сервера под такую цель)

| Вопрос | Ответ системы |
|---|---|
| проверь кошелёк 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | «Не поддерживается: криптокошельки» |
| проверь ФИО Иванов Иван Иванович | «Не поддерживается: поиск по ФИО» |

Осознанное решение: общий веб-поиск вернул бы правдоподобный, но бесполезный
отчёт и создал бы ложное впечатление проверки.

**Телефоны поддерживаются с 2026-07-20** — после включения ContrastAPI
(`phone_lookup`): страна, оператор, тип номера, таймзона. Владельца номера
открытые источники не раскрывают, и это не задача системы.

### H. Мета-вопросы

| Вопрос | Ответ системы |
|---|---|
| что ты умеешь? | каталог источников по категориям |
| какие источники подключены? | каталог источников по категориям |

### J. Составные цели

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь домен github.com и ip 8.8.8.8 | `domain=github.com`, `ip=8.8.8.8` | Shodan, VirusTotal, Shodan |
| досье: username durov, email test@example.com | `email=…`, `username=durov` | OpenOSINT, Maigret ×2 |

### K. Расплывчатые запросы

| Вопрос | Распознано | Источники |
|---|---|---|
| что известно про телеграм | `query` | DataNexus, BGPT, Not Human Search |
| помоги с расследованием | `query` | DataNexus, BGPT, Not Human Search |

Это корректное поведение: конкретной цели нет — идёт общий поиск.

### L. Этика — отказ

| Вопрос | Ответ системы |
|---|---|
| найди домашний адрес Иванова Ивана | отказ (деанон/доксинг) |
| как взломать аккаунт durov | отказ (взлом) |

Гейт стоит **в самом оркестраторе**, а не только в системном промпте: промпт
можно обойти или сменить модель, а этот отказ срабатывает всегда. Список
паттернов узкий — законный OSINT не блокируется.

### M. Край / негатив

| Вопрос | Распознано | Источники |
|---|---|---|
| проверь домен nonexistent-xyz-12345.xyz | `domain=nonexistent-xyz-12345.xyz` | Shodan, VirusTotal |
| asdkjhasdkjh | `username=asdkjhasdkjh` | Maigret, OpenOSINT |
| check domain github.com (англ.) | `domain=github.com` | Shodan, VirusTotal |
| проверь 8.8.8.8 8.8.4.4 1.1.1.1 | 3 × `ip` | Shodan, VirusTotal, Shodan |

---

## Фаза B — сквозные расследования

`investigate()` целиком: подбор источников → опрос → отчёт `.md` + `.pdf`.

| Вопрос пользователя | Время | Отчёт | Находки / внешние ссылки |
|---|---|---|---|
| проверь username durov | 59.8s | `username-durov-392256` | 2 / 16 |
| проверь durov | 53.4s | `durov-e22831` | 2 / 16 |
| что за сайт vk.com | 6.6s | `vk-com-9dae7a` | 2 / 0 |
| какие порты открыты на 8.8.8.8 | 6.1s | `8-8-8-8-f207d1` | 2 / 5 |
| что известно про john.doe@gmail.com | 11.4s | `john-doe-gmail-com-65a8dd` | 1 / 8 |
| проверь компанию Сбербанк | 5.5s | `report-d4ac69` | 1 / 0 |
| это вирус? 44d88612… | 6.8s | `44d88612…-c803d9` | 1 / 3 |
| проверь домен github.com и ip 8.8.8.8 | 10.5s | `github-com--ip-8-8-8-8-40459e` | 4 / 5 |
| проверь телефон +79001234567 | 3.5s | `79001234567-c66d62` | 1 / 0 (ContrastAPI) |
| check domain github.com | 10.1s | `check-domain-github-com-2fac6f` | 2 / 0 |

Все отчёты доступны по `http://localhost:8899/<имя>.md` / `.pdf`; список всех
созданных — http://localhost:8899/.

**Проверка содержимого** (`проверь компанию Сбербанк`): Checko вернул реальные
записи ЕГРЮЛ — ОГРН `1027739000728`, ИНН `7707009586`, «АО "СБЕРБАНК ЛИЗИНГ"»,
статус «Действует», юр. адрес. CompanyScope упал с `MCP error -32602`
(несовпадение схемы ответа сервера) — в отчёте честно указано «успешно опрошено
1 из 2».

---

## Примеры ответов системы

Всё ниже — **дословный вывод** оркестратора, снятый с живого стенда
(`tests/capture_answers.py`), а не пересказ. Именно этот текст видит пользователь
в чате.

### 1. Username — «проверь username durov»

```
✅ Досье по «проверь username durov» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/username-durov-986976.md) · [PDF](http://localhost:8899/username-durov-986976.pdf)

**Кратко:** ответили 2 из 2 источников; найдено ссылок/профилей: 111.

## Находки
- **Maigret** — 25 ссылок: [Bluesky](https://bsky.app/profile/durov.bsky.social), [Disqus](https://disqus.com/durov), [mastodon.social](https://mastodon.social/@durov), [Warpcast](https://warpcast.com/durov), [Minds](https://www.minds.com/durov), [Pikabu](https://pikabu.ru/@durov), [Myspace](https://myspace.com/durov), [Tumblr](https://www.tumblr.com/durov) … и ещё 17
- **OpenOSINT** — 86 ссылок: [9GAG](https://www.9gag.com/u/durov), [About.me](https://about.me/durov), [AllMyLinks](https://allmylinks.com/durov), [AniWorld](https://aniworld.to/user/profil/durov), [Anilist](https://anilist.co/user/durov/), [Aparat](https://www.aparat.com/durov/), [Atcoder](https://atcoder.jp/users/durov), [Audiojungle](https://audiojungle.net/user/durov) … и ещё 78

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 2. Домен — «что за сайт vk.com»

```
✅ Досье по «что за сайт vk.com» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/vk-com-b84f2d.md) · [PDF](http://localhost:8899/vk-com-b84f2d.pdf)

**Кратко:** ответили 2 из 2 источников; найдено ссылок/профилей: 0.

## Находки
- **VirusTotal**: 🌍 Domain Analysis Results Domain: vk.com 📅 Last Analysis Date: 7/20/2026, 5:13:11 AM 📊 Reputation Score: 11 Analysis Statistics: Detection Results: 🔴 Malicious: 0 (0.0%) ⚠️ Suspicious: 0 (0.0%) ✅ Clean: 58 (63.7%) ⚪ Unde
- **Shodan**: { "DNS Resolutions": [ { "Hostname": "vk.com", "IP Address": "87.240.132.78" } ], "Summary": { "Total Lookups": 1, "Queried Hostnames": [ "vk.com" ] } }

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 3. IP — «какие порты открыты на 8.8.8.8»

```
✅ Досье по «какие порты открыты на 8.8.8.8» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/8-8-8-8-3c612a.md) · [PDF](http://localhost:8899/8-8-8-8-3c612a.pdf)

**Кратко:** ответили 2 из 2 источников; найдено ссылок/профилей: 2.

## Находки
- **VirusTotal** — 2 ссылок: [ссылка](https://www.google.com/contact/), [ссылка](http://support.google.com/legal)
- **Shodan** — 3 ссылок: [ссылка](https://csp.withgoogle.com/csp/honest_dns/1_0;frame-ancestors), …

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 4. Компания по названию — «проверь компанию Сбербанк»

Обратите внимание: «ответили 1 из 2» — CompanyScope упал, и система об этом
честно сообщает, а не молчит.

```
✅ Досье по «проверь компанию Сбербанк» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/report-21ec95.md) · [PDF](http://localhost:8899/report-21ec95.pdf)

**Кратко:** ответили 1 из 2 источников; найдено ссылок/профилей: 0.

## Находки
- **Checko MCP**: { "data": { "ЗапВсего": 24, "СтрВсего": 1, "СтрТекущ": 1, "Записи": [ { "ОГРН": "1027739000728", "ИНН": "7707009586", "КПП": "503201001", "НаимСокр": "АО \"СБЕРБАНК ЛИЗИНГ\"", "НаимПолн": "АКЦИОНЕРНОЕ ОБЩЕСТВО \"СБЕРБАНК

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 5. Хеш / IOC — «это вирус? 44d88612fea8a8f36de82e1278abb02f»

```
✅ Досье по «это вирус? 44d88612fea8a8f36de82e1278abb02f» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/44d88612fea8a8f36de82e1278abb0-6d1a3f.md) · [PDF](http://localhost:8899/44d88612fea8a8f36de82e1278abb0-6d1a3f.pdf)

**Кратко:** ответили 1 из 1 источников; найдено ссылок/профилей: 3.

## Находки
- **VirusTotal** — 3 ссылок: [ссылка](https://github.com/advanced-threat-research/Yara-Rules), [ссылка](https://github.com/elastic/protections-artifacts), [ссылка](https://github.com/Neo23x0/signature-base)

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 6. Составная цель — «проверь домен github.com и ip 8.8.8.8»

Две цели → четыре опроса (по два источника на каждую).

```
✅ Досье по «проверь домен github.com и ip 8.8.8.8» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/github-com--ip-8-8-8-8-49898a.md) · [PDF](http://localhost:8899/github-com--ip-8-8-8-8-49898a.pdf)

**Кратко:** ответили 4 из 4 источников; найдено ссылок/профилей: 2.

## Находки
- **VirusTotal**: 🌍 Domain Analysis Results Domain: github.com 📅 Last Analysis Date: 7/20/2026, 12:00:02 AM 📊 Reputation Score: 121 …
- **VirusTotal** — 2 ссылок: [ссылка](https://www.google.com/contact/), [ссылка](http://support.google.com/legal)
- **Shodan**: { "DNS Resolutions": [ { "Hostname": "github.com", "IP Address": null } ], … }
- **Shodan** — 3 ссылок: …

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

### 7. Телефон — «проверь телефон +79001234567»

Работает после включения ContrastAPI: метаданные номера, без раскрытия владельца.

```
✅ Досье по «проверь телефон +79001234567» готово.

📄 **Полный отчёт:** [Markdown](http://localhost:8899/79001234567-c66d62.md) · [PDF](http://localhost:8899/79001234567-c66d62.pdf)

**Кратко:** ответили 1 из 1 источников; найдено ссылок/профилей: 0.

## Находки
- **ContrastAPI**: { "valid": true, "number": "+79001234567", "format": { "e164": "+79001234567", "international": "+7 900 123-45-67", "national": "8 (900) 123-45-67" }, "country_code": "RU", "country_name": "Russia", "type": "mobile", "carrier": "Tele2", ... }

_Полная детализация со всеми ссылками — в отчёте по ссылкам выше._
```

Для неподдерживаемых целей (криптокошелёк, ФИО) ответ остаётся честным отказом:

```
Не поддерживается: криптокошельки. В подключённом наборе источников нет ни одного
сервера для таких целей — искать по ним нечем. Доступные типы целей: username, email,
домен, IP, URL, хеш файла, компания/ИНН, тикер, телефон.
```

### 8. Отказ по этике — «как взломать аккаунт durov»

```
Отказ: запрос выходит за рамки законной OSINT-аналитики по открытым источникам
(взлом, преследование, поиск домашнего адреса/личных документов). Такие задачи здесь
не выполняются. Сформулируйте цель в рамках открытых данных — например, проверка
домена, компании, публичных профилей по username.
```

### 9. Мета-вопрос — «что ты умеешь?»

Каталог источников по категориям (фрагмент; всего 21 источник в 9 категориях):

```
Доступные источники:

[company]
  - Checko MCP: Проверка компаний и ИП РФ: ЕГРЮЛ/ЕГРИП, суды, госконтракты. Дай название или ИНН.
  - CompanyScope: Сводка о компании из открытых источников. Дай название компании.
  - FilingFirehose: Свежие отчёты компаний США в SEC (8-K/13D) и риски. Дай тикер или название.
  - StockScope: Финансы публичных компаний США из отчётности SEC. Дай тикер или название.

[network]
  - CrawlGraph: Кто ссылается на сайт (входящие ссылки), без сканирования цели. Дай домен.
  - DNSTwist: Ищет домены-двойники (тайпсквоттинг, фишинг). Дай домен.
  - DomScan: Разбор домена: DNS, WHOIS, SSL, поддомены, двойники, оценка. Дай домен.
  - Shodan: Разведка по IP и домену: открытые порты, сервисы, устройства, уязвимости (CVE). Дай IP или домен.
  - ZoomEye: Поиск устройств и сервисов в интернете по дорками. Дай IP, домен или запрос.

[socmint]
  - Maigret: Ищет аккаунты по нику или почте на 3000+ сайтах и в соцсетях. Дай username или email.

[threat]
  - OpenOSINT: Набор OSINT-проверок: почта, ник, домен, IP, утечки. Дай цель для проверки.
  - VirusTotal: Проверка файлов, ссылок, IP и доменов на угрозы. Дай хеш, URL, IP или домен.
  - Voidly: Блокировки и доступность сайтов в 119+ странах. Дай домен или URL.
  - VulneraMCP: Разведка и проверки уязвимостей веб-приложений (для авторизованного пентеста). Дай URL или домен.
```

### 10. План без запуска — «какие источники будешь использовать для github.com»

Инструмент `plan` показывает маршрутизацию, ничего не выполняя:

```
Цели: domain=github.com

Будут опрошены:
- Shodan ← domain:github.com
- VirusTotal ← domain:github.com
```

### 11. Прямой вызов конкретного источника (`call_server`)

Escape-hatch, когда нужен конкретный инструмент конкретного сервера:

```json
{
  "DNS Resolutions": [
    {
      "Hostname": "github.com",
      "IP Address": null
    }
  ],
  "Summary": {
    "Total Lookups": 1,
    "Queried Hostnames": ["github.com"]
  }
}
```

### 12. Как выглядит сам отчёт (файл по ссылке)

В чат приходит краткая сводка, вся детализация — в `.md`/`.pdf`. Начало
`username-durov-986976.md` (15 746 байт; PDF — 42 969 байт):

```markdown
# 🕵️ OSINT-досье

**Цель:** проверь username durov
**Дата:** 2026-07-20 08:43 UTC
**Источники:** Maigret, OpenOSINT
**Успешно опрошено:** 2 из 2

---

## Сводка

- **Maigret** — 25 ссылок
- **OpenOSINT** — 86 ссылок

---

## Подробности

### Maigret — `search_username` · ✅ успешно

**Найдено ссылок/профилей: 25**

- [Bluesky](https://bsky.app/profile/durov.bsky.social)
- [Disqus](https://disqus.com/durov)
- [mastodon.social](https://mastodon.social/@durov)
- [Warpcast](https://warpcast.com/durov)
- [Minds](https://www.minds.com/durov)
…
```

> Формулировки в чате может слегка перефразировать сама LLM — она получает этот
> текст и показывает его пользователю. Ссылки и цифры при этом переписывать
> запрещено системным промптом (см. README → «Отчёты»).

---

## Что было исправлено по итогам прогона

Прогон живыми формулировками (а не «чистыми» запросами) вскрыл три мёртвых пути:

| Проблема | Было | Стало |
|---|---|---|
| **Голый ник** — `RE_USERNAME` объявлен, но никогда не вызывался | «проверь durov», «кто такой durov» → общий веб-поиск | → Maigret + OpenOSINT |
| **Компания по названию** — тип `company` есть в рецептах и маршрутизации, но `detect_targets` его никогда не возвращал (6 серверов недостижимы) | «проверь компанию Сбербанк» → общий веб-поиск | → Checko + CompanyScope, реальные данные ЕГРЮЛ |
| **Тикер** — `RE_TICKER` требовал префикс `$` | «проверь тикер AAPL» → общий веб-поиск | → StockScope + FilingFirehose |
| **Телефон / крипта / ФИО** — серверов нет, но выполнялся общий поиск | правдоподобный, но бесполезный отчёт | честное «не поддерживается» |
| **Этика** — гейта в оркестраторе не было | «как взломать аккаунт durov» после правки ника стал бы запускать Maigret | отказ на уровне оркестратора |

Итог: **18 пробелов → 4**, и все 4 оставшихся — корректное поведение
(расплывчатые запросы действительно должны идти в общий поиск).

---

## Известные ограничения

- **`domscan`** не отвечает (WAF на стороне сервиса) — 21/22 сервера.
- **CompanyScope** `lookup_company` возвращает `MCP error -32602` (схема ответа).
  Дефект самого сервера; Checko по той же цели работает.
- **Платные источники молчат без ключа** (Shodan, VirusTotal, Checko, ZoomEye,
  Bright Data). Ключ вводится в UI: ⚙ у сервера в панели MCP.
- **Мусорный ввод** трактуется как username — для OSINT разумная догадка, но
  результат будет пустым.
- **Слой чат-модели не покрыт этим прогоном.** Здесь проверен движок
  (оркестратор). Насколько надёжно сама LLM *вызывает* `investigate` — зависит
  от модели: GigaChat иногда отвечает без вызова инструмента (см. README →
  «Отчёты»), Claude/GPT — практически всегда вызывают.

---

## Как перепроверить

Скрипты прогона лежат в [`tests/`](tests/) и запускаются внутри контейнера
оркестратора (он на сети `osint_net` и видит все серверы):

```bash
# закинуть скрипты в контейнер
docker cp tests/user_scenarios.py  osint_mcp_ui-orchestrator-1:/tmp/
docker cp tests/scenario_test.py   osint_mcp_ui-orchestrator-1:/tmp/
docker cp tests/capture_answers.py osint_mcp_ui-orchestrator-1:/tmp/

# матрица разбора формулировок (быстро, ~1 мин)
docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/user_scenarios.py a

# сквозной прогон investigate() (медленно, ~3 мин)
docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/user_scenarios.py b

# доступность всех MCP-серверов + поверхность оркестратора
docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/scenario_test.py health
docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/scenario_test.py tools

# пересобрать раздел «Примеры ответов» (дословный вывод системы)
docker exec osint_mcp_ui-orchestrator-1 python3 /tmp/capture_answers.py > answers.txt
```

> ⚠️ Не пропускайте вывод через `head`/`less` в конвейере: при выходе пейджера
> процесс получает SIGPIPE и последние кейсы не отрабатывают. Пишите в файл.

Свои сценарии добавляются в список `SCENARIOS` в
[`tests/user_scenarios.py`](tests/user_scenarios.py).
