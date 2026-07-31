# OSINT MCP UI — единый интерфейс поверх OSINT MCP-серверов

Первая версия проекта из [`Проект_B_Архитектура.md`](Проект_B_Архитектура.md):
аналитику даётся **одно окно** (чат) для работы со всеми OSINT MCP-серверами из
[awesome-osint-mcp-servers](https://github.com/soxoj/awesome-osint-mcp-servers),
с управлением ключами, оркестрацией по нескольким серверам и сборкой отчёта.

Стоит на готовом MCP-нативном хосте **LibreChat**. Вся ценность — в упаковке
серверов (реестр + генератор), UX ключей и рецептах расследований.

**Особенность этой версии:** в качестве LLM-оркестратора доступен **GigaChat
(Sber)** — наряду с облачными (Claude/GPT) и локальными (Ollama) моделями. Все
идут через единый OpenAI-совместимый шлюз **LiteLLM**.

## Как это устроено

```
                 registry/servers.yaml        ← единый источник правды
                          │  generator/generate.py
             ┌────────────┼─────────────────┐
             ▼            ▼                  ▼
   config/librechat.yaml  docker-compose.mcp.yml  config/catalog.json
        (mcpServers)        (сервисы серверов)      (каталог для UI)

  Аналитик → LibreChat (агент + системный промпт с рецептами)
                 │ выбирает серверы по типу цели
                 ├── LLM → LiteLLM → GigaChat / Claude / GPT / Ollama
                 └── инструменты → MCP-серверы (SSE-контейнеры / remote HTTP)
                          │
                 единый отчёт {цель, находки, источники, уверенность}
```

- **Реестр** ([`registry/servers.yaml`](registry/servers.yaml)) — одна запись на
  сервер. Из него генерируются все конфиги. Добавить сервер = правка реестра +
  `python generator/generate.py`. Справочник полей: [registry/README.md](registry/README.md).
- **stdio-серверы** запускаются как отдельные контейнеры, обёрнутые
  `supergateway` (stdio → SSE); LibreChat ходит к ним по URL. **remote**-серверы
  подключаются по HTTP напрямую.
- **GigaChat** несовместим с OpenAI API (Sber OAuth, обновление токена,
  российский TLS). Его закрывает sidecar **gpt2giga** (официальный прокси Sber),
  отдающий OpenAI-совместимый `/v1`; **LiteLLM** видит его как обычный
  openai-провайдер и потому стартует даже когда серверы Sber недоступны.

## Быстрый старт

Требуется Docker + Docker Compose и Python 3.10+.

```bash
# 1. Ключи
cp .env.example .env
#   впишите как минимум GIGACHAT_CREDENTIALS и LITELLM_MASTER_KEY;
#   ключи платных серверов — по мере надобности.

# 2. Зависимости генератора
pip install -r generator/requirements.txt

# 3. Поднять всё (соберёт базовый образ, сгенерирует конфиги, запустит стек)
./scripts/up.sh
```

Откройте **http://localhost:3080**, зарегистрируйтесь, примите условия
использования. В шапке чата выберите **пресет** (это и есть выбор модели):

- **GigaChat · OSINT Авто** — по умолчанию; агент сам подбирает серверы и
  собирает досье (нужен только `GIGACHAT_CREDENTIALS`).
- **Claude · OSINT Авто** / **GPT · OSINT Авто** — то же, но на облачной модели
  (нужен ключ, см. [«Облачные модели»](#облачные-модели-claude--gpt)).
- **Local · OSINT Авто** — то же на локальной модели Ollama (см.
  [«Локальная модель»](#локальная-модель-ollama)).

Все пресеты — агентные (один на провайдера): модель видит только `orchestrator`,
он сам подбирает серверы. Хотите ручной подбор конкретных серверов — выберите
эндпоинт напрямую (напр. «GigaChat (Sber)») и добавьте серверы в панели MCP.

Остановить: `./scripts/down.sh` (или `--wipe` для удаления данных).

## Интерфейс: тёмная тема, русский язык и авто-подключение оркестратора

Стенд по умолчанию открывается **в тёмной теме, на русском языке и с уже
подключённым сервером `orchestrator`**. Всё это — клиентские настройки, которые
LibreChat держит в localStorage браузера (задать их через `librechat.yaml` или
env нельзя), поэтому дефолты проставляет маленький скрипт
[`scripts/librechat-ui-defaults.sh`](scripts/librechat-ui-defaults.sh),
вставляющий их в `index.html` на старте контейнера.

- **Тема и язык** — ставятся один раз на браузер. Это дефолт, а не принуждение:
  дальше меняйте их в настройках, ваш выбор сохранится.

  **Где переключить вручную** (кнопки штатные, мы их не добавляли и не прячем):
  аватар пользователя в левом нижнем углу → **Settings / Настройки** →
  вкладка **General / Общие** → выпадающие списки **Theme / Тема**
  (System · Dark · Light) и **Language / Язык**.

  > Если стенд открывался в этом браузере ДО обновления, старые значения могли
  > остаться: LibreChat сам записывает язык при первом заходе (cookie на год),
  > поэтому мягкий дефолт по нему не срабатывал. Разовая миграция (маркер `v4`)
  > перезаписывает тему и язык один раз — обновите страницу (Ctrl+F5).
- **`orchestrator` выбран по умолчанию в новом чате** — агентный режим работает
  сразу, без ручного подключения сервера. Скрипт **при каждой загрузке страницы**
  проставляет `orchestrator` в выбор нового чата (ключи `LAST_MCP_new` /
  `LAST_MCP___defaults__`) и включает «пин».

  Почему так: LibreChat **игнорирует** `preset.mcpServers` из `librechat.yaml`
  (поле относится к «агентам», а не к пресетам), а свой выбор серверов хранит в
  localStorage. Без этой подстраховки у модели нет инструментов — и слабая модель
  вместо вызова `investigate` выдумывает «отчёт» (так появлялись ссылки на
  несуществующий CDN). Именованные чаты (свой выбор серверов) скрипт не трогает.

  > ⚠️ **Ограничение.** Дефолт железно применяется на **загрузке/обновлении
  > страницы**. Кнопка «Новый чат» без перезагрузки (SPA) переиспользует уже
  > загруженное состояние, поэтому после первого захода дефолт уже в силе. Если
  > orchestrator вдруг не отмечен — обновите страницу (Ctrl+F5).

- **Пресет «GigaChat · OSINT Авто»** выбран по умолчанию штатным механизмом
  LibreChat: у него `default: true` в `modelSpecs`, а резолвер пресетов проверяет
  `default` раньше, чем «последний использованный». Отдельных костылей не нужно.

Патч накладывается при каждом старте контейнера, поэтому переживает обновление
образа LibreChat.

## Отчёты

Оркестратор кладёт каждый отчёт в `./reports` в двух форматах (`.md` и `.pdf`) и
отдаёт ссылки в чат. Все реально созданные отчёты всегда доступны списком:

**http://localhost:8899/** — индекс файлов (что действительно сгенерировано).

> ⚠️ **Проверяйте домен ссылки.** Слабые модели (в первую очередь GigaChat)
> иногда отвечают, *не вызвав инструмент*, и выдумывают правдоподобную ссылку на
> сторонний CDN (`cdn.jsdelivr.net`, `github.com`, …). Настоящие отчёты этого
> стенда лежат **только** на `http://localhost:8899/`. Если модель прислала
> другой домен — отчёта не существует, повторите запрос или откройте индекс
> выше. Системный промпт это запрещает, но гарантировать поведение модели он не
> может — на Claude/GPT такого практически не случается.

## Получить ключ GigaChat

1. [developers.sber.ru](https://developers.sber.ru/studio/workspaces) → **GigaChat API**.
2. Создайте проект, скопируйте **Authorization key** (base64).
3. Вставьте в `.env` → `GIGACHAT_CREDENTIALS`; `GIGACHAT_SCOPE` — `GIGACHAT_API_PERS`
   (физлица) или `GIGACHAT_API_B2B` (для юрлиц/корп).

**Проверка:** `curl -s localhost:4000/v1/chat/completions -H "Authorization: Bearer $LITELLM_MASTER_KEY"
-H 'Content-Type: application/json' -d '{"model":"GigaChat","messages":[{"role":"user","content":"привет"}]}'`

- Ответ модели — всё работает.
- `402 Payment Required` — ключ и подключение валидны, но на проекте GigaChat
  нет баланса/токенов: пополните в кабинете Sber.
- `401/403` — неверный `GIGACHAT_CREDENTIALS` или `GIGACHAT_SCOPE`.
- Таймаут/`000` — серверы Sber недоступны из вашей сети (георестрикция).

## Облачные модели (Claude / GPT)

Помимо GigaChat платформа умеет работать на **Claude (Anthropic)** и **GPT
(OpenAI)** — через тот же шлюз LiteLLM. Нужен только API-ключ:

1. Получите ключ:
   - **Anthropic** — [console.anthropic.com](https://console.anthropic.com/) →
     *API Keys* → создайте ключ `sk-ant-…`.
   - **OpenAI** — [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
     → создайте ключ `sk-…`.
2. Впишите в `.env`:
   ```dotenv
   ANTHROPIC_API_KEY=sk-ant-...
   OPENAI_API_KEY=sk-...
   ```
3. Перезапустите шлюз (ключи читаются при старте):
   `docker compose up -d --force-recreate litellm librechat`
4. В чате выберите пресет **Claude · OSINT Авто** или **GPT · OSINT Авто** —
   агентный режим работает так же, как на GigaChat. Или выберите эндпоинт
   **Cloud (Claude/GPT via LiteLLM)** и модель напрямую для обычного чата.

Доступные модели заданы в [`litellm/config.yaml`](litellm/config.yaml):
`claude-opus-4-8`, `claude-sonnet-5`, `gpt-4o`, `gpt-4o-mini`. Чтобы добавить
другую — впишите ещё один блок `model_name` (с префиксом `anthropic/` или
`openai/`) и перечислите её в эндпоинте `Cloud` в
[`generator/templates/librechat.yaml.j2`](generator/templates/librechat.yaml.j2),
затем `./scripts/regen.sh`.

**Проверка** (ключ должен быть задан): 
```bash
curl -s localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"claude-opus-4-8","messages":[{"role":"user","content":"ping"}]}'
```
Ответ модели — работает. `AuthenticationError`/`401` — ключ не задан или неверен.

Ключи можно не хранить у развёртывания, а дать каждому пользователю вводить свой —
но для LLM-моделей per-user vault не используется: `ANTHROPIC_API_KEY`/
`OPENAI_API_KEY` задаются один раз в `.env` (общие для стенда). Per-user ключи —
это про MCP-серверы (Shodan, VirusTotal и т.д.), см. форму ⚙ у сервера в панели MCP.

## Локальная модель (Ollama) — опционально

Можно работать **полностью локально**, без облака и без GigaChat, на модели через
[Ollama](https://ollama.com). Данные не покидают вашу машину.

**По умолчанию ВЫКЛЮЧЕНА.** На небольшом хосте (≈8 ГБ) модель отъедает память у
~20 OSINT-серверов и делает стенд нестабильным, поэтому Ollama вынесена в
compose-профиль `local-llm` и не поднимается сама. Эндпоинт **Local · OSINT Авто**
остаётся в UI (для деплоя на мощном хосте).

**Включить на мощном хосте** (in-stack Ollama + автозагрузка `qwen2.5:1.5b`):
```bash
docker compose --profile local-llm up -d ollama ollama-init
```
Затем в чате выберите пресет **Local · OSINT Авто**.

**Или своя Ollama на хосте** (вместо in-stack): задайте в `.env`
`OLLAMA_BASE_URL=http://host.docker.internal:11434` и перезапустите `litellm`.

**Проверка** связки LiteLLM → Ollama (когда Ollama поднята):
```bash
curl -s localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5","messages":[{"role":"user","content":"ping"}]}'
```
Ответ модели — работает. Пусто/ошибка — модель ещё качается (`docker logs
osint-ollama-init`) или сервис `ollama` не поднялся.

**Взять модель покрупнее** (на мощном хосте — GPU желателен):
```bash
docker exec osint-ollama ollama pull qwen2.5:7b     # или llama3.1, mistral …
```
затем добавьте её `model_name` (с `model: ollama_chat/<имя>`) в
[`litellm/config.yaml`](litellm/config.yaml) и в список эндпоинта `Local` в
[`generator/templates/librechat.yaml.j2`](generator/templates/librechat.yaml.j2)
→ `./scripts/regen.sh`.

**Своя Ollama на хосте** (вместо встроенной): задайте в `.env`
`OLLAMA_BASE_URL=http://host.docker.internal:11434` (на Linux это имя резолвится
благодаря `extra_hosts: host-gateway` у сервиса `litellm`) и `up -d litellm`.

**Замечания.** Локальные модели слабее в tool-calling — агентный пресет
рассчитан именно на это (виден только `orchestrator`, вся логика подбора и сборки
отчёта детерминированная/на стороне оркестратора). Оркестратор по умолчанию для
внутреннего LLM использует `ORCHESTRATOR_MODEL=GigaChat-2-Pro`; для полностью
офлайн-стенда поставьте туда имя локальной модели (напр.
`ORCHESTRATOR_MODEL=qwen2.5`).

## Каталог серверов

Полный список и статусы — в [`registry/servers.yaml`](registry/servers.yaml)
(и в сгенерированном `config/catalog.json`). Free/OSS-серверы работают сразу;
платные (Shodan, VirusTotal, ZoomEye, Checko, Bright Data и т.д.) молчат, пока
их ключ не задан в `.env` — это ожидаемое поведение выбранного объёма первой
версии.

Включить/выключить сервер — поле `enabled` в реестре, затем `./scripts/regen.sh`.

## Рецепты расследований

Заложены в системный промпт агента ([`config/system_prompt.md`](config/system_prompt.md)):
досье по username / домену / компании и проверка IOC. Агент сам маршрутизирует
цель на нужные серверы и собирает отчёт в единой схеме.

**Что можно спрашивать** (живые формулировки, что поддерживается, что нет,
какие запросы отклоняются) — [`docs/USER_SCENARIOS.md`](docs/USER_SCENARIOS.md).
Формулировать можно свободно: ключевые слова вроде «домен» или «username» не
обязательны — «проверь durov», «что за сайт vk.com», «проверь компанию Сбербанк»
распознаются сами.

## Что вне первой версии (бэклог, спец. §9)

Экспорт в PDF (пока Markdown), командные роли сверх дефолта LibreChat,
детерминированные тул-карточки (формы), авто-discovery серверов, TLS-фронт
(Caddy/nginx) — сейчас только localhost.

## Замечания по эксплуатации

- Точные шаги сборки некоторых серверов (неофициальные обёртки, CLI-пакеты)
  проверяются на онбординге (спец. §10) — Dockerfile'ы в `servers/<id>/`
  содержат пометки. При недоступности сервер помечается `enabled: false`.
- Добавление сервера через `librechat.yaml` требует рестарта хоста LibreChat.
- Rate-limit через Redis — опционально: `docker compose --profile ratelimit up -d`.
