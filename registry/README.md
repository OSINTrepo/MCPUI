# Реестр серверов — справочник по полям

`servers.yaml` — единственный источник правды о подключённых MCP-серверах
(спец. §3). После любой правки запусти генератор:

```bash
python generator/generate.py
```

Он пересоберёт `config/librechat.yaml` (блок `mcpServers`),
`docker-compose.mcp.yml` и `config/catalog.json`.

## Запись сервера

| Поле | Обяз. | Значения | Назначение |
|---|---|---|---|
| `id` | да | kebab-case | Уникальный идентификатор. Имя сервиса compose и ключа mcpServers |
| `category` | да | `socmint` `network` `scraping` `company` `threat` `meta` | Группа в каталоге |
| `display_name` | да | строка | Отображаемое имя в UI |
| `description` | да | строка | Короткое описание |
| `transport` | да | `stdio` `http` `sse` | Как LibreChat говорит с сервером |
| `install` | да | `docker` `npx` `uvx` `pip` `remote` | Способ поставки |
| `build` | для docker | путь | Контекст сборки (`servers/<id>/Dockerfile`) |
| `stdio_command` | для stdio | строка | Команда запуска сервера ВНУТРИ контейнера; её оборачивает supergateway в SSE |
| `url` | для remote | URL | Адрес удалённого HTTP/SSE MCP-сервера |
| `auth.type` | да | `none` `api_key` `oauth` | Тип авторизации |
| `auth.user_var` | да | ИМЯ или `null` | Имя переменной ключа в `.env` и per-user vault LibreChat |
| `auth.env_var` | нет | ИМЯ | Имя переменной, которую читает сам сервер в контейнере (если отличается от `user_var`; напр. Bright Data ждёт `API_TOKEN`). По умолчанию = `user_var` |
| `cost_tier` | да | `free` `freemium` `paid` | Бейдж стоимости в каталоге |
| `inputs` | да | список | Типы целей: `username email domain ip company inn ticker hash url query` |
| `repo` | нет | URL | Ссылка на источник |
| `enabled` | да | `true`/`false` | Попадает ли в сгенерированные конфиги |

## Как это разворачивается

- **`transport: stdio`** → сервис в `docker-compose.mcp.yml`, собранный из
  `build:`; `stdio_command` оборачивается `supergateway` и публикуется как SSE на
  `sse_port` (по умолчанию 8000). В `librechat.yaml` попадает запись
  `type: sse`, `url: http://<id>:<port>/sse`.
- **`transport: http`/`install: remote`** → контейнер не создаётся; в
  `librechat.yaml` попадает запись `type: streamable-http`, `url: <url>`.
- **`enabled: false`** → сервер полностью исключается из генерации.

Ключи (`auth.user_var`) прокидываются в контейнер сервера как переменные
окружения из `.env`. Платный сервер стартует, но не отвечает, пока его ключ
не задан — это ожидаемо (см. выбранный scope в плане).
