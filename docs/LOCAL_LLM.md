# Локальная модель через Ollama

Этот вариант запускает чат и сборку аналитического досье на собственной машине.
В репозитории подготовлен профиль **Qwen2.5 14B**: тег Ollama `qwen2.5:14b`,
имя модели в шлюзе `qwen2.5-14b`.

Сначала выполните общую подготовку из [README](../README.md): установите Docker
Engine и плагин Compose, Git и Python, получите проект, создайте виртуальное
окружение, установите зависимости генератора и подготовьте `.env` с внутренними
секретами. Команды ниже выполняются из корня репозитория с активированным `.venv`.

Ключи облачных моделей для этого профиля не нужны. `LITELLM_MASTER_KEY` нужен:
это внутренний ключ шлюза. Ключи платных OSINT-источников настраиваются отдельно;
реестры, поиск и сайты компаний по-прежнему требуют доступа в интернет.

## Подготовка NVIDIA GPU

Для GPU-варианта нужна видеокарта NVIDIA, установленный драйвер и NVIDIA Container
Toolkit. Ориентир для собственного стенда — RTX 4090 с 24 ГБ VRAM, 64 ГБ RAM
и NVMe SSD. Это пример конфигурации, а не измеренный бенчмарк или гарантия времени
генерации. Объём памяти зависит от модели, контекста и количества запросов.

Сначала установите драйвер для своей ОС и убедитесь, что `nvidia-smi` видит карту.
Toolkit устанавливается по [официальной инструкции NVIDIA](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html).
Для Ubuntu/Debian с уже установленным драйвером:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg2
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit nvidia-container-toolkit-base \
  libnvidia-container-tools libnvidia-container1
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
nvidia-smi
```

Последняя настройка включает NVIDIA runtime для Docker; перезапуск Docker влияет
на уже работающие контейнеры. Проброс GPU в Ollama описан также в
[документации Ollama для Docker](https://docs.ollama.com/docker).

## Запуск локального профиля

Используйте актуальный плагин Compose; для приведённых инструкций — 2.24.4 или
новее. Файл `docker-compose.local.yml` использует `!reset`, чтобы убрать
зависимость LiteLLM от облачного прокси. См. [правила объединения Compose-файлов](https://docs.docker.com/reference/compose-file/merge/).

```bash
source .venv/bin/activate
python generator/generate.py
docker build -t osint-mcp-base:latest servers/base

export COMPOSE_FILE=docker-compose.yml:docker-compose.mcp.yml:docker-compose.local.yml:docker-compose.gpu.yml
export COMPOSE_PROFILES=local-llm

docker compose config --quiet
docker compose up -d --build
```

Порядок файлов важен: локальные настройки применяются после базовой конфигурации
и сгенерированных MCP-сервисов, GPU добавляется последним. Локальный override
задаёт обе внутренние модели оркестратора и адрес Ollama, а профиль `local-llm`
включает контейнеры `ollama` и `ollama-init`.

В новой shell-сессии повторно установите `COMPOSE_FILE` и `COMPOSE_PROFILES`
перед любыми командами управления этим стендом. Команды `docker compose` далее
предполагают именно эти настройки. Скрипт `scripts/up.sh` использует базовые
Compose-файлы и сам не добавляет локальный и GPU-файлы.

При первом запуске `ollama-init` ждёт сервер Ollama и скачивает модель. Успешный
сервис завершается с кодом 0; постоянно оставаться в состоянии Running ему
не требуется.

```bash
docker compose logs -f ollama-init
docker compose ps -a ollama-init
docker compose exec ollama ollama list
```

В списке моделей должна быть `qwen2.5:14b`. Если скачивание прервалось,
повторите его после восстановления сети:

```bash
docker compose run --rm ollama-init
```

## Проверка модели и первый отчёт

```bash
docker compose ps
docker compose exec ollama nvidia-smi
docker compose exec -T orchestrator python - qwen2.5-14b < scripts/check_llm.py
docker compose exec ollama ollama ps
```

`scripts/check_llm.py` делает два коротких запроса: проверяет вызов инструмента
и JSON. Он не запускает расследование и не обращается к OSINT-источникам.
`ollama list` показывает скачанные модели; `ollama ps` показывает загруженные
модели, контекст и распределение между GPU и CPU. По ним проверяется фактическое
использование видеокарты. [Контекст и проверка исполнения в Ollama](https://docs.ollama.com/context-length).

Откройте http://localhost:3080, создайте учётную запись или войдите по инструкции
из [README](../README.md). В **новом чате** выберите **Local · OSINT Авто**
и убедитесь, что включён **OSINT Orchestrator**. Основной облачный пресет остаётся
в конфигурации UI, поэтому выбор Local для этого варианта обязателен.

```text
Собери подробное досье по Microsoft Corporation, США,
тикер MSFT, CIK 0000789019, официальный сайт microsoft.com.
Нужны реквизиты, структура и руководство, годовые финансы,
деятельность, проекты, инфраструктура домена и источники.
Сохрани HTML, Markdown и PDF.
```

Дождитесь ответа `investigate` и откройте ссылку на полный HTML. Список созданных
файлов доступен на http://localhost:8899. Порт Ollama в этой конфигурации
не публикуется на хост; другие контейнеры обращаются к `http://ollama:11434`.
Для удалённого браузера настройте `REPORTS_URL_BASE` по [README](../README.md).

Проверьте, что отчёт относится к нужному юридическому лицу, даты и валюты
не смешаны, ссылки ведут к источникам, а недоступные сведения обозначены.
Успешный ответ модели сам по себе не подтверждает качество досье.

## Настройки модели

Все роли локального профиля должны использовать согласованную модель:

| Роль | Настройка | Значение |
|---|---|---|
| Чат и вызов инструмента | Пресет `Local · OSINT Авто` | `qwen2.5-14b` |
| Заголовки чатов | `titleModel` локального endpoint | `qwen2.5-14b` |
| Маршрутизация | `ORCHESTRATOR_MODEL` | `qwen2.5-14b` |
| Аналитическое досье | `ORCHESTRATOR_REPORT_MODEL` | `qwen2.5-14b` |
| Модель Ollama | `litellm_params.model` | `ollama_chat/qwen2.5:14b` |

Локальный Compose задаёт контекст 32 768, один параллельный запрос, одну
загруженную модель и `OLLAMA_KEEP_ALIVE=30m`. Пресет чата ограничен контекстом
24 000, чтобы оставить место для ответа. Выбор модели только в UI не меняет
внутреннего писателя; в данном варианте его переключает локальный Compose-файл.

Увеличение контекста повышает расход памяти. Следите за фактической загрузкой
через `ollama ps`; большие наборы документов могут не поместиться в окно модели.

## Вариант без GPU

Оставьте локальный файл, но исключите GPU-файл:

```bash
export COMPOSE_FILE=docker-compose.yml:docker-compose.mcp.yml:docker-compose.local.yml
export COMPOSE_PROFILES=local-llm
docker compose config --quiet
docker compose up -d --build
```

Вычисления будут выполняться на CPU. Проверяйте скорость и таймауты на своих
запросах, прежде чем использовать этот вариант для регулярных больших отчётов.
Базовый профиль без локального override загружает небольшую `qwen2.5:1.5b`;
её достаточно для проверки связи, но это не проверка качества досье на 14B.

## Ollama уже установлена на хосте

Для Ollama вне Docker не добавляйте `docker-compose.local.yml` и GPU-файл.
На хосте загрузите `qwen2.5:14b` и настройте сервер Ollama на адрес, доступный
из Docker-сети. Укажите в `.env`:

```dotenv
OLLAMA_BASE_URL=http://host.docker.internal:11434
ORCHESTRATOR_MODEL=qwen2.5-14b
ORCHESTRATOR_REPORT_MODEL=qwen2.5-14b
```

LiteLLM уже содержит `host-gateway` для этого имени на Linux. Ollama, слушающая
только `127.0.0.1`, недоступна из контейнера: настройте `OLLAMA_HOST` и доступ
из Docker-сети в firewall. API Ollama должен быть доступен контейнерам,
а не всему интернету.

```bash
unset COMPOSE_FILE COMPOSE_PROFILES
docker compose -f docker-compose.yml -f docker-compose.mcp.yml up -d --no-deps litellm orchestrator
docker compose -f docker-compose.yml -f docker-compose.mcp.yml exec -T orchestrator \
  python - qwen2.5-14b < scripts/check_llm.py
```

В UI также выберите локальный пресет.

## Замена модели

Для замены нужна chat/instruct-модель с вызовами инструментов, русским языком,
JSON и контекстом, достаточным для источников. Согласуйте четыре настройки:

1. Тег загружаемой модели в `docker-compose.local.yml`.
2. Имя в шлюзе и маршрут `ollama_chat/<тег>` в `litellm/config.yaml`.
3. Модель, `titleModel` и локальный пресет в `generator/templates/librechat.yaml.j2`.
4. `ORCHESTRATOR_MODEL` и `ORCHESTRATOR_REPORT_MODEL` в локальном Compose-файле.

Запустите генератор и пересоздайте изменённые сервисы, затем проверьте новое имя
через `scripts/check_llm.py` и полноценный запрос из UI. Сгенерированные
`config/librechat.yaml`, `config/catalog.json` и `docker-compose.mcp.yml`
вручную не редактируются. Маршрут шлюза использует
[Ollama Chat в LiteLLM](https://docs.litellm.ai/docs/providers/ollama).

## Управление и диагностика

При установленных выше переменных окружения:

```bash
docker compose logs --tail=100 ollama litellm orchestrator
docker compose exec ollama ollama ps
docker compose down
```

`down` сохраняет тома базы и скачанные модели. `down -v` удаляет данные томов,
включая модели, и не подходит для обычной остановки.

| Симптом | Что проверить |
|---|---|
| Ошибка `!reset` при чтении YAML | Обновить плагин Compose и проверить порядок файлов |
| Ollama не запущена | Наличие `COMPOSE_PROFILES=local-llm` и состояние `ollama-init` |
| Модель не найдена | Дождаться загрузки; сверить `ollama list` и тег `qwen2.5:14b` |
| GPU не видна | Драйвер на хосте, NVIDIA Container Toolkit, подключённый GPU-файл |
| Ошибка соединения шлюза с Ollama | `OLLAMA_BASE_URL`, состояние контейнера, Docker-сеть |
| Чат работает, досье использует другую модель | Локальный Compose и обе внутренние модели оркестратора |
| Неполные данные об организации | Доступность источников и их ключей, ограничения страны и реестров |

Перед переходом обратно к облачному запуску уберите `COMPOSE_FILE` и
`COMPOSE_PROFILES`, остановите Ollama и используйте инструкции
из [README](../README.md). Изменения `.env` применяются пересозданием контейнеров,
а не одним `restart`.
