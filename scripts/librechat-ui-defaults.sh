#!/bin/sh
# =============================================================================
# Дефолты UI LibreChat для этого стенда: тёмная тема + русский интерфейс.
#
# Почему так: LibreChat не умеет задавать тему/язык через librechat.yaml или env
# — это клиентские настройки, которые он держит в localStorage браузера
# (`color-theme`, `lang`). Поэтому мы вставляем в index.html крошечный скрипт,
# который ОДИН РАЗ на браузер проставляет значения по умолчанию.
#
# Важно: это дефолт, а не принуждение. Скрипт срабатывает один раз (маркер
# osint-ui-defaults-v5) и дальше не мешает пользователю переключать тему и язык
# в настройках — его выбор сохраняется.
#
# Переключатели — штатные, в самом LibreChat:
#   аватар слева внизу → Settings/Настройки → General/Общие → Theme + Language.
# Мы их не добавляем и не прячем, только задаём начальное значение.
#
# Патчим на старте контейнера (а не bind-mount'ом index.html), чтобы при
# обновлении образа LibreChat правка легла на новый index.html, а не сломала
# приложение ссылками на устаревшие хешированные ассеты.
# =============================================================================
set -e

INDEX=/app/client/dist/index.html
MARKER=osint-ui-defaults-v5

[ -f "$INDEX" ] || { echo "[ui-defaults] $INDEX не найден — пропускаю."; exit 0; }
grep -q "$MARKER" "$INDEX" && { echo "[ui-defaults] уже применено."; exit 0; }

# node гарантированно есть в образе LibreChat — используем его вместо sed/awk,
# чтобы не мучиться с экранированием кавычек и слешей внутри JS. Сам патчер
# пишем через heredoc в кавычках ('JS') — тогда shell ничего не подставляет и
# кавычки внутри JS остаются как есть.
cat > /tmp/ui-defaults-patch.js <<'JS'
const fs = require("fs");
const idx = process.argv[2];

// Скрипт в <head> страницы LibreChat. Только тема + язык. Подключение orchestrator по умолчанию делается ШТАТНО —
// полем modelSpec.mcpServers: ["orchestrator"] в librechat.yaml (LibreChat сам
// проставляет сервер в новый чат) + interface.defaultPinnedTools. Раньше здесь
// был localStorage-хак для выбора MCP — он не работал: применение пресета
// перетирало выбор пустым mcp, потому что mcpServers лежал не на том уровне.
//
// Тема хранится RAW-строкой ('dark'), а НЕ JSON ('"dark"') — приложение читает
// localStorage['color-theme'] и проверяет ∈ [light,dark,system]. Язык — JSON.
// Разовая миграция (маркер): применяется один раз на браузер, дальше выбор
// пользователя в Настройках сохраняется.
const snippet = `<script>/* osint-ui-defaults-v5 */(function(){try{` +
  `if(localStorage.getItem('osint-ui-defaults-v5'))return;` +
  `localStorage.setItem('osint-ui-defaults-v5','1');` +
  `localStorage.setItem('color-theme','dark');` +
  `localStorage.setItem('lang','"ru-RU"');` +
  `document.cookie='lang=ru-RU; path=/; max-age=31536000';` +
  `}catch(e){}})();<\/script>`;

let html = fs.readFileSync(idx, "utf8");
html = html.includes("</head>")
  ? html.replace("</head>", () => snippet + "</head>")
  : snippet + html;
fs.writeFileSync(idx, html);
JS

node /tmp/ui-defaults-patch.js "$INDEX"

echo "[ui-defaults] тёмная тема + русский UI выставлены по умолчанию."
