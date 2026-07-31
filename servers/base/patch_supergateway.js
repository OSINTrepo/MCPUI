/*
 * Патч supergateway 3.4.3: пробрасывает per-user ключ из заголовка X-Mcp-Env
 * в окружение дочернего stdio-процесса.
 *
 * LibreChat подставляет customUserVars в заголовок вида
 *   X-Mcp-Env: "SHODAN_API_KEY={{SHODAN_API_KEY}}"
 * и шлёт его на инициализацию сессии. Мы парсим NAME=VALUE и кладём в env
 * ребёнка. Пустые значения и неподставленные плейсхолдеры {{...}} пропускаем —
 * тогда остаётся значение из .env контейнера (общий фолбэк).
 */
const fs = require('fs');

const FILE = '/usr/local/lib/node_modules/supergateway/dist/gateways/stdioToStatefulStreamableHttp.js';
const FROM = 'const child = spawn(stdioCmd, { shell: true });';
const TO =
  "const child = spawn(stdioCmd, { shell: true, env: (() => { " +
  "const e = { ...process.env }; const raw = req.headers['x-mcp-env']; " +
  "if (raw) { String(raw).split(/[\\n;]+/).forEach((p) => { " +
  "const i = p.indexOf('='); if (i > 0) { const k = p.slice(0, i).trim(); " +
  "const v = p.slice(i + 1); if (v && !/\\{\\{.*\\}\\}/.test(v)) e[k] = v; } }); } " +
  "return e; })() });";

let src = fs.readFileSync(FILE, 'utf8');
if (src.includes(TO)) {
  console.log('supergateway already patched');
  process.exit(0);
}
if (!src.includes(FROM)) {
  console.error('PATCH ERROR: anchor not found in ' + FILE);
  process.exit(1);
}
fs.writeFileSync(FILE, src.replace(FROM, TO));
console.log('supergateway env-injection patch applied');
