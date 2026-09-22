/* Патчи supergateway 3.4.3: per-user env и обработка поздних async-ответов.
 * Патч применяется при сборке и старте, идемпотентен; при смене upstream
 * неизвестный код отклоняется, а не молча остаётся без исправления.
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
const SEND = 'transport.send(jsonMsg);';
const SAFE_SEND = `// osint: async send can reject after the HTTP client disconnected.
                            Promise.resolve().then(() => transport.send(jsonMsg)).catch((error) => {
                                logger.error('Failed to send to disconnected MCP client', error);
                                // Failed initialization leaves no usable client session.
                                if (jsonMsg.id === req.body.id && req.body.method === 'initialize') {
                                    return transport.close();
                                }
                            }).catch((error) => logger.error('Failed to close MCP transport', error));`;
function patch(source) {
  if (!source.includes(TO)) {
    if (!source.includes(FROM)) throw new Error('spawn anchor not found');
    source = source.replace(FROM, TO);
  }
  if (!source.includes(SAFE_SEND)) {
    if (!source.includes(SEND)) throw new Error('transport.send anchor not found');
    source = source.replace(SEND, SAFE_SEND);
  }
  return source;
}
if (require.main === module) {
  const source = fs.readFileSync(FILE, 'utf8');
  const updated = patch(source);
  if (updated !== source) fs.writeFileSync(FILE, updated);
  console.log('supergateway env and async-error patches ready');
}
module.exports = {patch, SAFE_SEND};
