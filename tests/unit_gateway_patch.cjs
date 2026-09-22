const assert = require('node:assert/strict');
const vm = require('node:vm');
const {patch, SAFE_SEND} = require('../servers/base/patch_supergateway.js');
(async () => {
  const original = 'const child = spawn(stdioCmd, { shell: true });\ntransport.send(jsonMsg);';
  const updated = patch(original);
  assert.equal(patch(updated), updated);
  assert.ok(updated.includes("req.headers['x-mcp-env']"));
  assert.throws(() => patch('unknown upstream'), /anchor/);
  let closed = 0;
  let errors = 0;
  let unhandled = 0;
  const handler = () => { unhandled++; };
  process.on('unhandledRejection', handler);
  const context = {Promise, req: {body: {id: 1, method: 'initialize'}}, jsonMsg: {id: 1},
    logger: {error: () => errors++},
    transport: {send: async () => {throw Error('No connection established');}, close: async () => {closed++;}}};
  vm.runInNewContext(SAFE_SEND, context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(unhandled, 0);
  assert.equal(errors, 1);
  assert.equal(closed, 1);
  context.jsonMsg = {id: 2};
  vm.runInNewContext(SAFE_SEND, context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(closed, 1, 'Cancelled ordinary request must not close other requests in the session');
  process.off('unhandledRejection', handler);
  console.log('Gateway: late async failure handled, failed initialization closed, active sessions retained, patch idempotent.');
})().catch(error => {console.error(error); process.exitCode = 1;});
