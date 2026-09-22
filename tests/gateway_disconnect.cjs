// Реальная регрессия: клиент ушёл до initialize-ответа, gateway должен выжить.
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = '/tmp/slow-mcp-fixture.cjs';
fs.writeFileSync(path, `require('node:readline').createInterface({input:process.stdin}).on('line', line => {
 const m=JSON.parse(line); if(m.method==='initialize') setTimeout(() => console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2025-03-26',capabilities:{tools:{}},serverInfo:{name:'slow-fixture',version:'1'}}})),800);
});`);
(async()=>{
 const gateway=spawn('supergateway',['--stdio','node '+path,'--outputTransport','streamableHttp','--stateful','--port','18991','--streamableHttpPath','/mcp','--healthEndpoint','/healthz']);
 let logs=''; gateway.stdout.on('data',b=>logs+=b);gateway.stderr.on('data',b=>logs+=b);
 try {
  let ready=false;
  for(let i=0;i<100;i++) {try {if((await fetch('http://127.0.0.1:18991/healthz')).ok){ready=true;break;}}catch{} await new Promise(r=>setTimeout(r,50));}
  assert.ok(ready,'Gateway startup');
  const controller=new AbortController();setTimeout(()=>controller.abort(),150);
  await fetch('http://127.0.0.1:18991/mcp',{method:'POST',signal:controller.signal,headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'1'}}})}).catch(e=>{assert.equal(e.name,'AbortError');});
  await new Promise(r=>setTimeout(r,1200));
  assert.equal(gateway.exitCode,null,'Gateway crashed after delayed response: '+logs);
  assert.equal((await fetch('http://127.0.0.1:18991/healthz')).status,200);
  assert.ok(logs.includes('Failed to send to disconnected MCP client'),'Delayed response rejection was exercised');
  console.log('PASS: actual supergateway survives client abort followed by delayed initialize response.');
 }finally{gateway.kill('SIGTERM');}
})().catch(e=>{console.error(e);process.exitCode=1;});
