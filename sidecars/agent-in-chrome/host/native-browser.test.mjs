import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CDPConnection } from './cdp.js';

test('CDP uses inherited pipes without a network endpoint and settles disconnects', async t => {
  const child = spawn(process.execPath, ['-e', `
    const fs=require('node:fs'); let buffer='';
    fs.createReadStream(null,{fd:3}).on('data',chunk=>{
      buffer+=chunk;let end;
      while((end=buffer.indexOf('\\0'))>=0){
        const request=JSON.parse(buffer.slice(0,end));buffer=buffer.slice(end+1);
        if(request.method==='Never.reply') continue;
        fs.writeSync(4,JSON.stringify({id:request.id,result:{echo:request.params}})+'\\0');
      }
    });`], {stdio:['ignore','ignore','inherit','pipe','pipe']});
  t.after(() => child.kill());
  const cdp = new CDPConnection({child}, {requestTimeoutMs:1000});
  await cdp.connect();
  assert.deepEqual(await cdp.send('Echo',{value:'owned'}),{echo:{value:'owned'}});
  const pending = cdp.send('Never.reply');
  const rejected = assert.rejects(pending,/closed/);
  child.kill();
  await rejected;
  assert.equal(cdp.pending.size,0);
});

test('an explicit missing browser fails without selecting a host installation', async () => {
  const before = process.env.OPENAGENT_CHROME_BINARY;
  try {
    process.env.OPENAGENT_CHROME_BINARY = path.join(os.tmpdir(),'unavailable-browser-'+process.pid);
    const {resolveBinaryCandidates} = await import('./browser.js');
    assert.throws(() => resolveBinaryCandidates(), /Configured browser executable is unavailable/);
  } finally {
    if(before===undefined)delete process.env.OPENAGENT_CHROME_BINARY;
    else process.env.OPENAGENT_CHROME_BINARY=before;
  }
});


test('owned Chromium pipe launch and close never probe an unrelated HTTP port', async t => {
  const executable = process.env.OPENAGENT_TEST_CHROME_BINARY || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  if (!fs.existsSync(executable)) return t.skip('An explicitly installed Chromium is required');
  const http = await import('node:http');
  let requests = 0;
  const server = http.createServer((request,response)=>{requests++;response.end(JSON.stringify({Browser:'Unrelated',webSocketDebuggerUrl:'ws://127.0.0.1/foreign'}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const profile=fs.mkdtempSync(path.join(os.tmpdir(),'openagent-owned-pipe-'));
  const names=['OPENAGENT_CHROME_BINARY','OPENAGENT_CHROME_PROFILE_DIR','OPENAGENT_CHROME_TRANSPORT','OPENAGENT_CHROME_HEADLESS'];
  const previous=Object.fromEntries(names.map(name=>[name,process.env[name]]));
  Object.assign(process.env,{OPENAGENT_CHROME_BINARY:executable,OPENAGENT_CHROME_PROFILE_DIR:profile,OPENAGENT_CHROME_TRANSPORT:'pipe',OPENAGENT_CHROME_HEADLESS:'true'});
  const {ensureBrowser,closeDedicatedBrowser}=await import('./browser.js');
  let launched,connection;
  try {
    launched=await ensureBrowser({port:server.address().port});
    connection=new CDPConnection(launched.wsUrl);await connection.connect();
    assert.match((await connection.send('Browser.getVersion')).product,/Chrome|Chromium/);
    const target=await connection.send('Target.createTarget',{url:'about:blank'});
    assert.ok(target.targetId);
    assert.equal(await closeDedicatedBrowser(connection,{ownsBrowser:true,browserPid:launched.pid,port:server.address().port}),true);
    assert.equal(requests,0);
  } finally {
    if(launched?.wsUrl?.child?.exitCode===null)launched.wsUrl.child.kill();
    connection?.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    for(const name of names)if(previous[name]===undefined)delete process.env[name];else process.env[name]=previous[name];
    fs.rmSync(profile,{recursive:true,force:true});
  }
});


test('semantic tools report an explicit pipe limitation without replacing the browser', async () => {
  const {AdvancedBrowser}=await import('./browser-advanced.js');
  const endpoint={wsUrl:{child:{}},closed:false};
  const controller={cdp:endpoint,ensure:async()=>{}};
  const advanced=new AdvancedBrowser(controller,{id:'owned',backend:'chrome',allow_downloads:true});
  assert.equal(advanced.support().semantic_locators,false);
  await assert.rejects(advanced.ensure(),error=>error.code==='unsupported_browser_transport');
  assert.equal(controller.cdp,endpoint);
});
