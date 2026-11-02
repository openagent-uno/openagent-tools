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
