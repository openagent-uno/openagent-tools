const test=require('node:test'),assert=require('node:assert/strict');
const {HostProcessBridge}=require('../dist');
test('revocation during optional host acquisition cannot start a stale process',async()=>{
 let release,accountCalls=0;
 const acquired=new Promise(resolve=>release=resolve);
 const bridge=new HostProcessBridge(()=>acquired,async()=>{accountCalls++;return 'fixture-user'});
 const starting=bridge.start({workspaceId:'workspace',agentId:'agent',sessionId:'session',deviceId:'device',deviceLabel:'Fixture'},1);
 const rejected=assert.rejects(starting,/host_tools_stopped/);
 await new Promise(resolve=>setImmediate(resolve));await bridge.hardStop();
 release({command:'/must-not-start',args:[],source:'packaged'});await rejected;
 assert.equal(accountCalls,1);
});

test('a changed authenticated account during acquisition cannot spawn the host',async()=>{
 let release,account='first';const acquired=new Promise(resolve=>release=resolve);
 const bridge=new HostProcessBridge(()=>acquired,async()=>account);
 const starting=bridge.start({workspaceId:'workspace',agentId:'agent',sessionId:'session',deviceId:'device',deviceLabel:'Fixture'},1);
 const rejected=assert.rejects(starting,/account_context_required/);
 await new Promise(resolve=>setImmediate(resolve));account='second';release({command:'/must-not-start',args:[],source:'packaged'});await rejected;
});
