"""Real private-pipe browser rendering inside an inherited macOS sandbox."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
host = root / 'sidecars/agent-in-chrome/host'
binary = args.binary.resolve(strict=True)
with tempfile.TemporaryDirectory(prefix='oa-render-', dir='/private/tmp') as directory:
    fixture = Path(directory).resolve()
    box, outside = fixture/'box', fixture/'outside'
    box.mkdir(mode=0o700)
    outside.write_text('synthetic sentinel, not host data')
    for name in ['tmp', 'profile']: (box/name).mkdir(mode=0o700)
    quoted = lambda path: json.dumps(str(path))
    profile = '''(version 1)
(deny default)
(allow process-exec process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read mach-lookup system-socket network*)
(allow mach-register (global-name-prefix "org.chromium.crashpad.")
 (global-name-prefix "com.google.chrome.for.testing.MachPortRendezvousServer."))
(allow iokit-open (iokit-user-client-class "RootDomainUserClient"))
(allow file-read-metadata)
(allow file-read* (literal "/") (subpath "/usr") (subpath "/bin") (subpath "/sbin")
 (subpath "/System") (subpath "/Library/Apple") (subpath "/private/etc")
 (subpath "/private/var/db/timezone") (subpath "/dev")
 (subpath HOST) (subpath BROWSER) (subpath BOX))
(allow file-write* (subpath BOX) (literal "/dev/null"))
'''.replace('HOST', quoted(host)).replace('BROWSER', quoted(binary.parents[3])).replace('BOX', quoted(box))
    node = Path(subprocess.check_output(['which','node'], text=True).strip()).resolve()
    requirements = json.loads(subprocess.check_output([str(node),str(host/'macos-host-requirements.js'),
        '--binary',str(binary),'--profile',str(box/'profile')],text=True))
    profile += '\n(allow mach-register (global-name '+json.dumps(requirements['machRegister'][0])+'))\n'
    profile += '\n(allow file-read* (subpath '+quoted(node.parent.parent)+'))\n'
    script = '''import fs from 'node:fs';
import http from 'node:http';
import assert from 'node:assert/strict';
import {ensureBrowser,closeDedicatedBrowser} from BROWSER;
import {CDPConnection} from CDP;
assert.throws(()=>fs.readFileSync(process.env.OWNED_SENTINEL),error=>['EACCES','EPERM'].includes(error.code));
const server=http.createServer((request,response)=>response.end('<h1>owned software rendering</h1>'));
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
let launched,cdp;
try {
 launched=await ensureBrowser();assert.equal(typeof launched.wsUrl,'object');
 fs.writeFileSync(process.env.OWNED_CHILD,JSON.stringify({pid:launched.pid}));
 launched.wsUrl.child.on('exit',(code,signal)=>console.error('Owned Chromium exit',JSON.stringify({code,signal})));
 launched.wsUrl.child.on('error',error=>console.error('Owned Chromium spawn error',error.code));
 assert.ok(!launched.wsUrl.child.spawnargs.some(arg=>arg.startsWith('--remote-debugging-port')));
 cdp=new CDPConnection(launched.wsUrl);await cdp.connect();
 await cdp.send('Browser.getVersion');
 const {targetId}=await cdp.send('Target.createTarget',{url:'about:blank'});
 const {sessionId}=await cdp.send('Target.attachToTarget',{targetId,flatten:true});
 await cdp.send('Page.enable',{},sessionId);
 await cdp.send('Page.navigate',{url:'http://127.0.0.1:'+server.address().port},sessionId);
 let text='';
 for(let n=0;n<100;n++){
  text=(await cdp.send('Runtime.evaluate',{expression:'document.body?.innerText',returnByValue:true},sessionId)).result.value||'';
  if(text.includes('owned software rendering'))break;
  await new Promise(resolve=>setTimeout(resolve,50));
 }
 assert.ok(text.includes('owned software rendering'));
 const screenshot=await cdp.send('Page.captureScreenshot',{format:'png'},sessionId);
 assert.ok(Buffer.from(screenshot.data,'base64').length>100);
 assert.equal(fs.existsSync(process.env.OPENAGENT_CHROME_PROFILE_DIR+'/DevToolsActivePort'),false);
 console.log('PASS: software DOM and screenshot in inherited sandbox; outside sentinel denied; private CDP pipe');
} finally {
 if(cdp)await closeDedicatedBrowser(cdp,{ownsBrowser:true,browserPid:launched?.pid});
 if(launched?.wsUrl.child.exitCode===null)launched.wsUrl.child.kill();
 server.close();
}
'''.replace('BROWSER', repr((host/'browser.js').as_uri())).replace('CDP;', repr((host/'cdp.js').as_uri())+';')
    environment = {'HOME':str(box),'CFFIXED_USER_HOME':str(box),'TMPDIR':str(box/'tmp'),
                   'MAC_CHROMIUM_TMPDIR':str(box/'tmp'),'PATH':'/usr/bin:/bin',
                   'OPENAGENT_CHROME_PROFILE_DIR':str(box/'profile'),'OPENAGENT_CHROME_BINARY':str(binary),
                   'OPENAGENT_CHROME_TRANSPORT':'pipe','OPENAGENT_CHROME_INHERITED_SANDBOX':'1',
                   'OPENAGENT_CHROME_HEADLESS':'true','OPENAGENT_CHROME_RENDERER':'software','OPENAGENT_CHROME_DIAGNOSTICS':'true',
                   'OWNED_SENTINEL':str(outside),'OWNED_CHILD':str(box/'owned-child.json')}
    started = time.time()
    result = subprocess.run(['/usr/bin/sandbox-exec','-p',profile,str(node),'--input-type=module','-e',script],
                            env=environment,cwd=box,timeout=90)
    if result.returncode:
        log = box/'profile/native-browser.log'
        if log.is_file(): print(log.read_text(errors='replace')[-12000:])
        pid = json.loads((box/'owned-child.json').read_text())['pid'] if (box/'owned-child.json').is_file() else None
        reports = Path.home()/'Library/Logs/DiagnosticReports'
        if reports.is_dir():
            for report in reports.glob('*.ips'):
                if report.stat().st_mtime < started: continue
                try:
                    parts=report.read_text().split('\n',1)
                    value=json.loads(parts[1])
                    if value.get('pid') == pid:
                        print('Owned crash',json.dumps({k:value.get(k) for k in ['exception','termination','asi','faultingThread']})[:12000])
                except (ValueError,OSError): pass
        logs=subprocess.run(['sudo','-n','log','show','--style','compact','--last','1m','--predicate',
            'eventMessage CONTAINS "deny" AND eventMessage CONTAINS "'+str(pid)+'"'],capture_output=True,text=True,timeout=30)
        print('Owned sandbox denials',logs.stdout[-12000:])
    raise SystemExit(result.returncode)
