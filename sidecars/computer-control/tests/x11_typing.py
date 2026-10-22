#!/usr/bin/env python3
"""Opt-in native MCP typing regression on a newly owned Xvfb, never host input.

Run inside a disposable private-network/private-tmp user service. All binaries
must be explicit absolute paths; this script creates its own display, cookie,
Chrome profile and loopback fixture. CDP only sets up pages and reads the test
oracle; every tested keyboard/pointer action goes through the official MCP tool.
No clipboard reads/writes, provider calls or connected-device sources.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, secrets, signal, struct, sys
from pathlib import Path
from aiohttp import web, ClientSession

HTML='''<!doctype html><meta charset="utf-8"><style>body{margin:0}textarea{position:absolute;left:20px;top:100px;width:800px;height:150px;font:24px monospace}button{position:absolute;left:20px;top:300px;width:240px;height:70px}</style><textarea id="entry" autofocus></textarea><button id="send">Submit</button><script>window.keys=[];entry.addEventListener('keydown',e=>keys.push({key:e.key,code:e.code,shift:e.shiftKey}));send.onclick=()=>fetch('/submit',{method:'POST',body:JSON.stringify({value:entry.value,keys})});</script>'''

async def main(args):
    if sys.platform!='linux' or not args.isolated_display or os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
        raise RuntimeError('Explicit isolated Linux test with no inherited display required')
    paths={k:Path(getattr(args,k)) for k in ('xvfb','computer','chrome','libraries','xkb','fonts','output')}
    for key,p in paths.items():
        if not p.is_absolute() or p.resolve()!=p:raise ValueError('Canonical absolute test paths required: '+key)
    out=paths['output'];out.mkdir(mode=0o700,exist_ok=True)
    cookie=secrets.token_bytes(16);auth=out/'Xauthority'
    auth.write_bytes(struct.pack('!H',65535)+b''.join(struct.pack('!H',len(v))+v for v in (b'',b'',b'MIT-MAGIC-COOKIE-1',cookie)));auth.chmod(0o600)
    env={'PATH':os.defpath,'HOME':str(out),'LANG':'C.UTF-8','TMPDIR':str(out),
        'LD_LIBRARY_PATH':str(paths['libraries']),'XKB_CONFIG_ROOT':str(paths['xkb'])}
    children=[];runner=None;rows=[];submissions=[];mcp_id=0
    async def spawn(*argv,**kw):
        p=await asyncio.create_subprocess_exec(*map(str,argv),env=env,start_new_session=True,limit=8<<20,**kw)
        children.append(p);return p
    try:
        r,w=os.pipe()
        xvfb=await spawn(paths['xvfb'],'-displayfd',str(w),'-screen','0','1280x800x24','-nolisten','tcp','-auth',auth,'-noreset','-br','-xkbdir',paths['xkb'],'-fp',paths['fonts'],pass_fds=(w,),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        os.close(w)
        display=await asyncio.wait_for(asyncio.to_thread(os.read,r,20),10);os.close(r)
        if not display.strip().isdigit() or xvfb.returncode is not None:raise RuntimeError('Owned Xvfb not ready')
        env.update(DISPLAY=':'+display.decode().strip(),XAUTHORITY=str(auth))
        app=web.Application()
        async def page(request):return web.Response(text=HTML,content_type='text/html')
        async def submit(request):
            submissions.append(json.loads(await request.text()));return web.Response(text='OK')
        app.router.add_get('/',page);app.router.add_post('/submit',submit)
        runner=web.AppRunner(app);await runner.setup();site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
        port=site._server.sockets[0].getsockname()[1];url=f'http://127.0.0.1:{port}/'
        sdk=await spawn(paths['computer'],stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        async def rpc(method,params):
            nonlocal mcp_id
            mcp_id+=1;sdk.stdin.write((json.dumps({'jsonrpc':'2.0','id':mcp_id,'method':method,'params':params})+'\n').encode());await sdk.stdin.drain()
            while True:
                line=await asyncio.wait_for(sdk.stdout.readline(),20)
                if not line:raise RuntimeError('Official MCP exited')
                reply=json.loads(line)
                if reply.get('id')==mcp_id:
                    if 'error' in reply:raise RuntimeError('Official MCP error '+json.dumps(reply['error']))
                    return reply['result']
        await rpc('initialize',{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'openagent-isolated-typing-regression','version':'1'}})
        sdk.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n');await sdk.stdin.drain()
        await rpc('tools/call',{'name':'computer','arguments':{'action':'get_screenshot'}})
        removed=[]
        if args.reset_keymap:
            # Regression fixture only: emulate a real X11 layout reload removing
            # the extra colon binding cached by the persistent input controller.
            await rpc('tools/call',{'name':'computer','arguments':{'action':'type','text':':'}})
            import ctypes as c
            x=c.CDLL(str(paths['libraries']/'libX11.so.6'))
            x.XOpenDisplay.argtypes=[c.c_char_p];x.XOpenDisplay.restype=c.c_void_p
            x.XDisplayKeycodes.argtypes=[c.c_void_p,c.POINTER(c.c_int),c.POINTER(c.c_int)]
            x.XGetKeyboardMapping.argtypes=[c.c_void_p,c.c_ubyte,c.c_int,c.POINTER(c.c_int)];x.XGetKeyboardMapping.restype=c.POINTER(c.c_ulong)
            x.XChangeKeyboardMapping.argtypes=[c.c_void_p,c.c_int,c.c_int,c.POINTER(c.c_ulong),c.c_int]
            x.XSync.argtypes=[c.c_void_p,c.c_int];x.XFree.argtypes=[c.c_void_p];x.XCloseDisplay.argtypes=[c.c_void_p]
            os.environ['XAUTHORITY']=str(auth)
            d=x.XOpenDisplay(env['DISPLAY'].encode());assert d
            try:
                low,high,width=c.c_int(),c.c_int(),c.c_int()
                x.XDisplayKeycodes(d,c.byref(low),c.byref(high))
                mapping=x.XGetKeyboardMapping(d,low.value,high.value-low.value+1,c.byref(width))
                assert mapping and width.value>0
                try:
                    for keycode in range(low.value,high.value+1):
                        if mapping[(keycode-low.value)*width.value]==ord(':'):
                            empty=(c.c_ulong*width.value)()
                            x.XChangeKeyboardMapping(d,keycode,width.value,empty,1);removed.append(keycode)
                finally:x.XFree(mapping)
                x.XSync(d,False)
            finally:x.XCloseDisplay(d)
            if not removed:raise RuntimeError('Regression did not create a colon binding')
        profile=out/'chrome-profile'
        chrome_log=(out/'chrome.log').open('wb')
        chrome=await spawn(paths['chrome'],'--ozone-platform=x11','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--password-store=basic','--disable-dev-shm-usage','--remote-debugging-port=0',f'--user-data-dir={profile}','--window-size=1280,800','about:blank',stdout=chrome_log,stderr=chrome_log)
        active=profile/'DevToolsActivePort'
        for _ in range(100):
            if active.is_file():break
            if chrome.returncode is not None:raise RuntimeError('Sandboxed Chrome did not start')
            await asyncio.sleep(.1)
        else:raise RuntimeError('Chrome readiness timeout')
        cdpport=int(active.read_text().splitlines()[0])
        async with ClientSession() as http:
            async with http.get(f'http://127.0.0.1:{cdpport}/json/list') as response:pages=await response.json()
            target=next(p for p in pages if p.get('type')=='page')
            async with http.ws_connect(target['webSocketDebuggerUrl']) as ws:
                cdp_id=0
                async def cdp(method,params):
                    nonlocal cdp_id
                    cdp_id+=1;await ws.send_json({'id':cdp_id,'method':method,'params':params})
                    while True:
                        value=await asyncio.wait_for(ws.receive_json(),10)
                        if value.get('id')==cdp_id:
                            if 'error' in value:raise RuntimeError('CDP oracle error')
                            return value.get('result',{})
                async def read():
                    data=await cdp('Runtime.evaluate',{'expression':'JSON.stringify({value:document.getElementById("entry")?.value,keys:window.keys,url:location.href})','returnByValue':True})
                    return json.loads(data['result']['value'])
                async def navigate():
                    await cdp('Page.navigate',{'url':url})
                    for _ in range(50):
                        try:
                            state=await read()
                            if state.get('value')=='':return
                        except (KeyError,TypeError):pass
                        await asyncio.sleep(.1)
                    raise RuntimeError('Fixture page not ready')
                async def action(**arguments):
                    result=await rpc('tools/call',{'name':'computer','arguments':arguments})
                    if result.get('isError'):raise RuntimeError('Official input error '+json.dumps(result))
                    await asyncio.sleep(.15)
                # Cold browser chrome has not yet seen a remapped Unicode key.
                await action(action='key',text='ctrl+l');await action(action='type',text=url);await action(action='key',text='Return');await asyncio.sleep(.6)
                cold=await read();rows.append({'case':'cold URL via address bar','expected':url,'observed':cold.get('url'),'passed':cold.get('url')==url})
                for expected in [url,':','/:@','ABC xyz !? &# [] {} _+=','caffè più già città €']:
                    await navigate();await action(action='left_click',coordinate=[100,150])
                    await action(action='type',text=expected)
                    state=await read()
                    await action(action='key',text='Tab');await action(action='key',text='Return')
                    for _ in range(20):
                        if submissions:break
                        await asyncio.sleep(.1)
                    posted=submissions.pop() if submissions else None
                    row={'expected':expected,'observed':state.get('value'),'keys':state.get('keys'),'posted':posted,'passed':state.get('value')==expected and posted is not None and posted['value']==expected}
                    rows.append(row)
                    (out/'progress.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
                await navigate();await action(action='key',text='ctrl+l');await action(action='type',text=url);await action(action='key',text='Return');await asyncio.sleep(.4)
                state=await read();rows.append({'case':'URL via normal address bar','expected':url,'observed':state.get('url'),'passed':state.get('url')==url})
                result=await rpc('tools/call',{'name':'computer','arguments':{'action':'get_screenshot'}})
                import base64
                for item in result.get('content',[]):
                    if item.get('type')=='image':(out/'final.png').write_bytes(base64.b64decode(item['data']));break
        report={'status':'passed' if all(r['passed'] for r in rows) else 'failed','scope':('source input.rs Linux debug harness; not full SDK' if args.input_harness else 'owned Xvfb and official MCP; synthetic Chrome input; no user or agent display'),'sdkSHA256':hashlib.file_digest(paths['computer'].open('rb'),'sha256').hexdigest(),'display':env['DISPLAY'],'uid':os.getuid(),'controllerInitializedBeforeChrome':True,'removedExtraColonBindings':removed,'clipboardAccessed':False,'rows':rows}
        (out/'typing.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps({'status':report['status'],'caseCount':len(rows),'passedCount':sum(r['passed'] for r in rows),'sdkSHA256':report['sdkSHA256']}))
        return 0 if report['status']=='passed' else 1
    finally:
        if runner is not None:await runner.cleanup()
        for process in reversed(children):
            if process.returncode is None:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:await asyncio.wait_for(process.wait(),3)
                except TimeoutError:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    await process.wait()
        auth.unlink(missing_ok=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--isolated-display',action='store_true')
    p.add_argument('--reset-keymap',action='store_true')
    p.add_argument('--input-harness',action='store_true',help='honestly identify a source-only input debug harness')
    for name in ('xvfb','computer','chrome','libraries','xkb','fonts','output'):p.add_argument('--'+name,required=True)
    raise SystemExit(asyncio.run(main(p.parse_args())))
