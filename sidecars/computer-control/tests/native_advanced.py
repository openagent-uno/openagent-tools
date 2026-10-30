"""Opt-in owned macOS advanced native-controls acceptance; never uses microphone.

Every audio capture is filtered to this fixture's exact app/process; clipboard
contents are compared privately by digest and are not copied into the receipt.
"""
from __future__ import annotations
import asyncio,base64,json,os,plistlib,shutil,signal,struct,subprocess,tempfile,time,uuid
from pathlib import Path
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
ROOT=Path(__file__).resolve().parents[1]

def unpack(result):
 text='\n'.join(item.text for item in result.content if hasattr(item,'text'))
 if result.isError:return {'error':text}
 return json.loads(text)
async def state_until(path,predicate,attempts=350):
 for _ in range(attempts):
  try:
   state=json.loads(path.read_text())
   if predicate(state):return state
  except (OSError,ValueError):pass
  await asyncio.sleep(.04)
 raise AssertionError(('owned fixture did not reach expected state',json.loads(path.read_text()) if path.exists() else None))

def wav_energy(data):
 assert data[:4]==b'RIFF' and data[8:12]==b'WAVE'
 offset=12;fmt=None;pcm=None
 while offset+8<=len(data):
  tag=data[offset:offset+4];size=struct.unpack_from('<I',data,offset+4)[0];payload=data[offset+8:offset+8+size]
  if tag==b'fmt ':fmt=struct.unpack_from('<HHIIHH',payload)
  if tag==b'data':pcm=payload
  offset+=8+size+(size&1)
 assert fmt and pcm is not None
 format_id,channels,rate,_,_,bits=fmt
 assert rate==24000 and channels==2,(fmt,len(data))
 if format_id==3 and bits==32:samples=struct.unpack('<'+'f'*(len(pcm)//4),pcm)
 elif format_id==1 and bits==16:samples=[v/32768 for v in struct.unpack('<'+'h'*(len(pcm)//2),pcm)]
 else:raise AssertionError(('unsupported QA WAV format',fmt))
 return max((abs(v) for v in samples),default=0),len(samples)//channels

async def main():
 checks=[];audio_boundary=None;audio_evidence=None;started=time.monotonic();owned_pid=None
 with tempfile.TemporaryDirectory(prefix='openagent-owned-native-advanced-') as temporary:
  directory=Path(temporary);bundle=directory/'OpenAgent Native Fixture.app';mac=bundle/'Contents/MacOS';resources=bundle/'Contents/Resources';mac.mkdir(parents=True);resources.mkdir()
  executable=mac/'NativeFixture';shutil.copy2(ROOT/'target/native-accessibility-fixture',executable)
  title='OpenAgent Advanced Fixture '+uuid.uuid4().hex[:8];state=directory/'state.json';control=directory/'control.txt'
  (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'NativeFixture','CFBundleIdentifier':'uno.openagent.fixture.'+uuid.uuid4().hex,'CFBundleName':'OpenAgent Native Fixture','CFBundlePackageType':'APPL','LSUIElement':False}))
  (resources/'FixtureConfig.json').write_text(json.dumps({'title':title,'state':str(state),'control':str(control)}))
  child=subprocess.Popen([str(executable),title,str(state),str(control)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   ready=await state_until(state,lambda s:s['title']==title);owned_pid=ready['pid']
   async with stdio_client(StdioServerParameters(command=(command:=json.loads(os.environ.get('OPENAGENT_NATIVE_QA_MCP_COMMAND',json.dumps([str(ROOT/'target/debug/openagent-computer-control')]))))[0],args=command[1:])) as (read,write):
    async with ClientSession(read,write) as session:
     initialized=await session.initialize()
     async def call(name,arguments):
      try:return unpack(await session.call_tool(name,arguments))
      except McpError as error:return {'error':str(error)}
     policy=await call('computer_app_policy',{});assert policy.get('host_authorization_required') is True,policy;checks.append('host/OS capability policy reported')
     apps=await call('computer_list_apps',{});assert 'error' not in apps,apps
     matches=[a for a in apps['apps'] if a['bundle_path']==str(bundle)];assert len(matches)==1,(len(apps['apps']),apps.get('truncated'))
     app_ref=matches[0]['app_ref'];checks.append('launchable catalog includes exact owned app')
     child.terminate();child.wait(timeout=3)
     launched=await call('computer_launch_app',{'app_ref':app_ref,'activate':True});assert launched.get('launched') is True,launched
     assert launched['pid']!=owned_pid;owned_pid=launched['pid'];app_ref=launched['app_ref'];await state_until(state,lambda s:s['pid']==owned_pid)
     checks.append('cold exact app launch confirms refreshed ref and PID')
     denied=await call('computer_launch_app',{'app_ref':matches[0]['app_ref'],'activate':False});assert 'stale_app_ref' in denied.get('error',''),denied;checks.append('consumed launch ref rejects replay')
     async def snapshot():
      last=None;previous=None
      for _ in range(30):
       windows=await call('computer_list_windows',{});target=[w for w in windows.get('windows',[]) if w['pid']==owned_pid and w['title']==title]
       if len(target)==1:
        current=tuple(target[0].get(key) for key in ('window_id','pid','title','x','y','width','height'))
        if current!=previous:
         previous=current;await asyncio.sleep(.1);continue
        last=await call('computer_accessibility_snapshot',{'window_id':target[0]['window_id'],'pid':owned_pid})
        if 'error' not in last:return last
        if not any(code in last['error'] for code in ('ambiguous_accessibility_window','stale_window_target')):break
       await asyncio.sleep(.05)
      raise AssertionError(last or target)
     def element(tree,identifier):
      matches=[row for row in tree['elements'] if row['state']['identifier']==identifier];assert len(matches)==1,(identifier,tree);return matches[0]
     async def invoke(name,selector=None,**args):
      print('native QA:',name,selector or '',flush=True)
      if name in {'computer_select_text','computer_paste'} or name=='computer_window_input' and args.get('input',{}).get('action')!='focus':
       focus=await snapshot()
       focused=await call('computer_window_input',{'snapshot_id':focus['snapshot_id'],'input':{'action':'focus'}})
       assert focused.get('ok') is True,focused
       await asyncio.sleep(.15)
      tree=await snapshot();arguments={'snapshot_id':tree['snapshot_id']}
      if selector:arguments['element_id']=element(tree,selector)['element_id']
      arguments.update(args);value=await call(name,arguments);assert 'error' not in value,(name,value);return value
     await invoke('computer_window_input',input={'action':'focus'});checks.append('explicit exact window focus')
     await invoke('computer_accessibility_action','oa-fixture-text',action='set_value',value='a🌞b target target')
     selected=await invoke('computer_select_text','oa-fixture-text',selection={'text':'target','prefix':'b ','suffix':' target','mode':'text'})
     assert selected['selected_range_utf16']==[5,6],selected
     await state_until(state,lambda s:s['selection_utf16']==[5,6]);checks.append('native Unicode prefix/suffix selection confirmed')
     tree=await snapshot();ambiguous=await call('computer_select_text',{'snapshot_id':tree['snapshot_id'],'element_id':element(tree,'oa-fixture-text')['element_id'],'selection':{'text':'target'}});assert 'ambiguous_text_selection' in ambiguous.get('error',''),ambiguous;checks.append('ambiguous native selection denied')
     await invoke('computer_window_input',input={'action':'type','text':'ciao🌞'})
     await state_until(state,lambda s:s['text']=='a🌞b ciao🌞 target');checks.append('PID/window-bound Unicode input confirmed')
     await invoke('computer_window_input',input={'action':'key','key':'cmd+a'})
     await state_until(state,lambda s:s['selection_utf16']==[0,len(s['text'].encode('utf-16-le'))//2]);checks.append('PID/window-bound physical key chord confirmed')
     tree=await snapshot();button=element(tree,'oa-fixture-apply');bounds=button['state']['bounds'];coordinate=[bounds[0]+bounds[2]/2-tree['window']['x'],bounds[1]+bounds[3]/2-tree['window']['y']]
     print('owned click observation:',tree['window'],bounds,coordinate,flush=True)
     clicked=await call('computer_window_input',{'snapshot_id':tree['snapshot_id'],'input':{'action':'click','coordinate':coordinate}});assert clicked.get('ok') is True,clicked
     await state_until(state,lambda s:s['clicks']==1,attempts=80);checks.append('window-relative PID-targeted click confirmed')
     tree=await snapshot();button=element(tree,'oa-fixture-apply');action=await call('computer_perform_action',{'snapshot_id':tree['snapshot_id'],'element_id':button['element_id'],'native_action':'AXPress'});assert action.get('ok') is True,action
     await state_until(state,lambda s:s['clicks']==2);checks.append('observed secondary native action confirmed')
     tree=await snapshot();surface=element(tree,'oa-fixture-input-surface');bounds=surface['state']['bounds'];start=[bounds[0]+20-tree['window']['x'],bounds[1]+20-tree['window']['y']];end=[start[0]+80,start[1]+10]
     dragged=await call('computer_window_input',{'snapshot_id':tree['snapshot_id'],'input':{'action':'drag','coordinate':start,'to_coordinate':end}});assert dragged.get('ok') is True,dragged
     await state_until(state,lambda s:s['drag_count']>=1 and abs(s['last_drag'][0]-100)<1 and abs(s['last_drag'][1]-30)<1,attempts=80);checks.append('window-bound drag reached owned view')
     await invoke('computer_window_input',input={'action':'scroll','coordinate':start,'direction':'down','amount':120})
     await state_until(state,lambda s:s['scroll_count']>=1 and s['last_scroll'][1]<0,attempts=80);checks.append('window-bound pixel scroll reached owned view')
     control.write_text('clipboard-digest-before');before=await state_until(state,lambda s:bool(s['clipboard_digest']));signature=before['clipboard_digest']
     await invoke('computer_select_text','oa-fixture-rich',selection={'start':0,'length':12})
     rtf=br'{\rtf1\ansi{\fonttbl{\f0 Helvetica;}}\f0\b Rich native paste\b0}'
     pasted=await invoke('computer_paste','oa-fixture-rich',items=[{'mime_type':'text/rtf','data_base64':base64.b64encode(rtf).decode()},{'mime_type':'text/plain','data_base64':base64.b64encode(b'Rich native paste').decode()}]);assert pasted['clipboard_restored'] is True,pasted
     await state_until(state,lambda s:s['rich_text']=='Rich native paste' and s['rich_bold']);checks.append('RTF rich paste delivered with formatting')
     control.write_text('clipboard-digest-after');await asyncio.sleep(.2);after=json.loads(state.read_text());assert after['clipboard_digest']==signature;checks.append('original clipboard representations restored privately')
     invalid_audio=await call('computer_audio_start',{'source':'system_output'});assert 'invalid_audio_source' in invalid_audio.get('error',''),invalid_audio;checks.append('missing audio target cannot widen capture')
     audio_start=await call('computer_audio_start',{'source':'system_output','app_ref':app_ref,'max_duration_ms':3000})
     if 'error' in audio_start:
      audio_boundary=audio_start['error'];checks.append('exact audio grant/backend boundary reported without capture claim')
     else:
      assert audio_start['source_scope']=='exact_app_process' and audio_start['pid']==owned_pid,audio_start
      control.write_text('tone');await state_until(state,lambda s:s['tone_playing']);await asyncio.sleep(1.2)
      raw=await session.call_tool('computer_audio_stop',{'recording_id':audio_start['recording_id']});audio_stop=unpack(raw);assert 'error' not in audio_stop,audio_stop
      chunks=[part for part in raw.content if getattr(part,'type',None)=='audio'];assert len(chunks)==1,raw
      data=base64.b64decode(chunks[0].data);energy,frames=wav_energy(data);assert energy>.001,(energy,frames);assert frames>1000
      artifact=Path(os.environ.get('OPENAGENT_NATIVE_QA_WAV',str(ROOT/'target/native-advanced-tone.wav')));artifact.write_bytes(data)
      audio_evidence={'sample_rate':24000,'channels':2,'frames':frames,'peak':energy,'source':'owned_fixture_app_only','artifact':str(artifact)}
      checks.extend(['exact app-filtered loopback start/stop','24kHz stereo WAV contains owned synthetic tone'])
      replay=await call('computer_audio_stop',{'recording_id':audio_start['recording_id']});assert any(code in replay.get('error','') for code in ('stale_recording_id','resource_owner_mismatch','recording belongs to another local interaction')),replay;checks.append('consumed audio resource rejects replay')
     result={'platform':'macos','sidecar_version':initialized.serverInfo.version,'checks':checks,'passed':len(checks),'audio_boundary':audio_boundary,'fixture_only':True,'audio':audio_evidence,'adopter':command[-1] if command[-1] in {'OpenAgent','GlassPalace','ICS'} else 'direct_mcp','elapsed_seconds':round(time.monotonic()-started,3)}
     Path(os.environ.get('OPENAGENT_NATIVE_QA_RECEIPT',str(ROOT/'target/native-advanced-evidence.json'))).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
  finally:
   try:control.write_text('quit');await asyncio.sleep(.3)
   except OSError:pass
   if child.poll() is None:child.terminate();child.wait(timeout=3)
   if owned_pid and owned_pid!=child.pid:
    command=subprocess.run(['/bin/ps','-p',str(owned_pid),'-o','comm='],capture_output=True,text=True).stdout.strip()
    if command==str(executable):os.kill(owned_pid,signal.SIGTERM)

if __name__=='__main__':asyncio.run(main())
