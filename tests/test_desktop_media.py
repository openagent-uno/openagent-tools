import asyncio
import json
import os
import sys
import unittest
from openagent_device_tools.media import NativeDesktopMedia, native_desktop_command, stream_options, video_packet

CONFIG={"type":"config","protocol":"openagent-video/1","codec":"avc1.42E01F","width":640,"height":480,"input_width":640,"input_height":480,"fps":20}
FRAME={"type":"frame","seq":0,"timestamp_us":0,"key":True,"data":"AAAAAQ=="}
class DesktopMedia(unittest.IsolatedAsyncioTestCase):
    async def test_owned_encoder_is_reaped_when_viewer_closes(self):
        script="import sys,json,time;sys.stdin.readline();print("+repr(json.dumps(CONFIG))+",flush=True);print("+repr(json.dumps(FRAME))+",flush=True);time.sleep(30)"
        media=NativeDesktopMedia([sys.executable,'-c',script])
        iterator=media.stream_tool('computer',{},None)
        self.assertEqual(CONFIG,await anext(iterator));self.assertEqual(FRAME,await anext(iterator));await asyncio.wait_for(iterator.aclose(),timeout=3)
    async def test_bounds_and_exact_tool_names(self):
        for value in ({'fps':True},{'fps':31},{'display_id':-1},{'command':'x'}):
            with self.assertRaises(ValueError):stream_options(value)
        for value in ({**FRAME,'seq':-1},{**FRAME,'data':'!!!'},{**CONFIG,'codec':'invalid'}):
            with self.assertRaises(ValueError):video_packet(value)
        media=NativeDesktopMedia([sys.executable])
        with self.assertRaises(LookupError):await anext(media.stream_tool('other',{},None))

    @unittest.skipUnless(os.environ.get('OPENAGENT_TEST_NATIVE_MEDIA')=='1','requires qualified native display capture')
    async def test_real_encoder_static_frames_and_same_source_renewal(self):
        command=native_desktop_command();self.assertIsNotNone(command)
        media=NativeDesktopMedia(command);self.assertTrue(await media.qualify())
        iterator=media.stream_tool('computer',{'fps':20,'max_duration_seconds':1},None)
        configs=frames=0
        try:
            async with asyncio.timeout(10):
                async for packet in iterator:
                    if packet['type']=='config':
                        configs+=1
                        if configs==2:break
                    else:
                        frames+=1
                        self.assertTrue(packet['data'])
        finally:await iterator.aclose()
        self.assertGreater(frames,0);self.assertEqual(2,configs)

    async def test_old_or_unrelated_process_is_not_advertised_as_a_media_encoder(self):
        media=NativeDesktopMedia([sys.executable,'-c','print("{}")'])
        self.assertFalse(await media.qualify())

    @unittest.skipUnless(os.environ.get('OPENAGENT_TEST_NATIVE_MEDIA')=='1','requires qualified native display capture and optional Core engine')
    async def test_real_mcp_screenshot_and_live_view_share_qualified_bundle(self):
        from openagent_core.capabilities import CapabilityCatalog
        from openagent_core.contracts import PrincipalRef, ExecutionContext
        from openagent_core.mcp.pool import MCPPool
        class Policy:
            async def authorize(self,*args,**kwargs):return True
        command=native_desktop_command();self.assertIsNotNone(command)
        pool=MCPPool.from_config([{'name':'computer-control','command':list(command)}],include_defaults=False)
        media=NativeDesktopMedia(command);self.assertTrue(await media.qualify());pool.register_media_executor('computer-control',media)
        catalog=CapabilityCatalog(Policy());principal=PrincipalRef('fixture','tenant','user')
        context=ExecutionContext(principal,principal,principal,'session','agent',(principal,))
        await pool.connect_all();pool.bind_capability_catalog(catalog)
        try:
            tools=await catalog.discover(context);computer=next(t for t in tools if t.name in {'computer','computer_control_computer'})
            result=await catalog.call_tool(computer.tool_ref,{'action':'get_screenshot'},context,surface='app')
            content=result.get('content',[]) if isinstance(result,dict) else result.content
            self.assertTrue(any((item.get('type') if isinstance(item,dict) else item.type)=='image' for item in content))
            iterator=catalog.stream_tool(computer.tool_ref,{'fps':10,'max_duration_seconds':1},context)
            try:
                self.assertEqual('config',(await anext(iterator))['type']);self.assertEqual('frame',(await anext(iterator))['type'])
            finally:await iterator.aclose()
        finally:await pool.close_all()
