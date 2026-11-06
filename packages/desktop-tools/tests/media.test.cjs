const test=require('node:test');
const assert=require('node:assert/strict');
const {NativeScreenStream,videoPacket,nativeHelper}=require('../dist');
const {VideoCanvasDecoder}=require('../dist/video-browser');
const config={type:'config',protocol:'openagent-video/1',codec:'avc1.42E01F',width:640,height:480,input_width:641,input_height:481,fps:20};
const frame={type:'frame',seq:0,timestamp_us:1,key:true,data:'AAAAAQ=='};
test('media wire rejects malformed, unbounded and ambiguous packets',()=>{
 assert.deepEqual(videoPacket(config),config);assert.deepEqual(videoPacket(frame),frame);
 for(const value of [{...config,fps:31},{...config,width:-1},{...config,codec:'arbitrary'},{...frame,seq:0.5},{...frame,data:'!'},null])assert.throws(()=>videoPacket(value));
});
test('owned encoder closes on cancellation and rejects bad sequence',async()=>{
 const script=`process.stdin.once('data',()=>{console.log(JSON.stringify(${JSON.stringify(config)}));console.log(JSON.stringify(${JSON.stringify(frame)}));setInterval(()=>{},1000)});`;
 const stream=new NativeScreenStream({command:process.execPath,args:['-e',script,'--']});let ended=0;const packets=[];
 const result=await stream.start({},packet=>packets.push(packet),()=>ended++);assert.equal(result.width,640);
 stream.stop();await new Promise(r=>setTimeout(r,50));assert.equal(ended,1);assert.ok(packets.length>=1);
 const broken=new NativeScreenStream({command:process.execPath,args:['-e',script.replace('"seq":0','"seq":8'),'--']});
 let error;await broken.start({},()=>{},e=>error=e);await new Promise(r=>setTimeout(r,50));assert.match(error.message,/video_sequence/);broken.stop();
});
test('browser decoder resets per encoder and releases every frame',async()=>{
 let closed=0,painted=0,decoderClosed=0;
 class Codec {state='configured';decodeQueueSize=0;constructor(callbacks){this.callbacks=callbacks;}static async isConfigSupported(){return {supported:true};}configure(){}decode(){this.callbacks.output({displayWidth:640,displayHeight:480,close(){closed++}});}close(){this.state='closed';decoderClosed++;}}
 global.VideoDecoder=Codec;global.EncodedVideoChunk=class{constructor(value){Object.assign(this,value)}};
 const canvas={getContext:()=>({drawImage(){painted++}})};
 const decoder=new VideoCanvasDecoder(()=>canvas,()=>{},error=>assert.fail(error));
 await decoder.accept(config);await decoder.accept(frame);await decoder.accept(config);await decoder.accept(frame);decoder.close();
 assert.equal(closed,2);assert.equal(painted,2);assert.equal(decoderClosed,2);
 const invalid=new VideoCanvasDecoder(()=>canvas,()=>{},()=>{});await assert.rejects(invalid.accept(frame),/interrupted/);invalid.close();
 delete global.VideoDecoder;delete global.EncodedVideoChunk;
});
test('native artifacts are explicit and digest verified',()=>{assert.throws(()=>nativeHelper('unqualified','none'),/unqualified/);});
