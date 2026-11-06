const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
test('qualified bundle keeps its application identity and rejects changed or extra files',()=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'openagent-native-fixture-')));
 try{
  fs.mkdirSync(path.join(root,'dist'));fs.copyFileSync(path.join(__dirname,'../dist/native-helper.js'),path.join(root,'dist/native-helper.js'));
  const bundle=path.join(root,'native/linux-x64/helper.app');fs.mkdirSync(path.join(bundle,'Contents/MacOS'),{recursive:true});
  const executable='Contents/MacOS/helper';fs.writeFileSync(path.join(bundle,executable),'fixture');fs.chmodSync(path.join(bundle,executable),0o755);
  fs.writeFileSync(path.join(bundle,'Contents/Info.plist'),'fixture-identity');
  const digest=name=>crypto.createHash('sha256').update(fs.readFileSync(path.join(bundle,name))).digest('hex');
  const role={root:'linux-x64/helper.app',executable,files:{[executable]:digest(executable),'Contents/Info.plist':digest('Contents/Info.plist')}};
  fs.writeFileSync(path.join(root,'native/manifest.json'),JSON.stringify({protocol:'openagent-native-artifacts/2',artifacts:{'linux-x64':{version:'fixture',roles:{control:role,view:role}}}}));
  const sdk=require(path.join(root,'dist/native-helper.js')),launch=sdk.nativeHelper('linux','x64');assert.equal(launch.command,path.join(bundle,executable));sdk.verifyNativeHelper(launch.command,'linux','x64');
  fs.writeFileSync(path.join(bundle,'Contents/Info.plist'),'changed');assert.throws(()=>sdk.nativeHelper('linux','x64'),/digest/);
  fs.writeFileSync(path.join(bundle,'Contents/Info.plist'),'fixture-identity');fs.writeFileSync(path.join(bundle,'extra'),'extra');assert.throws(()=>sdk.nativeHelper('linux','x64'),/inventory/);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
