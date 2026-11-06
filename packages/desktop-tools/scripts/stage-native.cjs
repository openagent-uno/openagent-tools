const {execFileSync}=require('node:child_process');
const {mkdirSync,copyFileSync,readFileSync,writeFileSync,readdirSync,lstatSync,chmodSync}=require('node:fs');
const {createHash}=require('node:crypto');
const path=require('node:path');
const root=path.resolve(__dirname,'..'),crate=path.resolve(root,'../../sidecars/computer-control');
const target=process.platform+'-'+process.arch,name='openagent-computer-control'+(process.platform==='win32'?'.exe':'');
const native=path.join(root,'native');mkdirSync(native,{recursive:true});
const refresh=process.argv.includes('--refresh-manifest');
const version=/^version\s*=\s*"([^"]+)"/m.exec(readFileSync(path.join(crate,'Cargo.toml'),'utf8'))[1];
const app=process.platform==='darwin';
const relative=app?`${target}/openagent-computer-control.app`:`${target}`;
const executable=app?'Contents/MacOS/'+name:name;
if(!refresh){
 execFileSync('cargo',['build','--release','--locked'],{cwd:crate,stdio:'inherit',env:{...process.env,...(process.platform==='win32'?{RUSTFLAGS:((process.env.RUSTFLAGS||'')+' -C target-feature=+crt-static').trim()}:{})}});
 execFileSync(process.platform==='win32'?'python':'python3',[path.join(root,'scripts/native-notices.py')],{stdio:'inherit'});
 const destination=path.join(native,relative,executable);mkdirSync(path.dirname(destination),{recursive:true});
 copyFileSync(path.join(process.env.CARGO_TARGET_DIR||path.join(crate,'target'),'release',name),destination);if(process.platform!=='win32')chmodSync(destination,0o755);
 if(app){
  const info=`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.openagent.computer-control</string><key>CFBundleName</key><string>OpenAgent Computer Control</string><key>CFBundleExecutable</key><string>${name}</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>${version}</string><key>CFBundleShortVersionString</key><string>${version}</string><key>LSUIElement</key><true/><key>LSMinimumSystemVersion</key><string>12.0</string><key>NSHighResolutionCapable</key><true/></dict></plist>`;
  writeFileSync(path.join(native,relative,'Contents/Info.plist'),info);
 }
}
function inventory(directory,prefix=''){
 const result={};for(const entry of readdirSync(directory,{withFileTypes:true})){
  const file=path.join(directory,entry.name),key=prefix+entry.name;
  if(entry.isSymbolicLink())throw new Error('native_artifact_symlink');
  if(entry.isDirectory())Object.assign(result,inventory(file,key+'/'));
  else if(entry.isFile()&&lstatSync(file).isFile())result[key]=createHash('sha256').update(readFileSync(file)).digest('hex');
  else throw new Error('native_artifact_invalid');
 }return result;
}
const file=path.join(native,'manifest.json');let manifest={protocol:'openagent-native-artifacts/2',artifacts:{}};
try{manifest=JSON.parse(readFileSync(file,'utf8'));}catch(error){if(error.code!=='ENOENT')throw error;}
if(manifest.protocol!=='openagent-native-artifacts/2')throw new Error('native_manifest_invalid');
const files=inventory(path.join(native,relative));
manifest.artifacts[target]={version,source_revision:execFileSync('git',['rev-parse','HEAD'],{cwd:crate,encoding:'utf8'}).trim(),roles:{
 control:{root:relative,executable,files,...(app?{minimumSystemVersion:'12.0'}:{})},
 view:{root:relative,executable,files,...(app?{minimumSystemVersion:'12.3'}:{})}
}};
writeFileSync(file,JSON.stringify(manifest,null,2)+'\n');
