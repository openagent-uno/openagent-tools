import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

type Role = {root:string;executable:string;files:Record<string,string>;minimumSystemVersion?:string};
type Artifact = {version:string;roles:Record<string,Role>};
type Manifest = {protocol:string;artifacts:Record<string,Artifact>};
const unpack=(value:string)=>value.replace(/([\\/])app\.asar([\\/])/,'$1app.asar.unpacked$2');
const nativeRoot=()=>unpack(path.resolve(__dirname,'../native'));
function relative(value:unknown):value is string {
 return typeof value==='string'&&value.length>0&&value.length<4096&&/^[A-Za-z0-9_./-]+$/.test(value)&&value.split('/').every(part=>part&&part!=='.'&&part!=='..');
}
function manifest():Manifest {
 let value:Manifest;
 try{value=JSON.parse(readFileSync(path.join(nativeRoot(),'manifest.json'),'utf8')) as Manifest;}
 catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')throw new Error('native_artifact_unqualified');throw error;}
 if(value.protocol!=='openagent-native-artifacts/2'||!value.artifacts||typeof value.artifacts!=='object')throw new Error('native_manifest_invalid');
 return value;
}
function selection(platform:string,arch:string,role:string):{artifact:Artifact;role:Role;command:string} {
 const artifact=manifest().artifacts[`${platform}-${arch}`],selected=artifact?.roles?.[role];
 if(!artifact||!selected||!relative(selected.root)||!relative(selected.executable)||!selected.files||typeof selected.files!=='object'||Object.keys(selected.files).length>256||!selected.files[selected.executable])throw new Error('native_artifact_unqualified');
 return {artifact,role:selected,command:path.join(nativeRoot(),selected.root,selected.executable)};
}
function files(root:string,prefix=''):string[] {
 return readdirSync(root,{withFileTypes:true}).flatMap(entry=>{
  if(entry.isSymbolicLink())throw new Error('native_artifact_invalid');
  const relative=prefix+entry.name;
  if(entry.isDirectory())return files(path.join(root,entry.name),relative+'/');
  if(!entry.isFile())throw new Error('native_artifact_invalid');
  return [relative];
 });
}
function verify(root:string,role:Role):void {
 const actual=files(root).sort(),expected=Object.keys(role.files).sort();
 if(JSON.stringify(actual)!==JSON.stringify(expected))throw new Error('native_artifact_inventory_mismatch');
 for(const name of expected){
  if(!relative(name)||!/^[a-f0-9]{64}$/.test(role.files[name]||''))throw new Error('native_manifest_invalid');
  const file=path.join(root,name);
  if(!lstatSync(file).isFile()||createHash('sha256').update(readFileSync(file)).digest('hex')!==role.files[name])throw new Error('native_artifact_digest_mismatch');
 }
}
function systemVersion():number[]{
 const reader=(process as NodeJS.Process & {getSystemVersion?:()=>string}).getSystemVersion;
 const version=reader?reader():execFileSync('/usr/bin/sw_vers',['-productVersion'],{encoding:'utf8',timeout:2000}).trim();
 return version.split('.').map(Number);
}
export function nativeHelper(platform=process.platform,arch=process.arch,role='control'):{command:string;args:string[];version:string} {
 const selected=selection(platform,arch,role);
 if(platform==='darwin'&&process.platform==='darwin'&&selected.role.minimumSystemVersion){
  const current=systemVersion(),minimum=selected.role.minimumSystemVersion.split('.').map(Number);
  for(let i=0;i<Math.max(current.length,minimum.length);i++){const a=current[i]||0,b=minimum[i]||0;if(a>b)break;if(a<b)throw new Error('native_os_version_unsupported');}
 }
 verify(path.join(nativeRoot(),selected.role.root),selected.role);
 return {command:selected.command,args:[],version:selected.artifact.version};
}
/** Change process role only for the exact paired artifact in this package. */
export function nativeMediaLaunch<T extends {command:string;args:readonly string[]}>(launch:T):T {
 let control;
 try{control=selection(process.platform,process.arch,'control');}
 catch(error){if((error as Error).message==='native_artifact_unqualified')return launch;throw error;}
 if(path.resolve(launch.command)!==control.command||launch.args.length)return launch;
 const source=nativeHelper(process.platform,process.arch,'control'),view=nativeHelper(process.platform,process.arch,'view');
 if(source.version!==view.version)throw new Error('native_artifact_version_mismatch');
 return {...launch,command:view.command};
}
export function verifyNativeHelper(destination:string,platform=process.platform,arch=process.arch,role='control'):void {
 const selected=selection(platform,arch,role),parts=selected.role.executable.split('/');
 let root=destination;for(const _part of parts)root=path.dirname(root);
 verify(root,selected.role);
}
