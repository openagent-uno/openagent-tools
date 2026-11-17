"""Assemble immutable native target inventories without rebuilding or re-signing."""
from pathlib import Path
import argparse, hashlib, json, shutil, stat

TARGETS={f'{os}-{arch}' for os in ('darwin','linux','win32') for arch in ('arm64','x64')}
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def confined(value):return isinstance(value,str) and value and not value.startswith('/') and all(part not in {'','.','..'} for part in value.split('/'))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts',type=Path);parser.add_argument('output',type=Path);parser.add_argument('--source',required=True)
    args=parser.parse_args();assert not args.output.exists(),'Use an empty output directory'
    manifests={};notices=None;payloads={}
    for manifest in args.artifacts.rglob('manifest.json'):
        data=json.loads(manifest.read_text());assert data['protocol']=='openagent-native-artifacts/2'
        assert len(data['artifacts'])==1
        target,artifact=next(iter(data['artifacts'].items()));assert target in TARGETS and target not in manifests
        assert artifact['source_revision']==args.source and artifact['version']=='0.1.7'
        assert set(artifact['roles'])=={'control','view'}
        for role in artifact['roles'].values():
            assert confined(role['root']) and role['root'].startswith(target+'/') or role['root']==target
            assert confined(role['executable']) and role['executable'] in role['files']
            root=manifest.parent/role['root'];entries=list(root.rglob('*'));assert not any(path.is_symlink() for path in entries)
            actual={path.relative_to(root).as_posix():digest(path) for path in entries if path.is_file()}
            assert actual==role['files'],'Native inventory changed in artifact transport'
        notice=(manifest.parent/'THIRD_PARTY_NOTICES.txt').read_bytes().replace(b'\r\n',b'\n')
        if notices is None:notices=notice
        assert notice==notices,'Native dependency notices differ across targets'
        manifests[target]=artifact;payloads[target]=manifest.parent/target
    assert set(manifests)==TARGETS,'All six qualified targets are required'
    args.output.mkdir(parents=True)
    for target,source in payloads.items():
        shutil.copytree(source,args.output/target)
        if not target.startswith('win32-'):
            for role in manifests[target]['roles'].values():(args.output/role['root']/role['executable']).chmod(0o755)
    (args.output/'THIRD_PARTY_NOTICES.txt').write_bytes(notices)
    (args.output/'manifest.json').write_text(json.dumps({'protocol':'openagent-native-artifacts/2','artifacts':manifests},indent=2)+'\n')
    print('Assembled six verified native target inventories')
if __name__=='__main__':main()
