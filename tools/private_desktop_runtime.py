"""Install/update/rollback an independent private-desktop Hub without touching the shared Bridge.

SHA-verified source ZIP, immutable release dirs, atomic active config, idle-only stop.
"""
import argparse,hashlib,json,os,subprocess,sys,time,uuid,zipfile,shutil
from pathlib import Path

def digest(data):return hashlib.sha256(data).hexdigest()
def write(path,value):
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp');tmp.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');os.replace(tmp,path)
def owned(home,create=False):
    home=home.resolve()
    if any(p.is_symlink() or getattr(p,'is_junction',lambda:False)() for p in [home,*home.parents]):raise RuntimeError('HOME_LINK_FORBIDDEN')
    marker=home/'private-runtime-owner.json'
    if not marker.exists():
        if not create or (home.exists() and any(home.iterdir())):raise RuntimeError('HOME_NOT_OWNED')
        home.mkdir(parents=True,exist_ok=True);write(marker,{'schema':'ff-private-runtime-home-v1','id':uuid.uuid4().hex})
    if json.loads(marker.read_text()).get('schema')!='ff-private-runtime-home-v1':raise RuntimeError('HOME_OWNER_INVALID')
    return home
def config(home):return json.loads((home/'active.json').read_text())
def modules(home,cfg):
    release=home/'releases'/cfg['release']
    if release.resolve().parent!=(home/'releases').resolve():raise RuntimeError('RELEASE_PATH_INVALID')
    manifest=json.loads((release/'install-manifest.json').read_text())
    for name,sha in manifest['files'].items():
        path=release/name
        if path.is_symlink() or digest(path.read_bytes())!=sha:raise RuntimeError('INSTALLED_HASH_MISMATCH')
    sys.path.insert(0,str(release/'runtime/bridge-v3'))
    from ff_hub import HubClient,HubError,ensure_running
    return release,HubClient,HubError,ensure_running
def stop(home,cfg):
    _,Client,Error,_=modules(home,cfg);client=Client(home/'state/hub',timeout=5)
    try:client.endpoint()
    except Error as exc:
        if exc.code=='HUB_NOT_RUNNING':return
        raise
    client.call('hub_shutdown_idle')
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try:client.endpoint()
        except Error as exc:
            if exc.code=='HUB_NOT_RUNNING':return
            raise
        time.sleep(.1)
    raise RuntimeError('IDLE_STOP_TIMEOUT')
def install(home,source,sha):
    raw=source.read_bytes()
    if digest(raw)!=sha:raise RuntimeError('SOURCE_ZIP_HASH_MISMATCH')
    home=owned(home,True);previous=config(home) if (home/'active.json').exists() else None
    release_id=sha[:20];releases=home/'releases';releases.mkdir(exist_ok=True);target=releases/release_id
    with zipfile.ZipFile(source) as z:
        if z.testzip():raise RuntimeError('SOURCE_ZIP_CRC_FAILED')
        names=[i for i in z.infolist() if not i.is_dir()]
        if sum(i.file_size for i in names)>64000000:raise RuntimeError('SOURCE_ZIP_TOO_LARGE')
        for entry in names:
            name=Path(entry.filename)
            if name.is_absolute() or '..' in name.parts or ':' in entry.filename or '\\' in entry.filename or (entry.external_attr>>16)&0o170000==0o120000:raise RuntimeError('SOURCE_ZIP_PATH_INVALID')
        expected=json.loads(z.read('release-manifest.json'))['files']
        hashes={i.filename:digest(z.read(i)) for i in names}
        for name,value in hashes.items():
            if name.startswith('runtime/') and expected.get(name)!=value:raise RuntimeError('SOURCE_MANIFEST_MISMATCH')
        if 'runtime/bridge-v3/cua_private_browser.py' not in hashes:raise RuntimeError('SOURCE_PRIVATE_API_MISSING')
        if not target.exists():
            stage=releases/('.stage-'+uuid.uuid4().hex);stage.mkdir()
            for entry in names:
                path=stage/entry.filename;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(z.read(entry))
            write(stage/'install-manifest.json',{'source_zip_sha256':sha,'files':hashes})
            assert stage.resolve().is_relative_to(home) and target.resolve().is_relative_to(home)
            os.replace(stage,target)
    if previous:stop(home,previous)
    cfg={'schema':1,'release':release_id,'previous_release':previous['release'] if previous else None,'python':sys.executable,'source_zip_sha256':sha}
    write(home/'active.json',cfg);state=home/'state/hub';state.mkdir(parents=True,exist_ok=True)
    if not (state/'config.json').exists():write(state/'config.json',{'port':0})
    return {'installed':True,'release':release_id,'previous_release':cfg['previous_release']}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--home',type=Path,required=True);sub=p.add_subparsers(dest='command',required=True)
    add=sub.add_parser('install');add.add_argument('--source-zip',type=Path,required=True);add.add_argument('--sha256',required=True)
    sub.add_parser('start');sub.add_parser('status');sub.add_parser('stop');sub.add_parser('rollback');sub.add_parser('doctor')
    sub.add_parser('enable-autostart');sub.add_parser('disable-autostart')
    grant=sub.add_parser('grant-apps');grant.add_argument('--agent',required=True);grant.add_argument('--apps',required=True)
    a=p.parse_args()
    try:
        if a.command=='install':result=install(a.home,a.source_zip,a.sha256)
        else:
            home=owned(a.home);cfg=config(home)
            if a.command=='rollback':
                if not cfg.get('previous_release'):raise RuntimeError('NO_PREVIOUS_RELEASE')
                stop(home,cfg);cfg['release'],cfg['previous_release']=cfg['previous_release'],cfg['release'];cfg['source_zip_sha256']=json.loads((home/'releases'/cfg['release']/'install-manifest.json').read_text())['source_zip_sha256'];write(home/'active.json',cfg);result={'rolled_back':True,'release':cfg['release']}
            elif a.command=='stop':stop(home,cfg);result={'stopped':True}
            else:
                release,Client,Error,start=modules(home,cfg)
                if a.command=='start':
                    os.environ['FF_BRIDGE_ROOT']=str(home/'state/runtime');endpoint=start(home/'state/hub');result={'running':True,'pid':endpoint['pid'],'port':endpoint['port'],'release':cfg['release']}
                elif a.command in {'enable-autostart','disable-autostart'}:
                    import winreg
                    marker=json.loads((home/'private-runtime-owner.json').read_text());name='FFPrivateDesktop-'+marker['id'];record=home/'autostart.json'
                    pythonw=Path(cfg['python']).with_name('pythonw.exe')
                    if not pythonw.is_file():raise RuntimeError('PYTHONW_REQUIRED_FOR_HIDDEN_AUTOSTART')
                    command=subprocess.list2cmdline([str(pythonw),str(release/'tools/private_desktop_runtime.py'),'--home',str(home),'start'])
                    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run') as key:
                        try:current=winreg.QueryValueEx(key,name)[0]
                        except FileNotFoundError:current=None
                        saved=json.loads(record.read_text()) if record.exists() else {}
                        if current is not None and current not in {command,saved.get('command')}:raise RuntimeError('AUTOSTART_OWNER_CHANGED')
                        if a.command=='enable-autostart':
                            winreg.SetValueEx(key,name,0,winreg.REG_SZ,command)
                            if winreg.QueryValueEx(key,name)[0]!=command:raise RuntimeError('AUTOSTART_READBACK_FAILED')
                            write(record,{'name':name,'command':command});result={'registered':True,'readback_verified':True,'actual_reboot_verified':False,'scope':'HKCU login only'}
                        else:
                            if current is not None:winreg.DeleteValue(key,name)
                            result={'registered':False,'removed_only_owned_entry':True}
                elif a.command=='doctor':
                    from cua_hidden_chrome import chrome_path
                    try:state=Client(home/'state/hub',timeout=3).call('hub_status')
                    except Error:state={'running':False}
                    result={'installed_hashes_verified':True,'release':cfg['release'],'chrome_installed':chrome_path() is not None,'free_bytes':shutil.disk_usage(home).free,'hub':state,'autostart_config_recorded':(home/'autostart.json').exists(),'reboot_recovery_verified':False}
                elif a.command=='grant-apps':
                    from ff_hub_permissions import Policy
                    result=Policy(home/'state/hub/policy.json').add_grant(['app_launch'],agents=[a.agent],apps=a.apps.split(','),note='Local owner-authorized private runtime apps')
                else:result=Client(home/'state/hub',timeout=5).call('hub_status')
        print(json.dumps(result,ensure_ascii=False,default=str));return 0
    except Exception as exc:
        print(json.dumps({'error_code':getattr(exc,'code',str(exc)),'automatic_replay':False}));return 1
if __name__=='__main__':raise SystemExit(main())
