"""Owned editor-host file protocol. No installation in the owner's extension profile."""
import hashlib,json,os,time,uuid
from pathlib import Path
from cua_runtime_deploy import atomic_json
from cua_universal_fastpath import UniversalFastPath,FastPathError

def prepare_extension(root,document):
    root=Path(root);extension=root/'editor-extension';channel=root/'editor-channel'
    extension.mkdir();channel.mkdir();nonce=uuid.uuid4().hex
    code=(Path(__file__).resolve().parent/'cua_vscode_extension.cjs').read_bytes()
    (extension/'extension.cjs').write_bytes(code)
    atomic_json(extension/'package.json',{'name':'ffbridge-owned-editor','publisher':'ffbridge-local','version':'0.0.1',
        'engines':{'vscode':'^1.90.0'},'activationEvents':['onStartupFinished'],'main':'./extension.cjs',
        'capabilities':{'untrustedWorkspaces':{'supported':True}}})
    atomic_json(channel/'owner.json',{'protocol':1,'nonce':nonce,'document':str(Path(document).resolve(strict=True))})
    return {'extension':str(extension),'channel':str(channel),'nonce':nonce,'document':str(Path(document).resolve()),
            'extension_sha256':hashlib.sha256(code).hexdigest()}

def host_request(config,discovery,command,**args):
    fp=UniversalFastPath();channel=Path(config['channel']);deadline=time.monotonic()+20;sent=False
    def valid():
        if not fp._cached_discovery_valid(discovery) or not fp._panel_owner_valid(discovery):
            raise FastPathError('STALE_TARGET',{'attempted':sent and command!='observe','retry_safe':not sent})
    if command not in ('observe','replace_save'):raise FastPathError('EDITOR_COMMAND_UNSUPPORTED',{'attempted':False})
    if command=='replace_save' and any(not p.with_name(p.name.replace('.claim.json','.result.json')).exists() for p in channel.glob('*.claim.json')):
        raise FastPathError('EDITOR_PENDING_OUTCOME_UNKNOWN',{'attempted':False,'retry_safe':False})
    files=list(channel.iterdir())
    if len(files)>512 or sum(p.stat().st_size for p in files if p.is_file())>8*1024*1024:
        raise FastPathError('EDITOR_CHANNEL_LIMIT',{'attempted':False})
    valid()
    while not (channel/'ready.json').exists():
        if time.monotonic()>deadline:raise FastPathError('EDITOR_NATIVE_HOST_NOT_READY',{'attempted':False})
        time.sleep(.1)
    ready=json.loads((channel/'ready.json').read_bytes());assert ready['nonce']==config['nonce'] and ready['protocol']==1
    identity=fp._process_identity(ready['pid']);owner=discovery['cdp']['owner_identity']
    if not identity or ready['pid'] not in fp._child_process_ids(owner['pid']):
        raise FastPathError('EDITOR_NATIVE_HOST_NOT_OWNED',{'attempted':False})
    if 'host_identity' in config and config['host_identity']!=identity:
        raise FastPathError('EDITOR_NATIVE_HOST_IDENTITY_CHANGED',{'attempted':False})
    config['host_identity']=identity
    key=uuid.uuid4().hex;payload={'nonce':config['nonce'],'document':config['document'],'command':command,**args}
    packet=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    # The extension fingerprints exact input bytes. Atomic same-directory rename publishes once.
    if len(packet)>262144:raise FastPathError('EDITOR_PACKET_LIMIT',{'attempted':False})
    temp=channel/(key+'.tmp')
    with temp.open('xb') as stream:
        stream.write(packet);stream.flush();os.fsync(stream.fileno())
    temp.replace(channel/(key+'.request.json'));sent=True
    deadline=time.monotonic()+20;result=channel/(key+'.result.json')
    while not result.exists():
        if fp._process_identity(ready['pid'])!=identity or time.monotonic()>deadline:
            raise FastPathError('EDITOR_NATIVE_OUTCOME_UNKNOWN',{'request_id':key,'attempted':command!='observe','retry_safe':False})
        time.sleep(.05)
    reply=json.loads(result.read_bytes());valid()
    if fp._process_identity(ready['pid'])!=identity or reply.get('id')!=key or reply.get('fingerprint')!=hashlib.sha256(packet).hexdigest():
        raise FastPathError('EDITOR_NATIVE_REPLY_IDENTITY_INVALID',{'attempted':command!='observe','retry_safe':False})
    if not reply['ok']:raise FastPathError(reply['error_code'],{'attempted':reply.get('attempted',command!='observe'),'retry_safe':reply.get('retry_safe',False),'request_id':key})
    return {**reply,'host_identity':identity,'extension_sha256':config['extension_sha256'],'physical_input_used':False}
