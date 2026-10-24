"""Own isolated-browser profile trees and reclaim only verifiably dead owners."""
from pathlib import Path
import json,os,re,shutil,stat,time,uuid
from cua_global_resources import _StateLock,process_creation_identity,process_is_same
WORKER=re.compile(r"worker-[0-9a-f]{32}$")
def linked(path):
    return path.is_symlink() or getattr(path,"is_junction",lambda:False)()
def _remove_owned_tree_once(candidate,owner):
    from cua_windows_paths import extended_path
    def retry_readonly(function,name,error):
        item=Path(name)
        if not isinstance(error,PermissionError) or linked(item):
            raise error
        info=item.stat()
        if not getattr(info,"st_file_attributes",0)&1:
            raise error # A sharing lock or ACL failure must stay visible.
        item.chmod(stat.S_IWRITE)
        function(name)
    try:
        # Short roots can have long descendants; rmtree derives every child
        # name from the root, so recursive removal must force the prefix.
        shutil.rmtree(extended_path(candidate,force=True),onexc=retry_readonly)
    except OSError:
        # rmtree can remove the marker before reaching a locked file.
        # Preserve ownership so a later start can retry the incomplete cleanup.
        if candidate.is_dir() and not linked(candidate) and not linked(candidate/"owner.json") and not (candidate/"owner.json").exists():
            (candidate/"owner.json").write_text(json.dumps(owner),encoding="utf-8")
        raise

def remove_owned_tree(candidate,owner):
    for attempt in range(11):
        try:
            _remove_owned_tree_once(candidate,owner)
            return attempt+1
        except PermissionError:
            if attempt==10:raise
            time.sleep(.2) # Windows may release cache mappings shortly after process exit.

class ManagedBrowserProfiles:
    def __init__(self,state_dir):
        # The Node sidecar has a different cwd. Never hand it a relative path
        # created relative to the Python process's cwd (otherwise attach ENOENT).
        from cua_windows_paths import extended_path
        self.root=extended_path(Path(state_dir).absolute()/"isolated-browser-profiles")
        if linked(self.root):
            raise OSError("ISOLATED_PROFILE_ROOT_LINK_FORBIDDEN")
        self.root.mkdir(parents=True,exist_ok=True)
        self.owner={"schema":1,"kind":"ff-isolated-browser-worker","pid":os.getpid(),
                    "creation":process_creation_identity(),"nonce":uuid.uuid4().hex}
        self.path=extended_path(self.root/("worker-"+self.owner["nonce"]))
        self.reclaimed=0
        self.cleanup_errors=[]
        self.cleanup_attempts={}
        with _StateLock(self.root/"profiles.lock"):
            for candidate in self.root.iterdir():
                if not WORKER.fullmatch(candidate.name) or linked(candidate) or not candidate.is_dir():
                    continue
                owner=self._read_owner(candidate)
                if owner is None or process_is_same(owner["pid"],owner["creation"]):
                    continue
                try:
                    self.cleanup_attempts[candidate.name]=remove_owned_tree(candidate,owner)
                    self.reclaimed+=1
                except OSError as exc:
                    self.cleanup_errors.append({"worker":candidate.name,"winerror":getattr(exc,"winerror",None),
                                                "error":str(exc)})
            self.path.mkdir()
            try:
                (self.path/"owner.json").write_text(json.dumps(self.owner),encoding="utf-8")
            except Exception:
                self.path.rmdir()
                raise
    @staticmethod
    def _read_owner(candidate):
        from cua_windows_paths import extended_path
        marker=extended_path(candidate/"owner.json")
        try:
            if linked(marker) or marker.stat().st_size>4096:
                return None
            owner=json.loads(marker.read_text(encoding="utf-8"))
            if (not isinstance(owner,dict) or owner.get("schema")!=1 or
                owner.get("kind")!="ff-isolated-browser-worker" or
                type(owner.get("pid")) is not int or owner["pid"]<=0 or
                not isinstance(owner.get("creation"),str) or not re.fullmatch(r"(?:win|proc):[0-9]+",owner["creation"]) or
                candidate.name!="worker-"+str(owner.get("nonce"))):
                return None
            return owner
        except (OSError,ValueError):
            return None
    def close(self):
        with _StateLock(self.root/"profiles.lock"):
            if linked(self.path) or self._read_owner(self.path)!=self.owner:
                return False
            remove_owned_tree(self.path,self.owner)
            return True
