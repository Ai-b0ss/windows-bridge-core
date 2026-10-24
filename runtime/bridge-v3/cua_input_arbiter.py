from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any
import json, os, threading, time, uuid

class ArbiterError(RuntimeError):
    def __init__(self, code: str, details: Optional[dict[str, Any]] = None):
        super().__init__(code); self.code=code; self.details=details or {}

@dataclass(frozen=True)
class TargetFingerprint:
    hwnd: int
    pid: int
    process_start_ns: int
    rect: tuple[int,int,int,int]
    generation: int

@dataclass
class InputLease:
    lease_id: str
    owner_id: str
    sequence_id: str
    target: TargetFingerprint
    issued_ns: int
    expires_ns: int
    quiet_since_ns: int
    baseline_foreground: int
    baseline_cursor: tuple[int,int]
    owner_event_generation: int
    foreground_generation: int

class FileLeaseStore:
    """Cross-process fail-closed lease with a tiny atomic metadata guard."""
    def __init__(self, path: str | os.PathLike[str], clock_ns=time.monotonic_ns, guard_ttl_ms=2000):
        self.path=Path(path); self.clock_ns=clock_ns
        self.guard_path=self.path.with_suffix(self.path.suffix+'.guard')
        self.guard_ttl_ns=int(guard_ttl_ms*1e6)
        self.guard_clock_ns=time.monotonic_ns

    def _enter_guard(self) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        token=uuid.uuid4().hex
        permission_failure = None
        for _ in range(8):
            now=self.guard_clock_ns()
            payload=json.dumps({'token':token,'expires_ns':now+self.guard_ttl_ns},separators=(',',':'))
            try:
                fd=os.open(self.guard_path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
                with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(payload)
                return token
            except PermissionError as exc:
                # Windows CRT can report EACCES while the previous guard is
                # delete-pending. Retry only this metadata acquisition, never
                # input or a lease operation. Persistent denial stays closed.
                permission_failure = exc
                time.sleep(0.005)
            except FileExistsError:
                permission_failure = None
                try:
                    existing=json.loads(self.guard_path.read_text(encoding='utf-8'))
                    if int(existing.get('expires_ns',0)) <= now:
                        self.guard_path.unlink(missing_ok=True)
                        continue
                except Exception:
                    pass
                time.sleep(0.005)
        if permission_failure is not None:
            raise ArbiterError('LEASE_STORE_GUARD_UNAVAILABLE',
                {'retry_safe': False, 'errno': permission_failure.errno,
                 'winerror': getattr(permission_failure, 'winerror', None)}) from permission_failure
        raise ArbiterError('LEASE_STORE_BUSY')

    def _leave_guard(self, token: str) -> None:
        # On Windows another contender can have the guard file briefly open for read,
        # making unlink fail with PermissionError. Retry boundedly; leaving a guard
        # behind would otherwise block the winner from releasing its lease.
        for _ in range(20):
            try:
                cur=json.loads(self.guard_path.read_text(encoding='utf-8'))
                if cur.get('token') != token:
                    return
                self.guard_path.unlink(missing_ok=True)
                return
            except FileNotFoundError:
                return
            except PermissionError:
                time.sleep(0.002)
            except json.JSONDecodeError:
                time.sleep(0.002)
            except OSError:
                time.sleep(0.002)
        raise ArbiterError('LEASE_STORE_GUARD_RELEASE_FAILED')

    def acquire(self, payload: dict[str,Any]) -> None:
        token=self._enter_guard()
        try:
            existing=self._read_unlocked()
            if existing and int(existing.get('expires_ns',0)) > self.clock_ns():
                raise ArbiterError('PHYSICAL_INPUT_BUSY')
            if existing:
                self.path.unlink(missing_ok=True)
            raw=json.dumps(payload,separators=(',',':'),sort_keys=True)
            fd=os.open(self.path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(raw)
        finally:
            self._leave_guard(token)

    def heartbeat(self, lease_id: str, expires_ns: int) -> None:
        token=self._enter_guard()
        try:
            cur=self._read_unlocked()
            if not cur or cur.get('lease_id') != lease_id: raise ArbiterError('LEASE_LOST')
            if int(cur.get('expires_ns',0)) <= self.clock_ns(): raise ArbiterError('LEASE_EXPIRED')
            cur['expires_ns']=int(expires_ns)
            tmp=self.path.with_suffix(self.path.suffix+'.tmp-'+uuid.uuid4().hex)
            tmp.write_text(json.dumps(cur,separators=(',',':'),sort_keys=True),encoding='utf-8')
            os.replace(tmp,self.path)
        finally:
            self._leave_guard(token)

    def release(self, lease_id: str) -> None:
        token=self._enter_guard()
        try:
            cur=self._read_unlocked()
            if cur and cur.get('lease_id') == lease_id: self.path.unlink(missing_ok=True)
        finally:
            self._leave_guard(token)

    def _read_unlocked(self) -> Optional[dict[str,Any]]:
        try: return json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError: return None
        except Exception: raise ArbiterError('LEASE_STORE_CORRUPT')

    def read(self) -> Optional[dict[str,Any]]:
        token=self._enter_guard()
        try: return self._read_unlocked()
        finally: self._leave_guard(token)

class HumanInputArbiter:
    def __init__(self, store: FileLeaseStore, quiet_window_ms=500, lease_ttl_ms=1500, clock_ns=time.monotonic_ns):
        self.store=store; self.quiet_ns=int(quiet_window_ms*1e6); self.ttl_ns=int(lease_ttl_ms*1e6); self.clock_ns=clock_ns
        self._lock=threading.RLock()
        self.owner_event_generation=0; self.foreground_generation=0
        self.last_owner_input_ns=0; self.foreground_hwnd=0; self.cursor=(0,0)
        self.active: dict[str,InputLease]={}
        self.aborted: dict[str,str]={}

    def observe_owner_input(self, source: str='raw_input', *, now_ns: Optional[int]=None) -> None:
        """Record owner activity; accepts positional source for event-source callbacks."""
        if source == 'synthetic': return
        with self._lock:
            self.owner_event_generation += 1
            self.last_owner_input_ns = self.clock_ns() if now_ns is None else now_ns
            for lease_id in list(self.active): self.aborted.setdefault(lease_id,'USER_ACTIVE')

    def observe_foreground(self, hwnd: int) -> None:
        with self._lock:
            if hwnd != self.foreground_hwnd:
                self.foreground_hwnd=hwnd; self.foreground_generation += 1
                for lease_id, lease in list(self.active.items()):
                    if hwnd != lease.target.hwnd: self.aborted.setdefault(lease_id,'FOREGROUND_CHANGED')

    def observe_cursor(self, x:int,y:int) -> None:
        with self._lock: self.cursor=(x,y)

    def acquire(self, owner_id: str, target: TargetFingerprint, *, expected_foreground: int) -> InputLease:
        now=self.clock_ns()
        with self._lock:
            if self.last_owner_input_ns and now-self.last_owner_input_ns < self.quiet_ns:
                raise ArbiterError('USER_ACTIVE')
            if self.foreground_hwnd != expected_foreground or expected_foreground != target.hwnd:
                raise ArbiterError('TARGET_NOT_FOREGROUND', {'foreground':self.foreground_hwnd,'target':target.hwnd})
            lease=InputLease(uuid.uuid4().hex, owner_id, uuid.uuid4().hex, target, now, now+self.ttl_ns,
                             self.last_owner_input_ns, self.foreground_hwnd, self.cursor,
                             self.owner_event_generation, self.foreground_generation)
            self.store.acquire({
                'lease_id':lease.lease_id,'owner_id':owner_id,'sequence_id':lease.sequence_id,
                'expires_ns':lease.expires_ns,'target_hwnd':target.hwnd,'target_pid':target.pid})
            self.active[lease.lease_id]=lease
            return lease

    def heartbeat(self, lease_id: str) -> None:
        with self._lock:
            lease=self._require(lease_id); self._validate_common(lease)
            lease.expires_ns=self.clock_ns()+self.ttl_ns
            self.store.heartbeat(lease_id, lease.expires_ns)

    def focus_transition(self, owner_id, target, *, foreground_provider, focus, target_provider,
                         activation_fallback=None):
        """Reserve focus/input while activating the exact authorized target.

        The optional fallback is an ordinary marked caption click. Its guard
        checks the same owner generation, target and foreground before input.
        Mouse inactivity never supplies authorization.
        """
        now = self.clock_ns()
        expires = now + self.ttl_ns
        with self._lock:
            if self.last_owner_input_ns and now-self.last_owner_input_ns < self.quiet_ns:
                raise ArbiterError('USER_ACTIVE')
            owner_generation = self.owner_event_generation
            old_foreground = foreground_provider()
            lease_id = uuid.uuid4().hex
            self.store.acquire({'lease_id':lease_id,'owner_id':owner_id,'expires_ns':expires,
                                'target_hwnd':target.hwnd,'target_pid':target.pid})
        def before_activation():
            if self.clock_ns() >= expires:
                raise ArbiterError('LEASE_EXPIRED', {'retry_safe':False})
            if target_provider() != target:
                raise ArbiterError('TARGET_MOVED', {'retry_safe':False})
            if foreground_provider() != old_foreground:
                raise ArbiterError('FOREGROUND_CHANGED', {'retry_safe':False})
            with self._lock:
                if self.owner_event_generation != owner_generation:
                    raise ArbiterError('USER_ACTIVE', {'retry_safe':False})
        try:
            before_activation()
            activation = None
            try:
                focus(target.hwnd)
            except Exception as exc:
                if getattr(exc, 'code', None) != 'FOCUS_NOT_GRANTED_BY_WINDOWS' or activation_fallback is None:
                    raise
                before_activation()
                activation = activation_fallback(target.hwnd, before_activation)
            with self._lock:
                if self.owner_event_generation != owner_generation:
                    raise ArbiterError('USER_ACTIVE', {'retry_safe':False,'focus_effect_possible':True})
            # Windows activation may be queued to another UI thread and
            # GetForegroundWindow can transiently return zero. Wait for the
            # actual postcondition, while preserving target/owner/lease guards.
            deadline = min(expires, self.clock_ns()+250_000_000)
            wall_deadline = time.monotonic()+0.25
            while True:
                with self._lock:
                    if self.owner_event_generation != owner_generation:
                        raise ArbiterError('USER_ACTIVE', {'retry_safe':False,'focus_effect_possible':True})
                actual_foreground = foreground_provider()
                actual_target = target_provider()
                if actual_target == target and actual_foreground == target.hwnd:
                    break
                if actual_target != target or actual_foreground not in (0, old_foreground) or self.clock_ns() >= deadline or time.monotonic() >= wall_deadline:
                    raise ArbiterError('FOCUS_POSTCONDITION_FAILED',
                        {'retry_safe':False, 'expected_foreground':target.hwnd,
                         'actual_foreground':actual_foreground, 'target_changed':actual_target != target,
                         'target_rect_before':list(target.rect), 'target_rect_after':list(actual_target.rect)})
                time.sleep(0.005)
            result = {'ok':True,'verified':True,'foreground_before':old_foreground,
                      'foreground_after':target.hwnd,'lease_id':lease_id,
                      'physical_input_used':activation is not None}
            if isinstance(activation, dict):
                result.update(activation)
            return result
        finally:
            self.store.release(lease_id)

    def validate_before_event(self, lease_id: str, current_target: TargetFingerprint, *, current_foreground: int) -> dict[str,Any]:
        with self._lock:
            lease=self._require(lease_id); self._validate_common(lease)
            if current_target != lease.target:
                self._abort(lease_id,'TARGET_MOVED'); raise ArbiterError('TARGET_MOVED')
            if current_foreground != lease.target.hwnd or self.foreground_hwnd != lease.target.hwnd:
                self._abort(lease_id,'FOREGROUND_CHANGED'); raise ArbiterError('FOREGROUND_CHANGED')
            return {'ok':True,'lease_id':lease_id,'sequence_id':lease.sequence_id,'owner_event_generation':self.owner_event_generation}

    def execute_sequence(self, lease_id: str, events: list[dict[str,Any]], *, target_provider, foreground_provider, sink) -> dict[str,Any]:
        """Validate again before every physical event; stop before the next event on interference."""
        sent = 0
        for event in events:
            try:
                current_target = target_provider()
                current_foreground = int(foreground_provider())
            except Exception as exc:
                code = str(getattr(exc, 'code', 'PHYSICAL_GUARD_UNAVAILABLE'))
                self.aborted.setdefault(lease_id, code)
                return {
                    'ok': False, 'sent': sent, 'aborted': True,
                    'error_code': code, 'physical_effect_unknown': False,
                    'retry_safe': False, 'guard_error': f'{type(exc).__name__}: {exc}',
                }
            try:
                self.validate_before_event(lease_id, current_target, current_foreground=current_foreground)
            except ArbiterError as exc:
                self.aborted.setdefault(lease_id, exc.code)
                return {'ok': False, 'sent': sent, 'aborted': True, 'error_code': exc.code}
            try:
                sink(event)
            except Exception as exc:
                self.aborted.setdefault(lease_id, 'PHYSICAL_SINK_ERROR')
                return {
                    'ok': False, 'sent': sent, 'aborted': True,
                    'error_code': 'PHYSICAL_SINK_ERROR',
                    'physical_effect_unknown': True, 'retry_safe': False,
                    'sink_error': f'{type(exc).__name__}: {exc}',
                }
            sent += 1
        return {'ok': True, 'sent': sent, 'aborted': False}

    def finish(self, lease_id: str, *, verified: bool, foreground_after: int, cursor_after: tuple[int,int]) -> dict[str,Any]:
        with self._lock:
            lease=self._require(lease_id)
            reason=self.aborted.get(lease_id)
            receipt={
                'route':'PHYSICAL_INPUT','lease_id':lease_id,'sequence_id':lease.sequence_id,
                'target_hwnd':lease.target.hwnd,'verified':bool(verified and not reason),
                'aborted':bool(reason),'abort_reason':reason,
                'focus_preserved':foreground_after==lease.baseline_foreground,
                'cursor_preserved':cursor_after==lease.baseline_cursor,
                'owner_event_generation_before':lease.owner_event_generation,
                'owner_event_generation_after':self.owner_event_generation,
            }
            self.store.release(lease_id); self.active.pop(lease_id,None); self.aborted.pop(lease_id,None)
            return receipt

    def abort(self, lease_id: str, reason='ABORTED') -> None:
        with self._lock:
            self._abort(lease_id,reason)
            self.store.release(lease_id); self.active.pop(lease_id,None)

    def get_active_lease(self, lease_id: str) -> InputLease:
        with self._lock:
            lease=self._require(lease_id)
            self._validate_common(lease)
            return lease

    def _require(self, lease_id: str) -> InputLease:
        lease=self.active.get(lease_id)
        if not lease: raise ArbiterError('LEASE_NOT_FOUND')
        return lease

    def _validate_common(self, lease: InputLease) -> None:
        now=self.clock_ns()
        if now >= lease.expires_ns:
            self._abort(lease.lease_id,'LEASE_EXPIRED'); raise ArbiterError('LEASE_EXPIRED')
        reason=self.aborted.get(lease.lease_id)
        if reason: raise ArbiterError(reason)
        if self.owner_event_generation != lease.owner_event_generation:
            self._abort(lease.lease_id,'USER_ACTIVE'); raise ArbiterError('USER_ACTIVE')
        if self.foreground_generation != lease.foreground_generation and self.foreground_hwnd != lease.target.hwnd:
            self._abort(lease.lease_id,'FOREGROUND_CHANGED'); raise ArbiterError('FOREGROUND_CHANGED')

    def _abort(self, lease_id: str, reason: str) -> None:
        self.aborted.setdefault(lease_id,reason)
