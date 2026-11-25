"""Own isolated-browser profile trees, persistent isolated profiles, and fail-closed owner-profile guards."""
from __future__ import annotations

from pathlib import Path
import json
import os
import re
import shutil
import stat
import time
import uuid

from cua_global_resources import _StateLock, process_creation_identity, process_is_same
from cua_windows_paths import expand_windows_short_path

WORKER = re.compile(r"worker-[0-9a-f]{32}$")
PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_WINDOWS_DEVICE_RE = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)")
PERSISTENT_OWNER_KIND = "ff-persistent-browser-profile"

_OWNER_LOCALAPPDATA_SUBPATHS = (
    ("Google", "Chrome", "User Data"),
    ("Google", "Chrome Beta", "User Data"),
    ("Google", "Chrome SxS", "User Data"),
    ("Google", "Chrome Dev", "User Data"),
    ("Chromium", "User Data"),
    ("Microsoft", "Edge", "User Data"),
    ("Microsoft", "Edge Beta", "User Data"),
    ("Microsoft", "Edge Dev", "User Data"),
    ("Microsoft", "Edge SxS", "User Data"),
    ("BraveSoftware", "Brave-Browser", "User Data"),
    ("Vivaldi", "User Data"),
    ("Opera Software",),
    ("Mozilla", "Firefox"),
    ("Yandex", "YandexBrowser", "User Data"),
    ("Arc", "User Data"),
)

_OWNER_APPDATA_SUBPATHS = (
    ("Mozilla", "Firefox"),
    ("Opera Software",),
)

_OWNER_POSIX_SUBPATHS = (
    (".config", "google-chrome"),
    (".config", "google-chrome-beta"),
    (".config", "google-chrome-unstable"),
    (".config", "chromium"),
    (".config", "microsoft-edge"),
    (".config", "BraveSoftware", "Brave-Browser"),
    (".config", "vivaldi"),
    (".mozilla", "firefox"),
)

_OWNER_PROFILE_PATTERNS = (
    re.compile(r"(?i)(?:^|/)google/chrome(?:\s+(?:beta|dev|sxs))?/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)chromium/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)microsoft/edge(?:\s+(?:beta|dev|sxs))?/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)bravesoftware/brave-browser/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)vivaldi/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)yandex/yandexbrowser/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)arc/user data(?:/|$)"),
    re.compile(r"(?i)(?:^|/)opera software(?:/|$)"),
    re.compile(r"(?i)(?:^|/)mozilla/firefox(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.config/(?:google-chrome(?:-(?:beta|unstable))?|chromium|microsoft-edge|bravesoftware/brave-browser|vivaldi)(?:/|$)"),
    re.compile(r"(?i)(?:^|/)\.mozilla/firefox(?:/|$)"),
)

_CHROME_STALE_LOCKS = (
    "DevToolsActivePort",
    "SingletonLock",
    "SingletonSocket",
    "SingletonCookie",
)


class ProfileIsolationError(ValueError):
    def __init__(self, code: str, details: dict | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


def linked(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _strip_extended_prefix(raw: str) -> str:
    if raw[:8].upper() == "\\\\?\\UNC\\":
        return "\\\\" + raw[8:]
    if raw.startswith("\\\\?\\"):
        return raw[4:]
    return raw


def _norm_key(path: str | Path) -> str:
    cleaned = _strip_extended_prefix(str(path))
    return os.path.normcase(os.path.normpath(cleaned))


def _slash_norm(path: str | Path) -> str:
    return _strip_extended_prefix(str(path)).replace("\\", "/")


def _path_overlaps(a: str, b: str) -> bool:
    if not a or not b:
        return False
    a_clean = a.rstrip("\\/")
    b_clean = b.rstrip("\\/")
    if not a_clean or not b_clean:
        return True
    if a_clean == b_clean:
        return True
    sep = os.sep
    return a_clean.startswith(b_clean + sep) or b_clean.startswith(a_clean + sep)


def _owner_browser_roots() -> list[str]:
    roots: set[str] = set()
    local_bases: set[Path] = set()
    roaming_bases: set[Path] = set()
    home_bases: set[Path] = set()

    for key in ("USERPROFILE", "HOME"):
        val = os.environ.get(key)
        if val:
            home_bases.add(Path(val))
    try:
        home_bases.add(Path.home())
    except RuntimeError:
        pass

    local_env = os.environ.get("LOCALAPPDATA")
    if local_env:
        local_bases.add(Path(local_env))
    appdata_env = os.environ.get("APPDATA")
    if appdata_env:
        roaming_bases.add(Path(appdata_env))

    def _add_root(target: Path) -> None:
        roots.add(_norm_key(target))
        try:
            expanded = expand_windows_short_path(target)
            roots.add(_norm_key(expanded))
        except OSError:
            pass

    for home in home_bases:
        local_bases.add(home / "AppData" / "Local")
        roaming_bases.add(home / "AppData" / "Roaming")
        for sub in _OWNER_POSIX_SUBPATHS:
            _add_root(home.joinpath(*sub))

    for base in local_bases:
        for sub in _OWNER_LOCALAPPDATA_SUBPATHS:
            _add_root(base.joinpath(*sub))
    for base in roaming_bases:
        for sub in _OWNER_APPDATA_SUBPATHS:
            _add_root(base.joinpath(*sub))
    return sorted(roots)


def _has_traversal_segment(raw: str) -> bool:
    cleaned = _strip_extended_prefix(raw)
    return ".." in re.split(r"[\\/]+", cleaned)


def _check_no_links_on_path(candidate: Path) -> Path:
    """Reject any symlink or junction on candidate or its existing ancestors.

    Pure Windows 8.3 short paths (e.g. RUNNER~1 -> runneradmin) are canonicalized
    via GetLongPathNameW (which never follows symlinks, junctions, or SUBST) and
    verified against os.path.realpath so all link/reparse redirections still fail closed.
    """
    clean_path = Path(_strip_extended_prefix(str(candidate)))
    chain = list(reversed(clean_path.parents)) + [clean_path]
    deepest_existing: Path | None = None
    for part in chain:
        if linked(part):
            raise ProfileIsolationError("ISOLATED_PROFILE_LINK_FORBIDDEN", {"path": str(part)})
        try:
            exists = os.path.lexists(str(part))
        except OSError:
            exists = False
        if not exists:
            continue
        deepest_existing = part
    if deepest_existing is not None:
        long_anc = expand_windows_short_path(deepest_existing)
        if _norm_key(long_anc) != _norm_key(deepest_existing):
            for part in list(reversed(long_anc.parents)) + [long_anc]:
                if linked(part):
                    raise ProfileIsolationError("ISOLATED_PROFILE_LINK_FORBIDDEN", {"path": str(part)})
        real_anc = os.path.realpath(str(deepest_existing))
        if _norm_key(real_anc) != _norm_key(long_anc):
            if is_owner_browser_profile_path(real_anc):
                raise ProfileIsolationError("OWNER_BROWSER_PROFILE_FORBIDDEN", {"path": str(candidate)})
            raise ProfileIsolationError("ISOLATED_PROFILE_LINK_FORBIDDEN", {"path": str(deepest_existing)})
    return expand_windows_short_path(clean_path)


def is_owner_browser_profile_path(path: str | Path) -> bool:
    """Return True if path matches, is inside, or encloses an owner browser profile."""
    raw = str(path)
    if not raw or "\x00" in raw:
        return True
    candidates = [raw]
    stripped = _strip_extended_prefix(raw)
    try:
        candidates.append(os.path.abspath(stripped))
    except OSError:
        pass
    try:
        candidates.append(str(expand_windows_short_path(stripped)))
    except OSError:
        pass
    try:
        candidates.append(os.path.realpath(stripped))
    except OSError:
        pass
    owner_roots = _owner_browser_roots()
    for item in candidates:
        slash = _slash_norm(item)
        if any(pattern.search(slash) for pattern in _OWNER_PROFILE_PATTERNS):
            return True
        key = _norm_key(item)
        for root in owner_roots:
            if _path_overlaps(key, root):
                return True
    return False


def assert_not_owner_browser_profile(path: str | Path) -> Path:
    """Fail closed if path traverses, uses links, or overlaps any owner browser profile."""
    if not isinstance(path, (str, Path)):
        raise ProfileIsolationError("PROFILE_PATH_INVALID")
    raw = str(path)
    if not raw or "\x00" in raw:
        raise ProfileIsolationError("PROFILE_PATH_INVALID")
    if _has_traversal_segment(raw):
        raise ProfileIsolationError("PROFILE_PATH_TRAVERSAL", {"path": raw})
    if is_owner_browser_profile_path(raw):
        raise ProfileIsolationError("OWNER_BROWSER_PROFILE_FORBIDDEN", {"path": raw})
    clean = Path(_strip_extended_prefix(raw))
    if not clean.is_absolute():
        raise ProfileIsolationError("PROFILE_PATH_NOT_ABSOLUTE", {"path": raw})
    canonical = _check_no_links_on_path(clean)
    resolved = Path(os.path.realpath(str(canonical)))
    if is_owner_browser_profile_path(canonical) or is_owner_browser_profile_path(resolved):
        raise ProfileIsolationError("OWNER_BROWSER_PROFILE_FORBIDDEN", {"path": raw})
    return canonical


def validate_profile_id(profile_id: str) -> str:
    if (not isinstance(profile_id, str)
            or not PROFILE_ID_RE.fullmatch(profile_id)
            or ".." in profile_id
            or _WINDOWS_DEVICE_RE.match(profile_id)):
        raise ProfileIsolationError("PROFILE_ID_INVALID", {"profile_id": profile_id})
    return profile_id


def _is_strictly_inside(child: Path, parent: Path) -> bool:
    child_key = _norm_key(child).rstrip("\\/")
    parent_key = _norm_key(parent).rstrip("\\/")
    if not child_key or not parent_key or child_key == parent_key:
        return False
    return child_key.startswith(parent_key + os.sep)


def resolve_isolated_profile_dir(
    isolated_root: str | Path,
    *,
    profile_id: str | None = None,
    profile_dir: str | Path | None = None,
) -> tuple[Path, str]:
    """Resolve and validate a persistent isolated profile directory strictly under isolated_root."""
    root_clean = assert_not_owner_browser_profile(Path(isolated_root).absolute())
    if profile_id is None and profile_dir is None:
        raise ProfileIsolationError("PROFILE_ID_REQUIRED")

    validated_id = validate_profile_id(profile_id) if profile_id is not None else None
    if profile_dir is not None:
        if not isinstance(profile_dir, (str, Path)):
            raise ProfileIsolationError("PROFILE_PATH_INVALID")
        raw_dir = str(profile_dir)
        if not raw_dir or "\x00" in raw_dir:
            raise ProfileIsolationError("PROFILE_PATH_INVALID")
        if _has_traversal_segment(raw_dir):
            raise ProfileIsolationError("PROFILE_PATH_TRAVERSAL", {"path": raw_dir})
        if is_owner_browser_profile_path(raw_dir):
            raise ProfileIsolationError("OWNER_BROWSER_PROFILE_FORBIDDEN", {"path": raw_dir})
        target = assert_not_owner_browser_profile(raw_dir)
        if not _is_strictly_inside(target, root_clean):
            raise ProfileIsolationError(
                "PROFILE_OUTSIDE_ISOLATED_ROOT",
                {"path": str(target), "isolated_root": str(root_clean)},
            )
        name = target.name
        if not name or _WINDOWS_DEVICE_RE.match(name) or name.endswith(".") or name.endswith(" "):
            raise ProfileIsolationError("PROFILE_ID_INVALID", {"profile_id": name})
        if validated_id is not None:
            expected = root_clean / validated_id
            if _norm_key(target) != _norm_key(expected):
                raise ProfileIsolationError("PROFILE_OPTION_CONFLICT")
            return expected, validated_id
        return target, name

    assert validated_id is not None
    target = root_clean / validated_id
    target = assert_not_owner_browser_profile(target)
    if not _is_strictly_inside(target, root_clean):
        raise ProfileIsolationError(
            "PROFILE_OUTSIDE_ISOLATED_ROOT",
            {"path": str(target), "isolated_root": str(root_clean)},
        )
    return target, validated_id


def _remove_owned_tree_once(candidate, owner):
    from cua_windows_paths import extended_path

    def retry_readonly(function, name, error):
        item = Path(name)
        if not isinstance(error, PermissionError) or linked(item):
            raise error
        info = item.stat()
        if not getattr(info, "st_file_attributes", 0) & 1:
            raise error  # A sharing lock or ACL failure must stay visible.
        item.chmod(stat.S_IWRITE)
        function(name)

    try:
        # Short roots can have long descendants; rmtree derives every child
        # name from the root, so recursive removal must force the prefix.
        shutil.rmtree(extended_path(candidate, force=True), onexc=retry_readonly)
    except OSError:
        # rmtree can remove the marker before reaching a locked file.
        # Preserve ownership so a later start can retry the incomplete cleanup.
        if (candidate.is_dir() and not linked(candidate)
                and not linked(candidate / "owner.json")
                and not (candidate / "owner.json").exists()):
            (candidate / "owner.json").write_text(json.dumps(owner), encoding="utf-8")
        raise


def remove_owned_tree(candidate, owner):
    for attempt in range(11):
        try:
            _remove_owned_tree_once(candidate, owner)
            return attempt + 1
        except PermissionError:
            if attempt == 10:
                raise
            time.sleep(0.2)  # Windows may release cache mappings shortly after process exit.


class ManagedBrowserProfiles:
    def __init__(self, state_dir):
        # The Node sidecar has a different cwd. Never hand it a relative path
        # created relative to the Python process's cwd (otherwise attach ENOENT).
        from cua_windows_paths import extended_path

        assert_not_owner_browser_profile(Path(state_dir).absolute())
        self.root = extended_path(Path(state_dir).absolute() / "isolated-browser-profiles")
        if linked(self.root):
            raise OSError("ISOLATED_PROFILE_ROOT_LINK_FORBIDDEN")
        self.root.mkdir(parents=True, exist_ok=True)
        self.owner = {
            "schema": 1,
            "kind": "ff-isolated-browser-worker",
            "pid": os.getpid(),
            "creation": process_creation_identity(),
            "nonce": uuid.uuid4().hex,
        }
        self.path = extended_path(self.root / ("worker-" + self.owner["nonce"]))
        self.reclaimed = 0
        self.cleanup_errors = []
        self.cleanup_attempts = {}
        with _StateLock(self.root / "profiles.lock"):
            for candidate in self.root.iterdir():
                if not WORKER.fullmatch(candidate.name) or linked(candidate) or not candidate.is_dir():
                    continue
                owner = self._read_owner(candidate)
                if owner is None or process_is_same(owner["pid"], owner["creation"]):
                    continue
                try:
                    self.cleanup_attempts[candidate.name] = remove_owned_tree(candidate, owner)
                    self.reclaimed += 1
                except OSError as exc:
                    self.cleanup_errors.append({
                        "worker": candidate.name,
                        "winerror": getattr(exc, "winerror", None),
                        "error": str(exc),
                    })
            self.path.mkdir()
            try:
                (self.path / "owner.json").write_text(json.dumps(self.owner), encoding="utf-8")
            except Exception:
                self.path.rmdir()
                raise

    @staticmethod
    def _read_owner(candidate):
        from cua_windows_paths import extended_path

        marker = extended_path(candidate / "owner.json")
        try:
            if linked(marker) or marker.stat().st_size > 4096:
                return None
            owner = json.loads(marker.read_text(encoding="utf-8"))
            if (not isinstance(owner, dict) or owner.get("schema") != 1
                    or owner.get("kind") != "ff-isolated-browser-worker"
                    or type(owner.get("pid")) is not int or owner["pid"] <= 0
                    or not isinstance(owner.get("creation"), str)
                    or not re.fullmatch(r"(?:win|proc):[0-9]+", owner["creation"])
                    or candidate.name != "worker-" + str(owner.get("nonce"))):
                return None
            return owner
        except (OSError, ValueError):
            return None

    def close(self):
        with _StateLock(self.root / "profiles.lock"):
            if linked(self.path) or self._read_owner(self.path) != self.owner:
                return False
            remove_owned_tree(self.path, self.owner)
            return True


class PersistentBrowserProfile:
    """Owner-controlled persistent isolated browser profile with exclusive process lease.

    Unlike ManagedBrowserProfiles (ephemeral), close() releases only the process lease
    and preserves `chrome-profile/` across browser restarts.
    """

    def __init__(
        self,
        isolated_root: str | Path,
        *,
        profile_id: str | None = None,
        profile_dir: str | Path | None = None,
    ):
        from cua_windows_paths import extended_path

        root_clean = assert_not_owner_browser_profile(Path(isolated_root).absolute())
        target_clean, resolved_id = resolve_isolated_profile_dir(
            root_clean, profile_id=profile_id, profile_dir=profile_dir
        )
        self.root = extended_path(root_clean)
        self.path = extended_path(target_clean)
        self.profile_id = resolved_id
        self.persistent = True
        self.stale_owner_reclaimed = False
        self.owner = {
            "schema": 1,
            "kind": PERSISTENT_OWNER_KIND,
            "profile_id": self.profile_id,
            "persistent": True,
            "pid": os.getpid(),
            "creation": process_creation_identity(),
            "nonce": uuid.uuid4().hex,
        }
        if linked(self.root):
            raise ProfileIsolationError("ISOLATED_PROFILE_ROOT_LINK_FORBIDDEN")
        self.root.mkdir(parents=True, exist_ok=True)
        with _StateLock(self.root / "persistent-profiles.lock"):
            _check_no_links_on_path(target_clean)
            if self.path.exists() and not self.path.is_dir():
                raise ProfileIsolationError("PROFILE_PATH_NOT_DIRECTORY", {"path": str(target_clean)})
            self.path.mkdir(parents=True, exist_ok=True)
            existing_marker = self.path / "owner.json"
            if existing_marker.exists() or existing_marker.is_symlink():
                existing = self._read_owner(self.path)
                if existing is None:
                    raise ProfileIsolationError("PERSISTENT_PROFILE_OWNER_INVALID", {"profile_id": self.profile_id})
                if process_is_same(existing["pid"], existing["creation"]):
                    raise ProfileIsolationError(
                        "PERSISTENT_PROFILE_IN_USE",
                        {"profile_id": self.profile_id, "owner_pid": existing["pid"]},
                    )
                self.stale_owner_reclaimed = True
                existing_marker.unlink(missing_ok=True)
            chrome_dir = self.path / "chrome-profile"
            if chrome_dir.exists() or chrome_dir.is_symlink():
                if linked(chrome_dir) or not chrome_dir.is_dir():
                    raise ProfileIsolationError("ISOLATED_PROFILE_LINK_FORBIDDEN", {"path": str(chrome_dir)})
                for stale in _CHROME_STALE_LOCKS:
                    stale_file = chrome_dir / stale
                    if stale_file.is_symlink() or linked(stale_file):
                        raise ProfileIsolationError("ISOLATED_PROFILE_LINK_FORBIDDEN", {"path": str(stale_file)})
                    if stale_file.is_file():
                        try:
                            stale_file.unlink()
                        except OSError:
                            pass
            (self.path / "owner.json").write_text(json.dumps(self.owner), encoding="utf-8")

    @property
    def chrome_profile_path(self) -> Path:
        return self.path / "chrome-profile"

    @staticmethod
    def _read_owner(candidate: Path):
        from cua_windows_paths import extended_path

        marker = extended_path(Path(candidate) / "owner.json")
        try:
            if linked(marker) or not marker.is_file() or marker.stat().st_size > 4096:
                return None
            owner = json.loads(marker.read_text(encoding="utf-8"))
            if (not isinstance(owner, dict) or owner.get("schema") != 1
                    or owner.get("kind") != PERSISTENT_OWNER_KIND
                    or owner.get("persistent") is not True
                    or not isinstance(owner.get("profile_id"), str)
                    or not owner["profile_id"]
                    or type(owner.get("pid")) is not int or owner["pid"] <= 0
                    or not isinstance(owner.get("creation"), str)
                    or not re.fullmatch(r"(?:win|proc):[0-9]+", owner["creation"])
                    or not isinstance(owner.get("nonce"), str) or not owner["nonce"]):
                return None
            return owner
        except (OSError, ValueError):
            return None

    def close(self) -> dict:
        with _StateLock(self.root / "persistent-profiles.lock"):
            if linked(self.path) or self._read_owner(self.path) != self.owner:
                return {
                    "released": False,
                    "preserved": self.chrome_profile_path.is_dir(),
                    "profile_id": self.profile_id,
                    "profile_path": str(self.chrome_profile_path),
                }
            marker = self.path / "owner.json"
            if not linked(marker):
                marker.unlink(missing_ok=True)
            active_port = self.chrome_profile_path / "DevToolsActivePort"
            if active_port.is_file() and not linked(active_port):
                try:
                    active_port.unlink()
                except OSError:
                    pass
            return {
                "released": True,
                "preserved": self.chrome_profile_path.is_dir(),
                "profile_id": self.profile_id,
                "profile_path": str(self.chrome_profile_path),
            }
