"""Per-path Win32 long-path and 8.3 short-path helpers; never changes global Windows policy."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


def extended_path(path, *, force=False):
    path=Path(path).absolute()
    value=str(path)
    if os.name != "nt" or value.startswith("\\\\?\\") or (len(value)<240 and not force):
        return path
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\"+value[2:])
    return Path("\\\\?\\"+value)


def _strip_extended_prefix(raw: str) -> str:
    if raw[:8].upper() == "\\\\?\\UNC\\":
        return "\\\\" + raw[8:]
    if raw.startswith("\\\\?\\"):
        return raw[4:]
    return raw


def _to_extended_str(raw: str) -> str:
    if raw.startswith("\\\\?\\"):
        return raw
    if raw.startswith("\\\\"):
        return "\\\\?\\UNC\\" + raw[2:]
    return "\\\\?\\" + raw


def _get_long_path_name_win32(existing: str, *, force_extended: bool = False) -> str | None:
    """Call kernel32.GetLongPathNameW (expands 8.3 short names ONLY; never follows symlinks/junctions)."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.GetLongPathNameW.restype = wintypes.DWORD
    query = existing
    added_prefix = False
    if (force_extended or len(query) >= 240) and not query.startswith("\\\\?\\"):
        query = _to_extended_str(query)
        added_prefix = True
    needed = kernel32.GetLongPathNameW(query, None, 0)
    if not needed and not added_prefix and not query.startswith("\\\\?\\"):
        # Retry with extended prefix if expansion exceeds MAX_PATH.
        query = _to_extended_str(existing)
        added_prefix = True
        needed = kernel32.GetLongPathNameW(query, None, 0)
    if not needed:
        return None
    buf = ctypes.create_unicode_buffer(int(needed) + 1)
    written = kernel32.GetLongPathNameW(query, buf, len(buf))
    if not written or written >= len(buf):
        return None
    result = buf.value
    if added_prefix:
        result = _strip_extended_prefix(result)
    return result


def expand_windows_short_path(path) -> Path:
    """Expand Windows 8.3 short path segments WITHOUT following symlinks, junctions, or SUBST.

    Only existing prefixes (including dangling symlinks/junctions via lexists) are
    passed to GetLongPathNameW; non-existent trailing segments are preserved verbatim.
    Returns the original path unchanged on non-Windows platforms or if Win32 expansion
    fails (fail-closed).
    """
    orig = Path(path)
    if os.name != "nt":
        return orig
    raw = str(orig)
    if not raw or "\x00" in raw:
        return orig
    had_ext = raw.startswith("\\\\?\\")
    clean_str = _strip_extended_prefix(raw)
    clean = Path(clean_str)
    if had_ext and not clean.is_absolute():
        return orig
    suffix: list[str] = []
    cur = clean
    while True:
        cur_str = str(cur)
        probe_str = _to_extended_str(cur_str) if (had_ext or len(cur_str) >= 240) else cur_str
        try:
            exists = os.path.lexists(probe_str)
        except OSError:
            exists = False
        if exists:
            expanded = _get_long_path_name_win32(cur_str, force_extended=(had_ext or len(cur_str) >= 240))
            if not expanded:
                return orig
            result = Path(expanded)
            for part in reversed(suffix):
                result = result / part
            if had_ext:
                return Path(_to_extended_str(str(result)))
            return result
        if cur.parent == cur:
            return orig
        suffix.append(cur.name)
        cur = cur.parent
