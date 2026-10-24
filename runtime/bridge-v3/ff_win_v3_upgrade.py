from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import platform
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

TRANSFER_LOCK = threading.RLock()
TRANSFERS: dict[str, dict[str, Any]] = {}
MAX_STREAM_CHUNK = 1024 * 1024
DEFAULT_STREAM_CHUNK = 512 * 1024
DEFAULT_BATCH_PAGE = 100
MAX_BATCH_PAGE = 1000
DEFAULT_BATCH_RESPONSE_CHARS = 1_500_000
MAX_BATCH_PATHS_IN_MEMORY = 1_000_000
GUI_INLINE_LIMIT = 1_500_000


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _require_windows(core: Any) -> None:
    if platform.system().lower() != "windows":
        raise core.RPCError("GUI_WINDOWS_ONLY")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(core: Any, raw_path: str) -> list[str]:
    path = core.normalize_path(raw_path)
    core.enforce_allowed(path)
    if not path.is_file():
        raise core.RPCError("MANIFEST_NOT_FOUND", details={"path": str(path)})
    if path.stat().st_size > 128 * 1024 * 1024:
        raise core.RPCError("MANIFEST_TOO_LARGE")
    text = path.read_text(encoding="utf-8-sig")
    stripped = text.lstrip()
    if stripped.startswith("["):
        parsed = json.loads(text)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise core.RPCError("MANIFEST_INVALID")
        paths = parsed
    else:
        paths = [line.strip() for line in text.splitlines() if line.strip()]
    if not paths or len(paths) > MAX_BATCH_PATHS_IN_MEMORY:
        raise core.RPCError("MANIFEST_PATH_COUNT_INVALID", details={"count": len(paths)})
    return paths


def _read_multiple_files_paged(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    raw_paths = args.get("paths")
    manifest_path = args.get("manifest_path")
    if raw_paths is not None and manifest_path is not None:
        raise core.RPCError("PATH_SOURCE_AMBIGUOUS")
    if manifest_path is not None:
        if not isinstance(manifest_path, str) or not manifest_path.strip():
            raise core.RPCError("MANIFEST_INVALID")
        paths = _load_manifest(core, manifest_path)
        source = "manifest"
    else:
        if not isinstance(raw_paths, list) or not raw_paths or not all(isinstance(item, str) for item in raw_paths):
            raise core.RPCError("PATHS_INVALID")
        paths = raw_paths
        source = "inline"

    offset = args.get("index_offset", args.get("offset_index", 0))
    page_size = args.get("page_size", DEFAULT_BATCH_PAGE)
    max_chars = args.get("max_response_chars", DEFAULT_BATCH_RESPONSE_CHARS)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise core.RPCError("BATCH_OFFSET_INVALID")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
        raise core.RPCError("BATCH_PAGE_SIZE_INVALID")
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 10_000:
        raise core.RPCError("BATCH_RESPONSE_LIMIT_INVALID")
    page_size = min(page_size, MAX_BATCH_PAGE)
    max_chars = min(max_chars, 8_000_000)
    if offset >= len(paths):
        return {
            "source": source,
            "total_paths": len(paths),
            "offset": offset,
            "returned": 0,
            "next_offset": None,
            "done": True,
            "results": [],
        }

    reader = core.OPS["read_file"]
    results: list[dict[str, Any]] = []
    total_chars = 0
    next_offset = offset
    end = min(len(paths), offset + page_size)
    for index in range(offset, end):
        item = paths[index]
        try:
            result = reader(
                {
                    "path": item,
                    "offset": args.get("file_offset", 0),
                    "length": args.get("file_length", core.STATE.config.get("fileReadLineLimit", 2000)),
                    "range": args.get("range"),
                }
            )
            record = {"ok": True, "index": index, "path": item, "result": result}
        except Exception as exc:
            record = {
                "ok": False,
                "index": index,
                "path": item,
                "error": getattr(exc, "code", type(exc).__name__),
                "message": getattr(exc, "message", str(exc))[:1000],
            }
        encoded_len = len(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        if results and total_chars + encoded_len > max_chars:
            break
        results.append(record)
        total_chars += encoded_len
        next_offset = index + 1

    done = next_offset >= len(paths)
    return {
        "source": source,
        "total_paths": len(paths),
        "offset": offset,
        "returned": len(results),
        "next_offset": None if done else next_offset,
        "done": done,
        "truncated_by_response_budget": (not done and next_offset < end),
        "response_chars_estimate": total_chars,
        "results": results,
    }


def _open_file_read_stream(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    path = core.normalize_path(str(args.get("path") or ""))
    core.enforce_allowed(path)
    if not path.is_file():
        raise core.RPCError("FILE_NOT_FOUND", details={"path": str(path)})
    chunk_bytes = args.get("chunk_bytes", DEFAULT_STREAM_CHUNK)
    if isinstance(chunk_bytes, bool) or not isinstance(chunk_bytes, int) or chunk_bytes < 1:
        raise core.RPCError("STREAM_CHUNK_INVALID")
    chunk_bytes = min(chunk_bytes, MAX_STREAM_CHUNK)
    stream_id = _new_id("read")
    entry = {
        "stream_id": stream_id,
        "mode": "read",
        "path": str(path),
        "offset": 0,
        "chunk_bytes": chunk_bytes,
        "bytes": path.stat().st_size,
        "created_at": _now_ms(),
    }
    with TRANSFER_LOCK:
        TRANSFERS[stream_id] = entry
    return dict(entry)


def _read_file_stream_chunk(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    stream_id = str(args.get("stream_id") or "")
    with TRANSFER_LOCK:
        entry = TRANSFERS.get(stream_id)
        if not entry or entry.get("mode") != "read":
            raise core.RPCError("READ_STREAM_NOT_FOUND")
        path = Path(str(entry["path"]))
        offset = entry["offset"] if args.get("offset") is None else args.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise core.RPCError("STREAM_OFFSET_INVALID")
        length = args.get("chunk_bytes", entry["chunk_bytes"])
        if isinstance(length, bool) or not isinstance(length, int) or length < 1:
            raise core.RPCError("STREAM_CHUNK_INVALID")
        length = min(length, MAX_STREAM_CHUNK)
        total = int(entry["bytes"])
        if offset > total:
            raise core.RPCError("STREAM_OFFSET_PAST_EOF")
        with path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(length)
        next_offset = offset + len(raw)
        entry["offset"] = next_offset
    return {
        "stream_id": stream_id,
        "path": str(path),
        "offset": offset,
        "bytes": len(raw),
        "next_offset": next_offset,
        "total_bytes": total,
        "eof": next_offset >= total,
        "chunk_sha256": hashlib.sha256(raw).hexdigest(),
        "base64": base64.b64encode(raw).decode("ascii"),
    }


def _open_file_write_stream(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    path = core.normalize_path(str(args.get("path") or ""))
    core.enforce_allowed(path)
    expected_bytes = args.get("expected_bytes")
    expected_sha256 = args.get("expected_sha256")
    overwrite = bool(args.get("overwrite", True))
    if expected_bytes is not None and (isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes < 0):
        raise core.RPCError("EXPECTED_BYTES_INVALID")
    if expected_sha256 is not None:
        expected_sha256 = str(expected_sha256).lower()
        if not all(ch in "0123456789abcdef" for ch in expected_sha256) or len(expected_sha256) != 64:
            raise core.RPCError("EXPECTED_SHA256_INVALID")
    if path.exists() and not overwrite:
        raise core.RPCError("DESTINATION_EXISTS")
    path.parent.mkdir(parents=True, exist_ok=True)
    stream_id = _new_id("write")
    temp = path.with_name(path.name + f".ff3-upload-{stream_id}.tmp")
    temp.unlink(missing_ok=True)
    temp.touch()
    entry = {
        "stream_id": stream_id,
        "mode": "write",
        "path": str(path),
        "temp_path": str(temp),
        "offset": 0,
        "expected_bytes": expected_bytes,
        "expected_sha256": expected_sha256,
        "overwrite": overwrite,
        "created_at": _now_ms(),
    }
    with TRANSFER_LOCK:
        TRANSFERS[stream_id] = entry
    return {key: value for key, value in entry.items() if key != "expected_sha256"} | {"expected_sha256": expected_sha256}


def _write_file_stream_chunk(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    stream_id = str(args.get("stream_id") or "")
    encoded = args.get("base64")
    if not isinstance(encoded, str) or not encoded:
        raise core.RPCError("STREAM_BASE64_INVALID")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise core.RPCError("STREAM_BASE64_INVALID") from exc
    if len(raw) > MAX_STREAM_CHUNK:
        raise core.RPCError("STREAM_CHUNK_TOO_LARGE", details={"bytes": len(raw), "limit": MAX_STREAM_CHUNK})
    supplied_hash = args.get("chunk_sha256")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if supplied_hash is not None and str(supplied_hash).lower() != actual_hash:
        raise core.RPCError("STREAM_CHUNK_SHA256_MISMATCH")
    with TRANSFER_LOCK:
        entry = TRANSFERS.get(stream_id)
        if not entry or entry.get("mode") != "write":
            raise core.RPCError("WRITE_STREAM_NOT_FOUND")
        requested_offset = args.get("offset", entry["offset"])
        if requested_offset != entry["offset"]:
            raise core.RPCError("STREAM_NON_SEQUENTIAL_WRITE", details={"expected_offset": entry["offset"]})
        temp = Path(str(entry["temp_path"]))
        with temp.open("ab") as handle:
            handle.write(raw)
            handle.flush()
        entry["offset"] += len(raw)
        next_offset = int(entry["offset"])
    return {
        "stream_id": stream_id,
        "bytes_written": len(raw),
        "next_offset": next_offset,
        "chunk_sha256": actual_hash,
    }


def _finish_file_write_stream(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    stream_id = str(args.get("stream_id") or "")
    with TRANSFER_LOCK:
        entry = TRANSFERS.get(stream_id)
        if not entry or entry.get("mode") != "write":
            raise core.RPCError("WRITE_STREAM_NOT_FOUND")
        path = Path(str(entry["path"]))
        temp = Path(str(entry["temp_path"]))
        actual_bytes = temp.stat().st_size if temp.is_file() else -1
        expected_bytes = entry.get("expected_bytes")
        if expected_bytes is not None and actual_bytes != expected_bytes:
            raise core.RPCError("STREAM_SIZE_MISMATCH", details={"expected": expected_bytes, "actual": actual_bytes})
        actual_hash = _sha256_file(temp)
        expected_hash = entry.get("expected_sha256")
        if expected_hash is not None and actual_hash != expected_hash:
            raise core.RPCError("STREAM_SHA256_MISMATCH", details={"expected": expected_hash, "actual": actual_hash})
        if path.exists() and not bool(entry.get("overwrite", True)):
            raise core.RPCError("DESTINATION_EXISTS")
        os.replace(temp, path)
        TRANSFERS.pop(stream_id, None)
    return {
        "ok": True,
        "stream_id": stream_id,
        "path": str(path),
        "bytes": actual_bytes,
        "sha256": actual_hash,
    }


def _close_file_stream(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    stream_id = str(args.get("stream_id") or "")
    with TRANSFER_LOCK:
        entry = TRANSFERS.pop(stream_id, None)
    if not entry:
        return {"ok": True, "stream_id": stream_id, "existed": False}
    if entry.get("mode") == "write":
        Path(str(entry.get("temp_path", ""))).unlink(missing_ok=True)
    return {"ok": True, "stream_id": stream_id, "existed": True, "mode": entry.get("mode")}


def _list_file_streams(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    with TRANSFER_LOCK:
        items = [dict(entry) for entry in TRANSFERS.values()]
    for item in items:
        if item.get("expected_sha256"):
            item["expected_sha256"] = str(item["expected_sha256"])
    return {"streams": items[-500:]}


def _capture_screen_png(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    output_dir = core.V3_ROOT / "gui-captures"
    output_dir.mkdir(parents=True, exist_ok=True)
    capture_id = _new_id("screen")
    output = output_dir / f"{capture_id}.png"
    ps_path = str(output).replace("'", "''")
    script = (
        "Add-Type -AssemblyName System.Windows.Forms;"
        "Add-Type -AssemblyName System.Drawing;"
        "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;"
        "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
        "$g=[System.Drawing.Graphics]::FromImage($bmp);"
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
        f"$bmp.Save('{ps_path}',[System.Drawing.Imaging.ImageFormat]::Png);"
        "$g.Dispose();$bmp.Dispose();"
        "Write-Output ($b.X.ToString()+','+$b.Y.ToString()+','+$b.Width.ToString()+','+$b.Height.ToString())"
    )
    cp = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-Command", script],
        capture_output=True,
        timeout=20,
    )
    if cp.returncode != 0 or not output.is_file():
        raise core.RPCError("GUI_SCREENSHOT_FAILED", details={"stderr": cp.stderr.decode("utf-8", errors="replace")[-1000:]})
    dims = cp.stdout.decode("utf-8", errors="replace").strip().splitlines()[-1].split(",")
    try:
        x, y, width, height = [int(v) for v in dims]
    except Exception:
        x = y = 0
        width = height = 0
    raw = output.read_bytes()
    result: dict[str, Any] = {
        "capture_id": capture_id,
        "path": str(output),
        "mime": "image/png",
        "bytes": len(raw),
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if bool(args.get("inline", True)) and len(raw) <= GUI_INLINE_LIMIT:
        result["base64"] = base64.b64encode(raw).decode("ascii")
        result["inline"] = True
    else:
        result["inline"] = False
    return result


def _list_windows(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    user32 = ctypes.windll.user32
    limit = args.get("limit", 500)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise core.RPCError("GUI_WINDOW_LIMIT_INVALID")
    limit = min(limit, 2000)
    visible_only = bool(args.get("visible_only", True))
    title_filter = str(args.get("title_contains") or "").lower()
    windows: list[dict[str, Any]] = []

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    @WNDENUMPROC
    def callback(hwnd: int, _lparam: int) -> bool:
        if len(windows) >= limit:
            return False
        visible = bool(user32.IsWindowVisible(hwnd))
        if visible_only and not visible:
            return True
        length = int(user32.GetWindowTextLengthW(hwnd))
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buffer, length + 1)
        title = buffer.value
        if not title:
            return True
        if title_filter and title_filter not in title.lower():
            return True
        pid = ctypes.c_ulong(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        windows.append(
            {
                "hwnd": int(hwnd),
                "hwnd_hex": hex(int(hwnd)),
                "pid": int(pid.value),
                "title": title,
                "visible": visible,
                "rect": {"left": rect.left, "top": rect.top, "right": rect.right, "bottom": rect.bottom},
            }
        )
        return True

    user32.EnumWindows(callback, 0)
    return {"windows": windows, "count": len(windows)}


def _focus_window(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    hwnd = args.get("hwnd")
    if hwnd is None:
        title = str(args.get("title_contains") or "").lower()
        if not title:
            raise core.RPCError("GUI_WINDOW_TARGET_INVALID")
        matches = _list_windows(core, {"visible_only": False, "title_contains": title, "limit": 100})["windows"]
        if not matches:
            raise core.RPCError("GUI_WINDOW_NOT_FOUND")
        hwnd = matches[0]["hwnd"]
    if isinstance(hwnd, str):
        hwnd = int(hwnd, 0)
    if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
        raise core.RPCError("GUI_HWND_INVALID")
    user32 = ctypes.windll.user32
    if not user32.IsWindow(hwnd):
        raise core.RPCError("GUI_WINDOW_NOT_FOUND")
    user32.GetForegroundWindow.restype = ctypes.wintypes.HWND
    if int(user32.GetForegroundWindow() or 0) == hwnd:
        # Re-focusing an active window must not synthesize Alt: it enters menu
        # mode and can consume the first character of the next text input.
        return {"ok": True, "hwnd": hwnd, "foreground_hwnd": hwnd,
                "already_foreground": True, "physical_input_used": False}
    user32.ShowWindow(hwnd, 9)
    HWND_TOPMOST = -1
    HWND_NOTOPMOST = -2
    SWP_NOSIZE = 0x0001
    SWP_NOMOVE = 0x0002
    SWP_SHOWWINDOW = 0x0040
    flags = SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW
    user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, flags)
    user32.keybd_event(0x12, 0, 0, 0)
    ok = bool(user32.SetForegroundWindow(hwnd))
    user32.BringWindowToTop(hwnd)
    user32.keybd_event(0x12, 0, 0x0002, 0)
    user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, flags)
    wait_ms = min(max(float(args.get("wait_ms", 150)), 0), 2000)
    time.sleep(wait_ms / 1000.0)
    foreground = int(user32.GetForegroundWindow())
    return {"ok": bool(ok or foreground == hwnd), "hwnd": hwnd, "foreground_hwnd": foreground}


def _mouse(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    user32 = ctypes.windll.user32
    action = str(args.get("action") or "move").lower()
    x = args.get("x")
    y = args.get("y")
    if x is not None or y is not None:
        if isinstance(x, bool) or isinstance(y, bool) or not isinstance(x, int) or not isinstance(y, int):
            raise core.RPCError("GUI_COORDINATE_INVALID")
        if not user32.SetCursorPos(x, y):
            raise core.RPCError("GUI_CURSOR_MOVE_FAILED")
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_MIDDLEDOWN = 0x0020
    MOUSEEVENTF_MIDDLEUP = 0x0040
    MOUSEEVENTF_WHEEL = 0x0800
    pairs = {
        "click": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
        "left_click": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
        "right_click": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        "middle_click": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
    }
    if action in pairs:
        clicks = args.get("clicks", 1)
        if isinstance(clicks, bool) or not isinstance(clicks, int) or not 1 <= clicks <= 10:
            raise core.RPCError("GUI_CLICK_COUNT_INVALID")
        down, up = pairs[action]
        for _ in range(clicks):
            user32.mouse_event(down, 0, 0, 0, 0)
            user32.mouse_event(up, 0, 0, 0, 0)
            if clicks > 1:
                time.sleep(0.08)
    elif action == "scroll":
        delta = args.get("delta", 0)
        if isinstance(delta, bool) or not isinstance(delta, int):
            raise core.RPCError("GUI_SCROLL_INVALID")
        user32.mouse_event(MOUSEEVENTF_WHEEL, 0, 0, delta, 0)
    elif action != "move":
        raise core.RPCError("GUI_MOUSE_ACTION_INVALID")
    point = ctypes.wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(point))
    return {"ok": True, "action": action, "x": point.x, "y": point.y}


def _keyboard(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    user32 = ctypes.windll.user32
    text = args.get("text")
    keys = args.get("keys")
    if text is None and keys is None:
        raise core.RPCError("GUI_KEYBOARD_INPUT_INVALID")

    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004
    INPUT_KEYBOARD = 1
    ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", ctypes.c_ushort),
            ("wScan", ctypes.c_ushort),
            ("dwFlags", ctypes.c_ulong),
            ("time", ctypes.c_ulong),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong), ("time", ctypes.c_ulong), ("dwExtraInfo", ULONG_PTR)]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [("uMsg", ctypes.c_ulong), ("wParamL", ctypes.c_ushort), ("wParamH", ctypes.c_ushort)]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("union",)
        _fields_ = [("type", ctypes.c_ulong), ("union", _INPUTUNION)]

    def send_unicode_unit(unit: int) -> None:
        down = INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE, 0, 0)))
        up = INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0)))
        array = (INPUT * 2)(down, up)
        if user32.SendInput(2, ctypes.byref(array), ctypes.sizeof(INPUT)) != 2:
            raise core.RPCError("GUI_SENDINPUT_FAILED")

    if text is not None:
        if not isinstance(text, str):
            raise core.RPCError("GUI_TEXT_INVALID")
        raw = text.encode("utf-16-le")
        for index in range(0, len(raw), 2):
            send_unicode_unit(int.from_bytes(raw[index:index + 2], "little"))

    if keys is not None:
        if isinstance(keys, str):
            keys = [part.strip() for part in keys.split("+") if part.strip()]
        if not isinstance(keys, list) or not keys or not all(isinstance(item, str) for item in keys):
            raise core.RPCError("GUI_KEYS_INVALID")
        names = {
            "BACKSPACE": 0x08,
            "TAB": 0x09,
            "ENTER": 0x0D,
            "SHIFT": 0x10,
            "CTRL": 0x11,
            "CONTROL": 0x11,
            "ALT": 0x12,
            "ESC": 0x1B,
            "ESCAPE": 0x1B,
            "SPACE": 0x20,
            "PAGEUP": 0x21,
            "PAGEDOWN": 0x22,
            "END": 0x23,
            "HOME": 0x24,
            "LEFT": 0x25,
            "UP": 0x26,
            "RIGHT": 0x27,
            "DOWN": 0x28,
            "DELETE": 0x2E,
            "WIN": 0x5B,
        }
        for number in range(1, 25):
            names[f"F{number}"] = 0x6F + number
        virtual_keys: list[int] = []
        for name in keys:
            upper = name.upper()
            if upper in names:
                virtual_keys.append(names[upper])
            elif len(name) == 1:
                code = user32.VkKeyScanW(ord(name)) & 0xFF
                if code == 0xFF:
                    raise core.RPCError("GUI_KEY_UNSUPPORTED", details={"key": name})
                virtual_keys.append(code)
            else:
                raise core.RPCError("GUI_KEY_UNSUPPORTED", details={"key": name})
        for vk in virtual_keys:
            user32.keybd_event(vk, 0, 0, 0)
        for vk in reversed(virtual_keys):
            user32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)
    return {"ok": True, "text_chars": len(text) if isinstance(text, str) else 0, "keys": keys or []}


def _gui_cursor(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    _require_windows(core)
    point = ctypes.wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(point))
    return {"x": point.x, "y": point.y}


def register(core: Any) -> None:
    core.OPS["read_multiple_files"] = lambda args: _read_multiple_files_paged(core, args)
    core.OPS.update(
        {
            "open_file_read_stream": lambda args: _open_file_read_stream(core, args),
            "read_file_stream_chunk": lambda args: _read_file_stream_chunk(core, args),
            "open_file_write_stream": lambda args: _open_file_write_stream(core, args),
            "write_file_stream_chunk": lambda args: _write_file_stream_chunk(core, args),
            "finish_file_write_stream": lambda args: _finish_file_write_stream(core, args),
            "close_file_stream": lambda args: _close_file_stream(core, args),
            "list_file_streams": lambda args: _list_file_streams(core, args),
            "gui_screenshot": lambda args: _capture_screen_png(core, args),
            "gui_list_windows": lambda args: _list_windows(core, args),
            "gui_focus_window": lambda args: _focus_window(core, args),
            "gui_mouse": lambda args: _mouse(core, args),
            "gui_keyboard": lambda args: _keyboard(core, args),
            "gui_cursor": lambda args: _gui_cursor(core, args),
        }
    )

    original_capabilities = core.OPS.get("capabilities")

    def capabilities(args: dict[str, Any]) -> dict[str, Any]:
        result = original_capabilities(args) if original_capabilities else {}
        features = result.setdefault("features", {})
        features.update(
            {
                "paged_multi_file_read": True,
                "manifest_multi_file_read": True,
                "large_file_streaming": True,
                "atomic_streamed_upload": True,
                "gui_screenshot": platform.system().lower() == "windows",
                "gui_windows": platform.system().lower() == "windows",
                "gui_mouse": platform.system().lower() == "windows",
                "gui_keyboard": platform.system().lower() == "windows",
            }
        )
        result["stream_chunk_max_bytes"] = MAX_STREAM_CHUNK
        result["batch_page_max_files"] = MAX_BATCH_PAGE
        result["operations"] = sorted(core.OPS)
        return result

    core.OPS["capabilities"] = capabilities
