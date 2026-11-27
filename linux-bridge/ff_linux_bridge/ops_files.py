"""Filesystem operations for FF Linux Bridge v3 (zero external dependencies)."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any


class FileOpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def resolve_path(raw_path: str, workspace_root: str | None = None, *, must_exist: bool = False) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise FileOpError("INVALID_PATH", "path must be a non-empty string")
    expanded = os.path.expanduser(raw_path.strip())
    if workspace_root:
        root = Path(workspace_root).resolve()
        candidate = Path(expanded)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            raise FileOpError("PATH_OUTSIDE_WORKSPACE", f"Path escapes workspace root: {raw_path}")
    else:
        resolved = Path(expanded).resolve()

    if must_exist and not resolved.exists():
        raise FileOpError("NOT_FOUND", f"Path not found: {resolved}")
    return resolved


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def op_read_file(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path", ""), workspace_root, must_exist=True)
    if path.is_dir():
        raise FileOpError("IS_DIRECTORY", f"Cannot read directory as file: {path}")

    encoding = str(args.get("encoding") or "utf-8")
    binary = bool(args.get("binary", False))
    max_bytes = max(1, min(int(args.get("max_bytes", 1_048_576)), 10_485_760))
    start_line = args.get("start_line")
    end_line = args.get("end_line")

    raw = path.read_bytes()
    total_bytes = len(raw)
    sha256 = _sha256_bytes(raw)
    truncated = total_bytes > max_bytes
    chunk = raw[:max_bytes]

    if binary:
        return {
            "path": str(path),
            "size_bytes": total_bytes,
            "sha256": sha256,
            "truncated": truncated,
            "base64": base64.b64encode(chunk).decode("ascii"),
        }

    text = chunk.decode(encoding, errors="replace")
    lines = text.splitlines(keepends=True)
    total_lines = len(lines)
    if start_line is not None or end_line is not None:
        s = max(1, int(start_line or 1))
        e = int(end_line) if end_line is not None else total_lines
        if e < s:
            raise FileOpError("INVALID_RANGE", f"end_line ({e}) < start_line ({s})")
        text = "".join(lines[s - 1 : e])
        return {
            "path": str(path),
            "size_bytes": total_bytes,
            "sha256": sha256,
            "total_lines": total_lines,
            "start_line": s,
            "end_line": min(e, total_lines),
            "truncated": truncated,
            "content": text,
        }

    return {
        "path": str(path),
        "size_bytes": total_bytes,
        "sha256": sha256,
        "total_lines": total_lines,
        "truncated": truncated,
        "content": text,
    }


def op_write_file(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path", ""), workspace_root)
    expected_sha256 = args.get("expected_sha256")
    create_dirs = bool(args.get("create_dirs", True))
    append = bool(args.get("append", False))
    encoding = str(args.get("encoding") or "utf-8")

    if expected_sha256 is not None:
        if not path.exists():
            raise FileOpError("SHA256_CONFLICT", f"expected_sha256 provided but file does not exist: {path}")
        actual = _sha256_bytes(path.read_bytes())
        if actual != str(expected_sha256).strip().lower():
            raise FileOpError("SHA256_CONFLICT", f"File changed on disk (expected {expected_sha256}, actual {actual})")

    if "base64" in args and args["base64"] is not None:
        payload = base64.b64decode(str(args["base64"]))
    elif "content" in args and args["content"] is not None:
        payload = str(args["content"]).encode(encoding)
    elif "text" in args and args["text"] is not None:
        payload = str(args["text"]).encode(encoding)
    else:
        raise FileOpError("INVALID_ARGS", "Provide content, text, or base64")

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.parent.exists():
        raise FileOpError("PARENT_NOT_FOUND", f"Parent directory does not exist: {path.parent}")

    if append and path.exists():
        payload = path.read_bytes() + payload

    # Atomic write via temp file in same directory + os.replace
    fd, tmp_name = tempfile.mkstemp(prefix=".ff-tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            st = path.stat()
            os.chmod(tmp_name, stat.S_IMODE(st.st_mode))
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    return {
        "path": str(path),
        "bytes_written": len(payload),
        "sha256": _sha256_bytes(payload),
    }


def op_patch_file(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    """Exact search-and-replace edit on a UTF-8 file (supports single or multiple edits)."""
    path = resolve_path(args.get("path", ""), workspace_root, must_exist=True)
    encoding = str(args.get("encoding") or "utf-8")
    raw = path.read_bytes()
    expected_sha256 = args.get("expected_sha256")
    if expected_sha256 is not None:
        actual = _sha256_bytes(raw)
        if actual != str(expected_sha256).strip().lower():
            raise FileOpError("SHA256_CONFLICT", f"File changed on disk (expected {expected_sha256}, actual {actual})")

    text = raw.decode(encoding)
    edits = args.get("edits")
    if edits is None:
        old_str = args.get("old_str", args.get("old"))
        new_str = args.get("new_str", args.get("new"))
        if old_str is None or new_str is None:
            raise FileOpError("INVALID_ARGS", "Provide old_str/new_str or edits list")
        edits = [{"old_str": old_str, "new_str": new_str, "replace_all": bool(args.get("replace_all", False))}]

    replacements = 0
    for idx, edit in enumerate(edits):
        old_s = edit.get("old_str", edit.get("old"))
        new_s = edit.get("new_str", edit.get("new"))
        replace_all = bool(edit.get("replace_all", False))
        if not isinstance(old_s, str) or not isinstance(new_s, str) or old_s == "":
            raise FileOpError("INVALID_ARGS", f"Edit[{idx}] must have non-empty string old_str and string new_str")
        count = text.count(old_s)
        if count == 0:
            raise FileOpError("MATCH_NOT_FOUND", f"Edit[{idx}] old_str not found in {path}")
        if count > 1 and not replace_all:
            raise FileOpError(
                "AMBIGUOUS_MATCH",
                f"Edit[{idx}] matched {count} times in {path}; pass replace_all=true or more context",
            )
        if replace_all:
            text = text.replace(old_s, new_s)
            replacements += count
        else:
            text = text.replace(old_s, new_s, 1)
            replacements += 1

    write_res = op_write_file({"path": str(path), "content": text, "encoding": encoding}, workspace_root)
    write_res["replacements"] = replacements
    return write_res


def op_delete_file(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path", ""), workspace_root, must_exist=True)
    recursive = bool(args.get("recursive", False))
    if path.is_dir():
        if not recursive:
            raise FileOpError("IS_DIRECTORY", f"Pass recursive=true to delete directory: {path}")
        shutil.rmtree(path)
    else:
        path.unlink()
    return {"path": str(path), "deleted": True}


def op_list_dir(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path") or ".", workspace_root, must_exist=True)
    if not path.is_dir():
        raise FileOpError("NOT_A_DIRECTORY", f"Not a directory: {path}")
    include_hidden = bool(args.get("include_hidden", True))
    max_entries = max(1, min(int(args.get("max_entries", 500)), 5000))

    entries = []
    for entry in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if not include_hidden and entry.name.startswith("."):
            continue
        try:
            st = entry.lstat()
            kind = "symlink" if entry.is_symlink() else ("dir" if entry.is_dir() else "file")
            entries.append({
                "name": entry.name,
                "path": str(entry),
                "type": kind,
                "size_bytes": st.st_size if kind == "file" else None,
                "mtime": int(st.st_mtime),
                "mode": oct(stat.S_IMODE(st.st_mode)),
            })
        except OSError as exc:
            entries.append({"name": entry.name, "path": str(entry), "error": str(exc)})
        if len(entries) >= max_entries:
            break

    return {"path": str(path), "count": len(entries), "entries": entries}


def op_make_dir(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path", ""), workspace_root)
    parents = bool(args.get("parents", True))
    exist_ok = bool(args.get("exist_ok", True))
    path.mkdir(parents=parents, exist_ok=exist_ok)
    return {"path": str(path), "created": True}


def op_move_path(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    src = resolve_path(args.get("src") or args.get("source", ""), workspace_root, must_exist=True)
    dst = resolve_path(args.get("dst") or args.get("destination", ""), workspace_root)
    dst.parent.mkdir(parents=True, exist_ok=True)
    final_dst = shutil.move(str(src), str(dst))
    return {"src": str(src), "dst": str(final_dst)}


def op_copy_path(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    src = resolve_path(args.get("src") or args.get("source", ""), workspace_root, must_exist=True)
    dst = resolve_path(args.get("dst") or args.get("destination", ""), workspace_root)
    overwrite = bool(args.get("overwrite", False))
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=overwrite)
    else:
        if dst.exists() and not overwrite:
            raise FileOpError("ALREADY_EXISTS", f"Destination exists: {dst} (pass overwrite=true)")
        shutil.copy2(src, dst)
    return {"src": str(src), "dst": str(dst)}


def op_file_info(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    path = resolve_path(args.get("path", ""), workspace_root)
    if not path.exists() and not path.is_symlink():
        return {"path": str(path), "exists": False}
    st = path.lstat()
    info: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "type": "symlink" if path.is_symlink() else ("dir" if path.is_dir() else "file"),
        "size_bytes": st.st_size,
        "mtime": int(st.st_mtime),
        "mode": oct(stat.S_IMODE(st.st_mode)),
    }
    if bool(args.get("sha256", False)) and path.is_file() and st.st_size <= 25_000_000:
        info["sha256"] = _sha256_bytes(path.read_bytes())
    return info


def op_find_files(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    root = resolve_path(args.get("path") or ".", workspace_root, must_exist=True)
    pattern = str(args.get("pattern") or "*")
    max_results = max(1, min(int(args.get("max_results", 200)), 2000))
    include_dirs = bool(args.get("include_dirs", False))
    exclude_dirs = set(args.get("exclude_dirs") or [".git", "node_modules", "__pycache__", ".venv", "venv"])

    matches: list[str] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
        if include_dirs:
            for d in dirnames:
                if fnmatch.fnmatch(d, pattern):
                    matches.append(os.path.join(dirpath, d))
                    if len(matches) >= max_results:
                        truncated = True
                        break
        if truncated:
            break
        for f in sorted(filenames):
            if fnmatch.fnmatch(f, pattern):
                matches.append(os.path.join(dirpath, f))
                if len(matches) >= max_results:
                    truncated = True
                    break
        if truncated:
            break

    return {"root": str(root), "pattern": pattern, "count": len(matches), "truncated": truncated, "matches": matches}


def op_search_text(args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
    root = resolve_path(args.get("path") or ".", workspace_root, must_exist=True)
    query = args.get("query") or args.get("pattern")
    if not isinstance(query, str) or not query:
        raise FileOpError("INVALID_ARGS", "query must be a non-empty string")
    use_regex = bool(args.get("regex", False))
    ignore_case = bool(args.get("ignore_case", False))
    file_glob = str(args.get("glob") or "*")
    max_matches = max(1, min(int(args.get("max_matches", 200)), 2000))
    max_file_bytes = max(1024, min(int(args.get("max_file_bytes", 2_000_000)), 10_000_000))
    exclude_dirs = set(args.get("exclude_dirs") or [".git", "node_modules", "__pycache__", ".venv", "venv"])

    flags = re.IGNORECASE if ignore_case else 0
    rx = re.compile(query if use_regex else re.escape(query), flags)

    matches: list[dict[str, Any]] = []
    truncated = False

    def scan_file(fpath: Path) -> None:
        nonlocal truncated
        try:
            if fpath.stat().st_size > max_file_bytes:
                return
            data = fpath.read_bytes()
            if b"\x00" in data[:4096]:
                return
            text = data.decode("utf-8", errors="replace")
        except OSError:
            return
        for lineno, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                matches.append({"path": str(fpath), "line": lineno, "text": line[:400]})
                if len(matches) >= max_matches:
                    truncated = True
                    return

    if root.is_file():
        scan_file(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
            for fname in sorted(filenames):
                if not fnmatch.fnmatch(fname, file_glob):
                    continue
                scan_file(Path(dirpath) / fname)
                if truncated:
                    break
            if truncated:
                break

    return {"root": str(root), "query": query, "count": len(matches), "truncated": truncated, "matches": matches}


FILE_OPS = {
    "read_file": op_read_file,
    "write_file": op_write_file,
    "patch_file": op_patch_file,
    "edit_file": op_patch_file,
    "delete_file": op_delete_file,
    "list_dir": op_list_dir,
    "make_dir": op_make_dir,
    "move_path": op_move_path,
    "copy_path": op_copy_path,
    "file_info": op_file_info,
    "find_files": op_find_files,
    "search_text": op_search_text,
}
