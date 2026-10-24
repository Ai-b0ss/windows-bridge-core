from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_CURRENT_FILE_DIRECTORY = str(Path(__file__).resolve().parent)
try:
    sys.path.remove(_CURRENT_FILE_DIRECTORY)
except ValueError:
    pass
sys.path.insert(0, _CURRENT_FILE_DIRECTORY)

from cua_native_core import NativeError, NativeSemanticCore
from cua_native_hwnd import HwndMessageBackend
from cua_native_uia3 import Uia3PersistentBackend
from cua_native_waits import NativeWaitController
from cua_native_winapp import WinAppCliBackend


def _object_arg(args: dict[str, Any], key: str, *, default_empty: bool = True) -> dict[str, Any]:
    value = args.get(key)
    if value is None and default_empty:
        return {}
    if not isinstance(value, dict):
        raise NativeError("INVALID_ARGUMENT", f"{key} must be an object")
    return dict(value)


def dispatch(core: NativeSemanticCore, request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    args = request.get("args")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise NativeError("INVALID_ARGUMENT", "args must be an object")

    if op == "capabilities":
        result = dict(core.capabilities())
        result["semantic_waits"] = NativeWaitController.capabilities()
        return result
    if op == "observe":
        return core.observe(_object_arg(args, "target"), _object_arg(args, "options"))
    if op == "find":
        generation = args.get("generation")
        return core.find(generation, _object_arg(args, "query"))  # type: ignore[arg-type]
    if op == "get":
        ref = args.get("ref")
        if not isinstance(ref, str) or not ref:
            raise NativeError("INVALID_ARGUMENT", "ref must be a non-empty string")
        return core.get(ref)
    if op == "act":
        ref = args.get("ref")
        action = args.get("action")
        if not isinstance(ref, str) or not ref:
            raise NativeError("INVALID_ARGUMENT", "ref must be a non-empty string")
        if not isinstance(action, str) or not action:
            raise NativeError("INVALID_ARGUMENT", "action must be a non-empty string")
        postcondition = args.get("postcondition")
        if postcondition is not None and not isinstance(postcondition, dict):
            raise NativeError("INVALID_ARGUMENT", "postcondition must be an object")
        return core.act(
            ref,
            action,
            _object_arg(args, "action_args"),
            dict(postcondition) if postcondition is not None else None,
            _object_arg(args, "policy"),
            generation=args.get("generation"),
        )
    if op == "wait_for":
        timeout_ms = args.get("timeout_ms", 5000)
        poll_ms = args.get("poll_ms", 100)
        return core.wait_for(
            _object_arg(args, "target"),
            _object_arg(args, "query"),
            timeout_ms,  # type: ignore[arg-type]
            poll_ms,  # type: ignore[arg-type]
        )
    if op == "wait":
        return NativeWaitController(core).wait(
            _object_arg(args, "target"),
            _object_arg(args, "condition", default_empty=False),
            timeout_ms=args.get("timeout_ms", 5000),  # type: ignore[arg-type]
            poll_ms=args.get("poll_ms", 100),  # type: ignore[arg-type]
            stable_for_ms=args.get("stable_for_ms", 300),  # type: ignore[arg-type]
        )
    raise NativeError("OP_UNSUPPORTED", f"Unsupported op {op!r}")


def main() -> int:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["winapp", "hwnd", "uia3"], default="winapp")
    parser.add_argument("--uia3-exe", type=Path)
    ns = parser.parse_args()
    if ns.engine == "hwnd":
        backend = HwndMessageBackend()
    elif ns.engine == "uia3":
        if ns.uia3_exe is None:
            parser.error("--uia3-exe is required for --engine uia3")
        backend = Uia3PersistentBackend(ns.uia3_exe)
    else:
        backend = WinAppCliBackend()
    core = NativeSemanticCore(backend)
    try:
        lines = sys.stdin
        for line in lines:
            line = line.strip()
            if not line:
                continue
            request_id = None
            try:
                req = json.loads(line)
                if not isinstance(req, dict):
                    raise NativeError("INVALID_REQUEST", "Request must be an object")
                request_id = req.get("id")
                result = dispatch(core, req)
                response = {"id": request_id, "ok": True, "result": result}
            except NativeError as exc:
                response = {"id": request_id, "ok": False, "error": exc.as_dict()}
            except Exception as exc:
                response = {"id": request_id, "ok": False, "error": {"code": "INTERNAL_ERROR", "message": f"{type(exc).__name__}: {exc}"}}
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    finally:
        close = getattr(backend, "close", None)
        if callable(close): close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
