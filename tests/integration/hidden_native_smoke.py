"""Real private-desktop native edit/readback; requires interactive Windows.

Manual authorized Windows gate, not proof of universal GUI compatibility.
Only newly launched disposable Notepad/WordPad processes are mutated/closed.
No user document, visible input, screenshot, or clipboard content is read.
"""
from __future__ import annotations
import argparse
import ctypes
import ctypes.wintypes as w
import hashlib
import json
import os
from pathlib import Path
import sys
import time

RUNTIME = Path(__file__).resolve().parents[2]/"runtime/bridge-v3"


def check(value, code):
    if not value:
        raise RuntimeError(code)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", choices=("notepad", "wordpad"), default="notepad")
    opts = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("WINDOWS_INTERACTIVE_SESSION_REQUIRED")
    sys.path.insert(0, str(RUNTIME))
    from cua_hidden_desktop import HiddenDesktopSession, HiddenDesktopError
    from ff_win_process_identity import process_creation_token, process_identity_matches
    user = ctypes.WinDLL("user32")
    user.GetForegroundWindow.restype = w.HWND
    class Point(ctypes.Structure):
        _fields_ = [("x", w.LONG), ("y", w.LONG)]
    def owner_state():
        point = Point()
        check(user.GetCursorPos(ctypes.byref(point)), "CURSOR_OBSERVATION_UNAVAILABLE")
        return (int(user.GetForegroundWindow() or 0), point.x, point.y,
                int(user.GetClipboardSequenceNumber()))

    before = owner_state()
    session = None
    owned = []
    evidence = {"schema": "ff-hidden-native-smoke-v1", "app": opts.app,
                "physical_input_used": False, "owner_clipboard_content_read": False}
    try:
        session = HiddenDesktopSession(RUNTIME)
        owned.append((session.pid, process_creation_token(session.pid)))
        launched = session.request({"command": "launch_app", "app": opts.app})
        owned.append((launched["pid"], process_creation_token(launched["pid"])))
        check(all(token is not None for _, token in owned), "OWNED_PROCESS_IDENTITY_UNKNOWN")
        # First observe UIA. Status-bar panes can advertise Edit/set_value;
        # never mistake them for the actual document control.
        uia = session.request({"command": "uia_observe", "hwnd": launched["hwnd"]})
        original = session.request({"command": "read_text", "hwnd": launched["hwnd"]})
        check(original["value"] == "", "NEW_OWNED_DOCUMENT_NOT_EMPTY")
        observed = session.request({"command": "attach", "target": {"hwnd": launched["hwnd"]}})
        snapshot = observed["observation"]
        candidates = [entity for entity in snapshot["entities"]
                      if entity["identity"].get("hwnd") == original["document_hwnd"]
                      and "set_value" in entity["actions"]]
        check(len(candidates) == 1, "OWNED_DOCUMENT_TARGET_AMBIGUOUS")
        entity = candidates[0]
        # A foreign owner-visible HWND must be denied BEFORE action dispatch.
        try:
            session.request({"command": "read_text", "hwnd": before[0]})
        except HiddenDesktopError as exc:
            check(exc.code == "HIDDEN_WINDOW_NOT_OWNED", "WRONG_FOREIGN_TARGET_DENIAL")
        else:
            raise RuntimeError("FOREIGN_WINDOW_WAS_ACCEPTED")
        marker = "WINDOWS_BRIDGE_OWNED_NATIVE_20261025"
        result = session.request({
            "command": "act", "surface_id": observed["surface_id"],
            "generation": snapshot["generation"], "ref": entity["ref"],
            "operation": "set_value", "action_args": {"value": marker},
            "postcondition": {"type": "value_equals", "value": marker},
        })
        check(result.get("verified") is True, "NATIVE_ACTION_NOT_VERIFIED")
        readback = session.request({"command": "read_text", "hwnd": launched["hwnd"]})
        check(readback["value"] == marker, "INDEPENDENT_DOCUMENT_READBACK_FAILED")
        evidence.update({"route": "HWND_MESSAGE", "uia_entities_observed": len(uia["entities"]),
                         "independent_document_verified": True, "foreign_window_denied": True,
                         "document_sha256": hashlib.sha256(marker.encode()).hexdigest()})
    finally:
        if session:
            session.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and any(process_identity_matches(pid, token) for pid, token in owned):
            time.sleep(.1)
        after = owner_state()
        evidence.update({"foreground_unchanged": before[0] == after[0],
                         "cursor_unchanged": before[1:3] == after[1:3],
                         "clipboard_sequence_unchanged": before[3] == after[3],
                         "owned_processes_closed": not any(process_identity_matches(pid, token) for pid, token in owned)})
        print(json.dumps(evidence, sort_keys=True))
    for key in ("foreground_unchanged", "cursor_unchanged", "clipboard_sequence_unchanged", "owned_processes_closed"):
        check(evidence[key], "GATE_NOT_PROVEN_" + key.upper())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("HIDDEN_NATIVE_SMOKE_FAILED:" + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(1)
