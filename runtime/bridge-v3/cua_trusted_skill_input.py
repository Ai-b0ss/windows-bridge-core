"""Opt-in, short-lived trusted-agent window input (read-only navigation pilot).

This is an explicit alternative trust model, NOT cryptographically attested
ChatGPT-message consent. The agent requests a scoped session. The owner chose
to trust the authenticated Bridge connector + Skill policy for this pilot.
The server enforces exact app identity, HWND/PID/birth binding, TTL, action
limits, desktop ownership, and only bounded mouse input. All other Bridge
approval paths remain unchanged.

Never expose this interface as an unrestricted remote computer controller.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import threading
import time


class TrustedSkillError(ValueError):
    pass


APPROVAL_SCHEMA = "ff-trusted-skill-input-v1"
MAX_SESSION_SECONDS = 600
MAX_ACTIONS = 12
CLAUDE_EXE_SUFFIX = r"\app\claude.exe"
CLAUDE_PACKAGE_MARKER = r"\windowsapps\claude_"
CLAUDE_PUBLISHER = "__pzs8sxrjxfjjc"
ALLOWED_PURPOSE = "inspect_claude_usage_readonly"


def _require(condition: bool, code: str):
    if not condition:
        raise TrustedSkillError(code)


class WindowsWindowAPI:
    """Read the real window owner; never trust caller title or process label."""
    def __init__(self):
        self.user32 = ctypes.windll.user32
        self.kernel32 = ctypes.windll.kernel32

    def snapshot(self, hwnd):
        _require(type(hwnd) is int and hwnd > 0, "TRUSTED_GUI_HWND_INVALID")
        user32, kernel32 = self.user32, self.kernel32
        _require(bool(user32.IsWindow(hwnd)), "TRUSTED_GUI_WINDOW_GONE")
        _require(bool(user32.IsWindowVisible(hwnd)), "TRUSTED_GUI_WINDOW_HIDDEN")
        pid = wintypes.DWORD()
        _require(bool(user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))), "TRUSTED_GUI_PID_UNKNOWN")
        # PROCESS_QUERY_LIMITED_INFORMATION, non-elevated query only.
        kernel32.OpenProcess.restype = wintypes.HANDLE
        h = kernel32.OpenProcess(0x1000, False, pid.value)
        _require(bool(h), "TRUSTED_GUI_PROCESS_QUERY_DENIED")
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buf))
            kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            _require(bool(kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))), "TRUSTED_GUI_PROCESS_PATH_UNKNOWN")
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            kernel32.GetProcessTimes.restype = wintypes.BOOL
            _require(bool(kernel32.GetProcessTimes(h, ctypes.byref(created), ctypes.byref(exited),
                                                   ctypes.byref(kernel), ctypes.byref(user))), "TRUSTED_GUI_PROCESS_BIRTH_UNKNOWN")
            birth = (created.dwHighDateTime << 32) | created.dwLowDateTime
        finally:
            kernel32.CloseHandle(h)
        rect = wintypes.RECT()
        _require(bool(user32.GetWindowRect(hwnd, ctypes.byref(rect))), "TRUSTED_GUI_RECT_UNKNOWN")
        return {
            "hwnd": hwnd, "pid": pid.value, "birth": birth,
            "executable": buf.value.casefold().replace("/", "\\"),
            "rect": (rect.left, rect.top, rect.right, rect.bottom),
        }

    def foreground(self):
        return int(self.user32.GetForegroundWindow())

    def focus(self, hwnd):
        self.user32.ShowWindow(hwnd, 9)  # SW_RESTORE; do not bring other windows forward.
        self.user32.SetForegroundWindow(hwnd)
        return self.foreground() == hwnd

    def point_on_target(self, hwnd, x, y):
        class POINT(ctypes.Structure):
            _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]
        hit = int(self.user32.WindowFromPoint(POINT(x, y)))
        if hit == hwnd or bool(self.user32.IsChild(hwnd, hit)):
            return True
        # Some Chromium-owned popup children return a top-level ancestor.
        return False


class TrustedSkillInput:
    def __init__(self, config_path, *, windows=None, mouse=None, clock=None):
        self.config_path = Path(config_path)
        self.windows = windows if windows is not None else WindowsWindowAPI()
        self.mouse = mouse  # exact original Win32 core mouse op, not network wrapper
        self.clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._session = None

    def _config(self):
        try:
            cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if (not isinstance(cfg, dict)
            or cfg.get("schema") != APPROVAL_SCHEMA
            or cfg.get("enabled") is not True
            or cfg.get("agent_id") != "chatgpt"
            or cfg.get("purpose") != ALLOWED_PURPOSE
            or type(cfg.get("owner_opt_in_until")) not in (int, float)
            or not self.clock() < cfg["owner_opt_in_until"] <= self.clock() + 86400):
            return None
        return cfg

    @staticmethod
    def _claude(snapshot):
        path = snapshot["executable"]
        return (path.startswith("c:\\program files\\windowsapps\\claude_")
                and CLAUDE_PUBLISHER in path
                and path.endswith(CLAUDE_EXE_SUFFIX))

    def status(self):
        with self._lock:
            cfg = self._config()
            s = self._session
            valid = cfg is not None and s is not None and s["expires_at"] > self.clock()
            return {
                "schema": APPROVAL_SCHEMA,
                "enabled": cfg is not None,
                "auth_model": "owner_opted_in_to_skill_guided_agent",
                "chat_message_attested": False,
                "signed_approval_required_for_other_operations": True,
                "allowed_app": "Claude Desktop" if cfg else None,
                "allowed_purpose": ALLOWED_PURPOSE if cfg else None,
                "expires_at": cfg["owner_opt_in_until"] if cfg else None,
                "session_active": valid,
                "actions_remaining": max(0, s["remaining"]) if valid else 0,
                "session_expires_at": s["expires_at"] if valid else None,
            }

    def begin(self, args):
        with self._lock:
            cfg = self._config()
            _require(cfg is not None, "TRUSTED_GUI_NOT_ENABLED")
            _require(isinstance(args, dict), "TRUSTED_GUI_ARGS_INVALID")
            _require(set(args) == {"agent_id", "task_id", "purpose", "hwnd"}, "TRUSTED_GUI_SCOPE_INVALID")
            _require(args["agent_id"] == cfg["agent_id"], "TRUSTED_GUI_AGENT_DENIED")
            task = args["task_id"]
            _require(isinstance(task, str) and 8 <= len(task) <= 128 and all(ch.isalnum() or ch in "-_." for ch in task),
                     "TRUSTED_GUI_TASK_INVALID")
            _require(args["purpose"] == ALLOWED_PURPOSE, "TRUSTED_GUI_PURPOSE_DENIED")
            now = self.clock()
            if self._session and self._session["expires_at"] > now:
                _require(self._session["task_id"] == task, "TRUSTED_GUI_SESSION_BUSY")
                # Idempotent request does not reissue or prolong the session.
                return {"session_id": self._session["id"], "expires_at": self._session["expires_at"],
                        "actions_remaining": self._session["remaining"], "reused": True}
            window = self.windows.snapshot(args["hwnd"])
            _require(self._claude(window), "TRUSTED_GUI_APP_NOT_ALLOWLISTED")
            remaining_seconds = min(MAX_SESSION_SECONDS, cfg["owner_opt_in_until"] - now)
            _require(remaining_seconds > 0, "TRUSTED_GUI_CONFIG_EXPIRED")
            sid = secrets.token_urlsafe(32)
            self._session = {"id": sid, "task_id": task, "identity": (window["hwnd"], window["pid"], window["birth"], window["executable"]),
                             "expires_at": now + remaining_seconds, "remaining": MAX_ACTIONS}
            return {"session_id": sid, "expires_at": self._session["expires_at"],
                    "actions_remaining": MAX_ACTIONS, "reused": False}

    def _verify(self, args):
        cfg = self._config()
        _require(cfg is not None, "TRUSTED_GUI_NOT_ENABLED")
        s = self._session
        _require(s is not None and s["expires_at"] > self.clock(), "TRUSTED_GUI_SESSION_EXPIRED")
        _require(args.get("session_id") == s["id"] and args.get("task_id") == s["task_id"],
                 "TRUSTED_GUI_SESSION_SCOPE_DENIED")
        _require(s["remaining"] > 0, "TRUSTED_GUI_ACTION_LIMIT")
        snapshot = self.windows.snapshot(s["identity"][0])
        actual = (snapshot["hwnd"], snapshot["pid"], snapshot["birth"], snapshot["executable"])
        _require(actual == s["identity"] and self._claude(snapshot), "TRUSTED_GUI_WINDOW_IDENTITY_CHANGED")
        return snapshot, s

    def act(self, args):
        with self._lock:
            _require(isinstance(args, dict) and set(args) <= {"session_id","task_id","action","x","y","delta"},
                     "TRUSTED_GUI_ARGS_INVALID")
            action = args.get("action")
            _require(action in {"focus", "click", "move", "scroll"}, "TRUSTED_GUI_ACTION_DENIED")
            snap, session = self._verify(args)
            hwnd = snap["hwnd"]
            x, y = args.get("x"), args.get("y")
            if action in {"click", "move"}:
                _require(type(x) is int and type(y) is int, "TRUSTED_GUI_COORD_INVALID")
                left, top, right, bottom = snap["rect"]
                _require(left <= x < right and top <= y < bottom, "TRUSTED_GUI_COORD_OUTSIDE")
                _require(self.windows.point_on_target(hwnd, x, y), "TRUSTED_GUI_POINT_OBSCURED")
            else:
                _require(x is None and y is None, "TRUSTED_GUI_COORD_UNEXPECTED")
            if action == "scroll":
                delta = args.get("delta")
                _require(type(delta) is int and -360 <= delta <= 360 and delta != 0,
                         "TRUSTED_GUI_SCROLL_INVALID")
            else:
                _require("delta" not in args, "TRUSTED_GUI_SCROLL_UNEXPECTED")
            if action != "focus":
                _require(self.windows.foreground() == hwnd, "TRUSTED_GUI_NOT_FOREGROUND")
            _require(self.mouse is not None, "TRUSTED_GUI_DRIVER_MISSING")
            # Decrement before performing a possibly non-idempotent action.
            session["remaining"] -= 1
            if action == "focus":
                _require(self.windows.focus(hwnd), "TRUSTED_GUI_CANNOT_FOCUS")
            elif action == "scroll":
                self.mouse({"action":"scroll","delta":delta})
            else:
                self.mouse({"action":"click" if action == "click" else "move","x":x,"y":y,"clicks":1})
            return {"ok":True,"action":action, "actions_remaining":session["remaining"],
                    "expires_at":session["expires_at"], "window_verified":True}

    def end(self, args):
        with self._lock:
            _require(isinstance(args,dict), "TRUSTED_GUI_ARGS_INVALID")
            s = self._session
            if s is not None:
                _require(args.get("session_id") == s["id"] and args.get("task_id") == s["task_id"],
                         "TRUSTED_GUI_SESSION_SCOPE_DENIED")
            self._session = None
            return {"closed":True}
