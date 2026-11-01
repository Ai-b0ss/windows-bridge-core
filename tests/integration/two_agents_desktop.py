"""REAL Windows proof: two agents, two ordinary Win32 windows, one shared mouse and keyboard.

Run with: python tests/integration/two_agents_desktop.py
Starts ONLY a throw-away loopback Bridge (own root, chat permission enabled there) and two Notepad
windows that it creates itself, then kills them. Windows-MCP is needed (same as the live Bridge).
Shows: both agents hold grants at once; each can type only into its own window; a foreign window is
refused before focus or input; simultaneous actions are queued (no interleaving, nothing lost); a
bounded wait ends in LEASE_TIMEOUT; releasing one grant leaves the other; the owner's Stop ends all.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / "runtime/bridge-v3/ff_win_v3_main.py"
u = ctypes.windll.user32
WM_GETTEXT, WM_GETTEXTLENGTH = 0x000D, 0x000E
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def verify(check, code):
    if not check:
        raise RuntimeError(code)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def notepad_windows():
    found, cb = [], ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

    def each(hwnd, _):
        buf = ctypes.create_unicode_buffer(64)
        u.GetClassNameW(hwnd, buf, 64)
        if buf.value == "Notepad" and u.IsWindowVisible(hwnd):
            found.append(int(hwnd))
        return True
    u.EnumWindows(cb(each), 0)
    return found


def edit_text(hwnd):
    texts, cb = [], ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

    def each(child, _):
        buf = ctypes.create_unicode_buffer(64)
        u.GetClassNameW(child, buf, 64)
        if buf.value in ("Edit", "RichEditD2DPT", "RICHEDIT50W"):
            n = u.SendMessageW(child, WM_GETTEXTLENGTH, 0, 0)
            b = ctypes.create_unicode_buffer(n + 2)
            u.SendMessageW(child, WM_GETTEXT, n + 1, b)
            texts.append(b.value)
        return True
    u.EnumChildWindows(hwnd, cb(each), 0)
    return "".join(texts)


def launch_notepad(before):
    proc = subprocess.Popen([r"C:\Windows\System32\notepad.exe"])
    for _ in range(80):
        time.sleep(0.25)
        now = [h for h in notepad_windows() if h not in before]
        if now:
            return proc, now[0]
    raise RuntimeError("NOTEPAD_NOT_FOUND")


def center(hwnd):
    rect = wt.RECT()
    u.GetWindowRect(hwnd, ctypes.byref(rect))
    return [(rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2]


def main() -> int:
    if os.name != "nt":
        print("Requires Windows", file=sys.stderr)
        return 2
    checks, procs = [], []
    with TemporaryDirectory(prefix="ff-two-agents-") as td:
        root = Path(td) / "agent"
        state = root / "state"
        state.mkdir(parents=True)
        (state / "chat-permission.json").write_text(json.dumps(
            {"schema": "ff-chat-permission-v1", "enabled": True, "max_ttl_seconds": 600}))
        port = free_port()
        bridge = subprocess.Popen([sys.executable, str(SERVER), "serve", "--host", "127.0.0.1", "--port", str(port)],
                                  cwd=str(REPO), env={**os.environ, "FF_BRIDGE_ROOT": str(root)},
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                  creationflags=0x08000000)
        try:
            secret_file = root / "bridge-v3/secret"
            for _ in range(300):
                verify(bridge.poll() is None, "BRIDGE_EXITED")
                if secret_file.is_file():
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=.2).close()
                        break
                    except OSError:
                        pass
                time.sleep(.1)
            secret = secret_file.read_text().strip()

            def rpc(op, args, timeout=120):
                body = json.dumps({"task_id": "two-agents", "target_device": platform.node(), "op": op, "args": args}).encode()
                request = urllib.request.Request(f"http://127.0.0.1:{port}/rpc", data=body, method="POST",
                                                 headers={"X-FF3-Key": secret, "Content-Type": "application/json"})
                try:
                    return json.loads(OPENER.open(request, timeout=timeout).read())
                except urllib.error.HTTPError as exc:
                    return json.loads(exc.read())

            A = {"agent_id": "agent-a", "task_id": "task-a"}
            B = {"agent_id": "agent-b", "task_id": "task-b"}
            for ids in (A, B):
                rpc("computer_use", {"command": "task_preflight", "app": "Notepad", "task": "type text", **ids})

            pa, hwnd_a = launch_notepad(notepad_windows())
            pb, hwnd_b = launch_notepad(notepad_windows())
            procs += [pa, pb]
            verify(hwnd_a != hwnd_b, "SAME_WINDOW")

            def grant(ids, hwnd, seconds=300):
                return rpc("set_desktop_mode", {"mode": "dedicated", **ids, "targets": [{"hwnd": hwnd}],
                                                "owner_chat_permission": {"quote": "да (проверка двух агентов)",
                                                                          "apps": ["Notepad"], "duration_seconds": seconds}})

            ga, gb = grant(A, hwnd_a), grant(B, hwnd_b)
            verify(ga.get("ok") and gb.get("ok"), "SECOND_AGENT_REFUSED_%s" % gb.get("error_code"))
            gen_a, gen_b = ga["result"]["generation"], gb["result"]["generation"]
            status = rpc("desktop_mode_status", {})["result"]
            verify(len(status["grants"]) == 2, "STATUS_DOES_NOT_SHOW_BOTH")
            checks.append("two_agents_hold_independent_grants_for_two_windows")

            def type_into(ids, gen, hwnd, text, **extra):
                for _ in range(15):
                    answer = rpc("computer_use", {"command": "windows_mcp", "tool": "Type",
                                                  "arguments": {"text": text, "loc": center(hwnd)},
                                                  **ids, "mode_generation": gen, "target_hwnd": hwnd, **extra})
                    if answer.get("ok") or answer.get("error_code") != "OWNER_ACTIVE":
                        return answer
                    time.sleep(2)
                return answer

            r = type_into(A, gen_a, hwnd_a, "alpha-one ")
            verify(r.get("ok"), "A_TYPE_FAILED_%s" % r.get("error_code"))
            r = type_into(B, gen_b, hwnd_b, "bravo-one ")
            verify(r.get("ok"), "B_TYPE_FAILED_%s" % r.get("error_code"))
            time.sleep(0.5)
            verify("alpha-one" in edit_text(hwnd_a) and "bravo-one" not in edit_text(hwnd_a), "A_TEXT_WRONG_" + edit_text(hwnd_a))
            verify("bravo-one" in edit_text(hwnd_b) and "alpha-one" not in edit_text(hwnd_b), "B_TEXT_WRONG_" + edit_text(hwnd_b))
            checks.append("each_agent_types_into_its_own_window_after_a_scoped_focus")

            front_before = int(u.GetForegroundWindow())
            bad = type_into(A, gen_a, hwnd_b, "MUST-NOT-APPEAR")
            verify(bad.get("ok") is False and bad.get("error_code") == "DESKTOP_TARGET_OUTSIDE_SCOPE",
                   "FOREIGN_WINDOW_NOT_REFUSED_%s" % bad.get("error_code"))
            verify(int(u.GetForegroundWindow()) == front_before, "FOCUS_MOVED_TO_FOREIGN_WINDOW")
            bad2 = rpc("computer_use", {"command": "windows_mcp", "tool": "Type",
                                        "arguments": {"text": "MUST-NOT-APPEAR", "loc": center(hwnd_b)},
                                        **A, "mode_generation": gen_a})  # no target: foreground is B's window
            verify(bad2.get("error_code") == "DESKTOP_TARGET_OUTSIDE_SCOPE", "FOREGROUND_FOREIGN_NOT_REFUSED_%s" % bad2.get("error_code"))
            verify("MUST-NOT" not in edit_text(hwnd_a) + edit_text(hwnd_b), "FOREIGN_TEXT_APPEARED")
            checks.append("foreign_window_refused_before_focus_and_input")

            # Simultaneous requests share the keyboard in turn: both succeed, nothing interleaves.
            results = {}

            def worker(name, ids, gen, hwnd, text):
                results[name] = type_into(ids, gen, hwnd, text)

            threads = [threading.Thread(target=worker, args=("a", A, gen_a, hwnd_a, "AAAA-two ")),
                       threading.Thread(target=worker, args=("b", B, gen_b, hwnd_b, "BBBB-two "))]
            started = time.monotonic()
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(180)
            verify(results["a"].get("ok") and results["b"].get("ok"),
                   "CONCURRENT_FAILED_%s_%s" % (results["a"].get("error_code"), results["b"].get("error_code")))
            time.sleep(0.5)
            ta, tb = edit_text(hwnd_a), edit_text(hwnd_b)
            verify("AAAA-two" in ta and "BBBB" not in ta, "A_INTERLEAVED_" + ta)
            verify("BBBB-two" in tb and "AAAA" not in tb, "B_INTERLEAVED_" + tb)
            checks.append("simultaneous_requests_queue_without_interleaving_%.1fs" % (time.monotonic() - started))

            # A bounded wait ends cleanly while the other agent is typing.
            slow = {}
            threads = [threading.Thread(target=lambda: slow.update(a=type_into(A, gen_a, hwnd_a, "slow typing line " * 4)))]
            threads[0].start()
            time.sleep(0.4)
            late = rpc("computer_use", {"command": "windows_mcp", "tool": "Type",
                                        "arguments": {"text": "x", "loc": center(hwnd_b)}, **B,
                                        "mode_generation": gen_b, "target_hwnd": hwnd_b, "lease_wait_seconds": 0.05})
            threads[0].join(180)
            verify(late.get("error_code") == "LEASE_TIMEOUT", "NO_BOUNDED_WAIT_%s" % late.get("error_code"))
            details = late.get("details") or {}
            verify(details.get("retry_safe") is True and "agent-a" in json.dumps(details), "TIMEOUT_DETAILS_" + json.dumps(details)[:200])
            verify(slow["a"].get("ok"), "HOLDER_DISTURBED")
            checks.append("lease_wait_is_bounded_and_names_the_holder")

            # Releasing one grant leaves the other alone.
            rel = rpc("set_desktop_mode", {"mode": "coexist", **A})
            verify(rel.get("ok") and rel["result"]["other_grants"] == 1, "RELEASE_FAILED")
            gone = type_into(A, gen_a, hwnd_a, "after-release")
            verify(gone.get("ok") is False, "RELEASED_GRANT_STILL_WORKS")
            still = type_into(B, gen_b, hwnd_b, "b-still ")
            verify(still.get("ok"), "B_BROKEN_BY_A_RELEASE")
            checks.append("release_is_own_only")

            # Owner Stop beats everyone.
            (state / "chat-permission").mkdir(exist_ok=True)
            (state / "chat-permission" / "stop.flag").write_text("stop")
            stopped = type_into(B, gen_b, hwnd_b, "after-stop")
            verify(stopped.get("error_code") == "OWNER_STOPPED", "STOP_NOT_HONOURED_%s" % stopped.get("error_code"))
            verify(rpc("desktop_mode_status", {})["result"]["grants"] == [], "STOP_LEFT_GRANTS")
            checks.append("owner_stop_revokes_all")
        finally:
            bridge.terminate()
            try:
                bridge.wait(8)
            except Exception:
                bridge.kill()
            for proc in procs:
                subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], capture_output=True)
    print(json.dumps({"all_passed": True, "checks": checks}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
