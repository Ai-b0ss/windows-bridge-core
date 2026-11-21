"""Comprehensive P0 release provenance, Playwright integrity, and REAL isolated non-prod drill tests.

Safety invariants:
- NEVER touches live production paths, live ports (39073/39076/39090/52136/58995),
  Task Scheduler, global PATH, or unrelated user processes.
- Uses an isolated sandbox (env FF_P0_DRILL_ROOT when provided, else TemporaryDirectory)
  and an ephemeral free loopback port on 127.0.0.1.
- Spawns REAL Python HTTP server + REAL PowerShell ff_win_v3_keeper.ps1 processes to prove:
  1. Deploy rel-v1 -> manifest SHA + tools/runtime_parity.py pass.
  2. Upgrade to rel-v2 -> atomic state/active-release.json pointer update + real 40-char Git SHA.
  3. Simulated restart / reboot (stop and relaunch keeper) -> keeper boots rel-v2, NOT stale rel-v1.
  4. Safe rollback to rel-v1 -> keeper boots rel-v1, owner state preserved, unrelated dummy process NOT killed.
  5. Negative tamper tests -> tampered file, tampered manifest, stale commit (c034e527/abd6666),
     and tampered Playwright coreBundle.js ALL fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
RUNTIME_DIR = REPO_ROOT / "runtime" / "bridge-v3"
for _p in (str(TOOLS_DIR), str(RUNTIME_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build_portable_release as builder  # noqa: E402
import cua_release_manifest as rel_manifest  # noqa: E402
import cua_runtime_deploy as deploy  # noqa: E402
import runtime_parity  # noqa: E402

FORBIDDEN_PROD_PORTS = frozenset({20128, 21476, 21477, 39073, 39076, 39090, 52136, 58995})
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return cp.stdout.strip()


def _free_ephemeral_port() -> int:
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in FORBIDDEN_PROD_PORTS:
            return port
    raise RuntimeError("NO_FREE_EPHEMERAL_PORT")


def _http_rpc(port: int, secret: str, op: str = "ping") -> dict | None:
    body = json.dumps({"op": op, "args": {}}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=body,
        headers={"Content-Type": "application/json", "X-FF3-Key": secret},
        method="POST",
    )
    try:
        with NO_PROXY_OPENER.open(req, timeout=2) as resp:
            return json.loads(resp.read(65536).decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None


def _wait_for_rpc_version(
    port: int, secret: str, *, expected_version: str | None = None, timeout: float = 25.0
) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        resp = _http_rpc(port, secret, "ping")
        if isinstance(resp, dict) and resp.get("ok") is True:
            last = resp
            res = resp.get("result") or {}
            if expected_version is None or res.get("version") == expected_version:
                return resp
        time.sleep(0.25)
    raise AssertionError(f"Timed out waiting for RPC version={expected_version!r}; last={last!r}")


def _terminate_pid(pid: int | None) -> None:
    if not pid or pid <= 0:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def _wait_port_closed(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return
        time.sleep(0.2)


def _minimal_agent_source(version_label: str) -> bytes:
    """Minimal standalone loopback HTTP agent mimicking ff_win_v3_main.py serve."""
    script = f'''"""Isolated non-production drill agent ({version_label})."""
from __future__ import annotations
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sys

VERSION = {version_label!r}
HERE = Path(__file__).resolve().parent


def _read_secret() -> str:
    bridge_root = Path(os.environ.get("FF_BRIDGE_ROOT") or HERE.parent)
    for candidate in (bridge_root / "bridge-v3" / "secret", HERE / "secret"):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8").strip()
    return ""


def _manifest_meta() -> dict:
    mf = HERE / "installed-runtime-manifest.json"
    if not mf.is_file():
        return {{}}
    return json.loads(mf.read_text(encoding="utf-8-sig"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    srv = sub.add_parser("serve")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, required=True)
    ns = ap.parse_args(argv)
    if ns.host != "127.0.0.1":
        raise SystemExit("LOOPBACK_ONLY")
    secret = _read_secret()
    meta = _manifest_meta()
    agent_sha = hashlib.sha256((HERE / "ff_win_v3_agent.py").read_bytes()).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, code: int, payload: dict):
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.headers.get("X-FF3-Key", "") != secret:
                self._send(403, {{"ok": False, "error": "FORBIDDEN"}})
                return
            if self.path == "/health":
                self._send(200, {{"ok": True, "version": VERSION, "pid": os.getpid()}})
                return
            self._send(404, {{"ok": False, "error": "NOT_FOUND"}})

        def do_POST(self):
            if self.headers.get("X-FF3-Key", "") != secret:
                self._send(403, {{"ok": False, "error": "FORBIDDEN"}})
                return
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {{}}
            op = body.get("op")
            if op == "ping":
                self._send(200, {{
                    "ok": True,
                    "result": {{
                        "version": VERSION,
                        "pid": os.getpid(),
                        "release_dir": str(HERE),
                        "source_head": meta.get("source_head"),
                        "release_id": meta.get("release_id"),
                        "agent_sha256": agent_sha,
                        "env_active_release_dir": os.environ.get("FF_ACTIVE_RELEASE_DIR"),
                        "env_active_release_head": os.environ.get("FF_ACTIVE_RELEASE_HEAD"),
                    }},
                }})
                return
            if op == "shutdown":
                self._send(200, {{"ok": True, "stopping": True}})
                self.server._stop_flag = True
                return
            self._send(400, {{"ok": False, "error": "UNKNOWN_OP"}})

    server = HTTPServer((ns.host, ns.port), Handler)
    server._stop_flag = False
    server.timeout = 0.25
    while not server._stop_flag:
        server.handle_request()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    return script.replace("\r\n", "\n").encode("utf-8")


@unittest.skipUnless(shutil.which("git"), "git required")
class TestReleaseProvenanceContract(unittest.TestCase):
    def _make_git_repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.name", "Release Provenance Test")
        _git(repo, "config", "user.email", "release-prov@example.invalid")
        _git(repo, "config", "core.autocrlf", "false")
        return repo

    def test_refresh_source_manifest_clears_stale_ancestor_commits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ff-prov-manifest-") as td:
            repo = self._make_git_repo(Path(td))
            (repo / "runtime" / "bridge-v3").mkdir(parents=True)
            (repo / "runtime" / "bridge-v3" / "ff_win_v3_main.py").write_bytes(b"print('ok')\n")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_sample.py").write_bytes(b"assert True\n")
            for name in builder.ROOT_FILES | builder.TOOL_FILES:
                p = repo / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(f"# {name}\n".encode("utf-8"))

            for stale_sha in (
                "c034e527a77b737b266c3c7df8b8521032be6f8a",
                "abd6666b1fc630e84debeef961d0b60da9d0e631",
            ):
                mf_path = repo / "release-manifest.json"
                mf_path.write_text(
                    json.dumps({
                        "schema": "ff-gh-release-v1",
                        "source_commit": stale_sha,
                        "public_source_commit": stale_sha,
                        "source_bytes_verified_against_commit": True,
                        "files": {"assets/test.zip": "a" * 64, "README-FIRST.md": "b" * 64},
                    }),
                    encoding="utf-8",
                    newline="\n",
                )
                with self.assertRaisesRegex(ValueError, "STALE_SOURCE_COMMIT_FORBIDDEN"):
                    builder.verify_release_manifest_provenance(
                        json.loads(mf_path.read_text(encoding="utf-8")), repo=repo, mode="template"
                    )
                res = builder.refresh_source_manifest(repo)
                self.assertTrue(res["ok"])
                self.assertEqual(res["source_commit"], builder.TEMPLATE_SOURCE_COMMIT)
                raw = mf_path.read_bytes()
                self.assertNotIn(b"\r\n", raw, "release-manifest.json must be strictly LF")
                refreshed = json.loads(raw.decode("utf-8"))
                self.assertEqual(refreshed["source_commit"], builder.TEMPLATE_SOURCE_COMMIT)
                self.assertNotIn("public_source_commit", refreshed)
                self.assertNotIn("source_bytes_verified_against_commit", refreshed)
                checked = builder.verify_release_manifest_provenance(refreshed, repo=repo, mode="template")
                self.assertTrue(checked["ok"])

    def test_assemble_stamps_exact_40char_git_head_and_validates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ff-prov-assemble-") as td:
            root = Path(td)
            repo = self._make_git_repo(root)
            src = repo / "source.py"
            src.write_bytes(b"VALUE = 42\n")
            _git(repo, "add", "source.py")
            _git(repo, "commit", "-q", "-m", "real source commit")
            head = _git(repo, "rev-parse", "HEAD")

            prev_zip = root / "previous.zip"
            asset = b"vendor-binary-fixture"
            with zipfile.ZipFile(prev_zip, "w") as z:
                z.writestr(
                    "release-manifest.json",
                    json.dumps({
                        "schema": "ff-gh-release-v1",
                        "source_commit": "c034e527a77b737b266c3c7df8b8521032be6f8a",
                    }),
                )
                z.writestr("assets/test.zip", asset)
                z.writestr("README-FIRST.md", "Previous")
            out_zip = root / "out.zip"
            with patch.object(builder, "PREVIOUS_RELEASE_SHA", builder.sha(prev_zip.read_bytes())), \
                 patch.object(builder, "ASSET_HASHES", {"assets/test.zip": builder.sha(asset)}), \
                 patch.object(builder, "source_tree", return_value={"source.py": src.read_bytes()}):
                receipt = builder.assemble(repo, prev_zip, out_zip)
            self.assertEqual(receipt["public_source_commit"], head)
            with zipfile.ZipFile(out_zip) as z:
                built_mf = json.loads(z.read("release-manifest.json"))
            self.assertEqual(built_mf["source_commit"], head)
            self.assertEqual(built_mf["public_source_commit"], head)
            self.assertTrue(built_mf["source_bytes_verified_against_commit"])
            self.assertTrue(builder.verify_release_manifest_provenance(built_mf, repo=repo, mode="assembled")["ok"])
            # Forged/unknown 40-char commit must fail closed against repo Git history.
            forged = dict(built_mf, source_commit="f" * 40, public_source_commit="f" * 40)
            with self.assertRaisesRegex(ValueError, "SOURCE_COMMIT_UNKNOWN_IN_GIT"):
                builder.verify_release_manifest_provenance(forged, repo=repo, mode="assembled")

    def test_playwright_core_bundle_integrity_fails_closed_on_tamper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ff-prov-pw-") as td:
            root = Path(td)
            repo = self._make_git_repo(root)
            rt = repo / "runtime" / "bridge-v3"
            rt.mkdir(parents=True)
            (rt / "ff_win_v3_agent.py").write_bytes(b"AGENT = 'clean'\n")
            (rt / "ff_win_v3_main.py").write_bytes(b"MAIN = 'clean'\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "clean runtime")
            sha = _git(repo, "rev-parse", "HEAD")

            pw_clean = root / "pw-clean"
            clean_bundle = pw_clean / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"
            clean_bundle.parent.mkdir(parents=True)
            clean_bundle.write_bytes(b"function createExtensionBrowser() { return { ok: true }; }\n")

            pw_tampered = root / "pw-tampered"
            tampered_bundle = pw_tampered / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"
            tampered_bundle.parent.mkdir(parents=True)
            tampered_bundle.write_bytes(
                b'function openConnect(href) { require("fs").writeFileSync("pw_connect_url.txt", href); }\n'
            )

            bridge_root = root / "bridge-root"
            rel_dir = bridge_root / "runtime-releases" / "rel-clean" / "bridge-v3"
            staged = deploy.stage_release_dir(repo, rel_dir, ref=sha, playwright_root=pw_clean)
            self.assertTrue(staged["ok"])
            self.assertTrue(staged["playwright_integrity"]["ok"])

            # Clean playwright root passes runtime_parity CLI.
            cp_ok = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "runtime_parity.py"),
                    "--installed", str(rel_dir),
                    "--ref", sha,
                    "--repo", str(repo),
                    "--require-manifest",
                    "--playwright-root", str(pw_clean),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(cp_ok.returncode, 0, cp_ok.stdout + cp_ok.stderr)
            report_ok = json.loads(cp_ok.stdout)
            self.assertTrue(report_ok["parity"])
            self.assertTrue(report_ok["playwright_integrity"]["ok"])

            # Tampered coreBundle.js fails closed in stage_release_dir, activate_release, and runtime_parity!
            rel_tampered = bridge_root / "runtime-releases" / "rel-tampered" / "bridge-v3"
            with self.assertRaisesRegex(RuntimeError, "PLAYWRIGHT_INTEGRITY_FAILED"):
                deploy.stage_release_dir(repo, rel_tampered, ref=sha, playwright_root=pw_tampered)

            with self.assertRaisesRegex(RuntimeError, "ACTIVE_RELEASE_UNVERIFIED"):
                deploy.activate_release(bridge_root, rel_dir, repo=repo, playwright_root=pw_tampered)

            cp_bad = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "runtime_parity.py"),
                    "--installed", str(rel_dir),
                    "--ref", sha,
                    "--repo", str(repo),
                    "--require-manifest",
                    "--playwright-root", str(pw_tampered),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(cp_bad.returncode, 1, cp_bad.stdout + cp_bad.stderr)
            report_bad = json.loads(cp_bad.stdout)
            self.assertFalse(report_bad["parity"])
            self.assertFalse(report_bad["playwright_integrity"]["ok"])
            self.assertEqual(report_bad["playwright_integrity"]["error"], "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")

            # Optional read-only check against an externally provided clean Playwright 1.65.1 root.
            env_pw = os.environ.get("FF_P0_CLEAN_PW_ROOT")
            if env_pw and Path(env_pw).is_dir():
                real_pw_check = runtime_parity.check_playwright_integrity(rel_dir, playwright_root=Path(env_pw))
                self.assertTrue(real_pw_check["ok"], f"Clean Playwright root unexpectedly failed: {real_pw_check}")

    def test_playwright_integrity_delegates_to_cua_playwright_integrity_contract(self) -> None:
        import types

        with tempfile.TemporaryDirectory(prefix="ff-prov-pw-delegate-") as td:
            pw_root = Path(td) / "pw"
            bundle_path = pw_root / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"
            bundle_path.parent.mkdir(parents=True)
            bundle_path.write_bytes(b"export const clean = true;\n")

            calls: list[tuple[str, str, bool]] = []
            fake_mod = types.ModuleType("cua_playwright_integrity")

            def scan_playwright_root(root, *, require_present=True):
                calls.append(("scan_playwright_root", str(root), bool(require_present)))
                return {
                    "ok": False,
                    "status": "tampered",
                    "error_code": "PLAYWRIGHT_CORE_BUNDLE_TAMPERED",
                    "playwright_root": str(root),
                    "bundle_path": str(bundle_path),
                    "playwright_core_version": "1.65.1",
                    "sha256": deploy.sha256_file(bundle_path),
                    "size_bytes": bundle_path.stat().st_size,
                    "findings": [{"rule": "pw_connect_url_write", "line": 1, "column": 1, "reason": "debug patch"}],
                    "finding_count": 1,
                }

            fake_mod.scan_playwright_root = scan_playwright_root  # type: ignore[attr-defined]
            with patch.dict(sys.modules, {"cua_playwright_integrity": fake_mod}):
                res = deploy.check_playwright_integrity(Path(td), playwright_root=pw_root)
            self.assertFalse(res["ok"])
            self.assertEqual(res["scanner"], "cua_playwright_integrity.scan_playwright_root")
            self.assertEqual(res["error"], "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")
            self.assertEqual(res["matched_rules"], ["pw_connect_url_write"])
            self.assertEqual(res["finding_count"], 1)
            self.assertEqual(calls, [("scan_playwright_root", str(pw_root), True)])

    def test_cold_rollback_bundle_rejects_stale_head_and_preserves_active_release_pointer(self) -> None:
        import cua_cold_rollback_bundle as cold_bundle

        with tempfile.TemporaryDirectory(prefix="ff-prov-cold-ptr-") as td:
            base = Path(td)
            repo = self._make_git_repo(base)
            rt = repo / "runtime" / "bridge-v3"
            rt.mkdir(parents=True)
            (rt / "ff_win_v3_agent.py").write_bytes(b"V = 1\n")
            (rt / "ff_win_v3_main.py").write_bytes(b"M = 1\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "v1")
            v1 = _git(repo, "rev-parse", "HEAD")

            (rt / "ff_win_v3_agent.py").write_bytes(b"V = 2\n")
            (rt / "ff_win_v3_main.py").write_bytes(b"M = 2\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "v2")
            v2 = _git(repo, "rev-parse", "HEAD")

            bridge_root = base / "bridge"
            v3 = bridge_root / "bridge-v3"
            deploy.apply_runtime(repo, v3, ref=v1)
            rel_v1 = bridge_root / "runtime-releases" / "rel-v1" / "bridge-v3"
            rel_v2 = bridge_root / "runtime-releases" / "rel-v2" / "bridge-v3"
            deploy.apply_runtime(repo, rel_v1, ref=v1)
            deploy.apply_runtime(repo, rel_v2, ref=v2)
            deploy.activate_release(bridge_root, rel_v1, repo=repo, release_name="rel-v1")
            ptr_path = deploy.active_release_pointer_path(bridge_root)
            ptr_before = ptr_path.read_bytes()

            with self.assertRaisesRegex(RuntimeError, "TRUSTED_HEAD_STALE_FORBIDDEN"):
                cold_bundle.preflight(
                    repo, v3, trusted_head="c034e527a77b737b266c3c7df8b8521032be6f8a", candidate_ref=v2
                )

            snap = base / "recovery" / "snap-1"
            snap.parent.mkdir()
            cap = cold_bundle.capture(repo, v3, snap, trusted_head=v1, candidate_ref=v2)
            self.assertTrue(cap["ok"])
            self.assertTrue((snap / "previous-active-release.json").is_file())

            # Advance pointer to v2 and runtime files to v2, then cold-restore back to v1.
            deploy.apply_runtime(repo, v3, ref=v2)
            deploy.activate_release(bridge_root, rel_v2, repo=repo, release_name="rel-v2")
            self.assertNotEqual(ptr_path.read_bytes(), ptr_before)
            res = cold_bundle.restore(snap, v3, offline_confirmed=True)
            self.assertTrue(res["ok"])
            self.assertEqual(ptr_path.read_bytes(), ptr_before)
            self.assertEqual(deploy.verify_active_release_pointer(bridge_root, repo=repo)["source_head"], v1)

    def test_release_provenance_rpc_op_reports_active_pointer(self) -> None:
        import types
        import ff_win_v3_upgrade as upgrade_mod

        with tempfile.TemporaryDirectory(prefix="ff-prov-rpc-") as td:
            base = Path(td)
            repo = self._make_git_repo(base)
            rt = repo / "runtime" / "bridge-v3"
            rt.mkdir(parents=True)
            (rt / "ff_win_v3_agent.py").write_bytes(b"A = 1\n")
            (rt / "ff_win_v3_main.py").write_bytes(b"M = 1\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "v1")
            v1 = _git(repo, "rev-parse", "HEAD")

            bridge_root = base / "bridge"
            rel_v1 = bridge_root / "runtime-releases" / "rel-v1" / "bridge-v3"
            deploy.apply_runtime(repo, rel_v1, ref=v1)
            deploy.activate_release(bridge_root, rel_v1, repo=repo, release_name="rel-v1")

            core = types.SimpleNamespace(
                BRIDGE_ROOT=bridge_root,
                OPS={"capabilities": lambda _args: {"features": {}}},
            )
            upgrade_mod.register(core)
            caps = core.OPS["capabilities"]({})
            self.assertTrue(caps["features"]["atomic_release_pointer"])
            self.assertIn("release_provenance", caps["operations"])
            prov = core.OPS["release_provenance"]({})
            self.assertTrue(prov["ok"])
            self.assertTrue(prov["pointer_present"])
            self.assertEqual(prov["source_head"], v1)
            self.assertEqual(prov["release_name"], "rel-v1")


@unittest.skipUnless(os.name == "nt" and shutil.which("git") and (shutil.which("powershell.exe") or shutil.which("pwsh")),
                     "Windows + git + PowerShell required for real keeper drill")
class TestRealIsolatedReleaseDrill(unittest.TestCase):
    def _pwsh(self) -> str:
        exe = shutil.which("powershell.exe") or shutil.which("pwsh")
        assert exe
        return exe

    def _create_sandbox(self) -> tuple[Path, bool]:
        custom = os.environ.get("FF_P0_DRILL_ROOT", "").strip()
        if custom:
            base = Path(custom) / f"run-{uuid.uuid4().hex[:10]}"
            base.mkdir(parents=True, exist_ok=True)
            return base, True
        td = tempfile.TemporaryDirectory(prefix="ff-p0-release-drill-")
        self.addCleanup(td.cleanup)
        return Path(td.name), False

    def _spawn_keeper(self, ps: str, keeper_script: Path, bridge_root: Path, port: int) -> subprocess.Popen:
        env = dict(os.environ)
        env["FF_ENABLE_COMMANDER_RELAY"] = "0"
        env["FF_ENABLE_CONTINUATION_DAEMON"] = "0"
        env["FF_ENABLE_OWNER_CHROME_PROBE"] = "0"
        return subprocess.Popen(
            [
                ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(keeper_script),
                "-BridgeRoot", str(bridge_root),
                "-Port", str(port),
                "-PollIntervalSeconds", "1",
            ],
            cwd=str(bridge_root / "bridge-v3"),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _stop_keeper_and_agent(
        self, keeper_proc: subprocess.Popen | None, agent_pid: int | None, port: int
    ) -> None:
        if keeper_proc is not None:
            if keeper_proc.poll() is None:
                _terminate_pid(keeper_proc.pid)
                try:
                    keeper_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (keeper_proc.stdout, keeper_proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if agent_pid is not None:
            _terminate_pid(agent_pid)
        _wait_port_closed(port, timeout=10.0)

    def test_end_to_end_isolated_upgrade_restart_rollback_and_negative_tamper_drill(self) -> None:
        ps = self._pwsh()
        sandbox, preserve_evidence = self._create_sandbox()
        port = _free_ephemeral_port()
        self.assertNotIn(port, FORBIDDEN_PROD_PORTS)

        # 1. Build a real two-commit Git repository (v1 and v2) with unified Bridge + Hub files.
        repo = sandbox / "source-repo"
        rt_src = repo / "runtime" / "bridge-v3"
        rt_src.mkdir(parents=True)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.name", "P0 Drill")
        _git(repo, "config", "user.email", "p0-drill@example.invalid")
        _git(repo, "config", "core.autocrlf", "false")

        (rt_src / "ff_win_v3_main.py").write_bytes(_minimal_agent_source("rel-v1"))
        (rt_src / "ff_win_v3_agent.py").write_bytes(b"AGENT_RELEASE = 'rel-v1'\n")
        (rt_src / "ff_hub.py").write_bytes(b"HUB_RELEASE = 'rel-v1'\n")
        (rt_src / "ff_browser_hub.mjs").write_bytes(b"export const HUB_RELEASE = 'rel-v1';\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "release v1")
        v1_sha = _git(repo, "rev-parse", "HEAD")

        (rt_src / "ff_win_v3_main.py").write_bytes(_minimal_agent_source("rel-v2"))
        (rt_src / "ff_win_v3_agent.py").write_bytes(b"AGENT_RELEASE = 'rel-v2'\n")
        (rt_src / "ff_hub.py").write_bytes(b"HUB_RELEASE = 'rel-v2'\n")
        (rt_src / "ff_browser_hub.mjs").write_bytes(b"export const HUB_RELEASE = 'rel-v2';\n")
        (rt_src / "cua_native_core.py").write_bytes(b"RECEIPT_RECOVERY_V2 = True\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "release v2 with gui receipt fix")
        v2_sha = _git(repo, "rev-parse", "HEAD")
        self.assertNotEqual(v1_sha, v2_sha)

        # 2. Prepare isolated Bridge root + owner state sentinels + real ff_win_v3_keeper.ps1.
        bridge_root = sandbox / "isolated-bridge"
        v3_root = bridge_root / "bridge-v3"
        state_root = bridge_root / "state"
        chat_perm_dir = state_root / "chat-permission"
        v3_root.mkdir(parents=True)
        chat_perm_dir.mkdir(parents=True)

        ephemeral_secret = "drill-secret-" + uuid.uuid4().hex
        secret_file = v3_root / "secret"
        secret_file.write_text(ephemeral_secret + "\n", encoding="utf-8", newline="\n")
        (v3_root / "python-path.txt").write_text(sys.executable + "\n", encoding="utf-8", newline="\n")
        chat_perm_file = state_root / "chat-permission.json"
        chat_perm_bytes = b'{"enabled": true, "drill_sentinel": "preserve-owner-consent"}\n'
        chat_perm_file.write_bytes(chat_perm_bytes)
        stop_flag_file = chat_perm_dir / "stop.flag"
        stop_flag_bytes = b'{"stopped": true, "drill_sentinel": "never-delete-stop-flag"}\n'
        stop_flag_file.write_bytes(stop_flag_bytes)
        secret_bytes = secret_file.read_bytes()

        keeper_copy = v3_root / "ff_win_v3_keeper.ps1"
        keeper_copy.write_bytes((RUNTIME_DIR / "ff_win_v3_keeper.ps1").read_bytes())

        # Start an unrelated dummy background process simulating a foreign user app.
        foreign_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(180)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        keeper_proc: subprocess.Popen | None = None
        active_agent_pid: int | None = None
        drill_evidence: dict = {
            "port": port,
            "v1_sha": v1_sha,
            "v2_sha": v2_sha,
            "foreign_dummy_pid": foreign_proc.pid,
            "steps": {},
        }

        try:
            # --- STEP 1: Deploy rel-v1 -> manifest SHA + runtime_parity.py pass ---
            rel_v1 = bridge_root / "runtime-releases" / "rel-v1" / "bridge-v3"
            stage_v1 = deploy.stage_release_dir(repo, rel_v1, ref=v1_sha)
            self.assertTrue(stage_v1["ok"])
            self.assertEqual(stage_v1["source_head"], v1_sha)

            act_v1 = deploy.activate_release(bridge_root, rel_v1, repo=repo, release_name="rel-v1")
            self.assertTrue(act_v1["ok"])
            self.assertEqual(act_v1["source_head"], v1_sha)
            self.assertEqual(Path(act_v1["hub_path"]).parent, rel_v1.resolve())
            self.assertEqual(Path(act_v1["browser_hub_path"]).parent, rel_v1.resolve())

            parity_v1_cp = subprocess.run(
                [
                    sys.executable, str(TOOLS_DIR / "runtime_parity.py"),
                    "--installed", str(rel_v1),
                    "--ref", v1_sha,
                    "--repo", str(repo),
                    "--require-manifest",
                    "--bridge-root", str(bridge_root),
                ],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(parity_v1_cp.returncode, 0, parity_v1_cp.stdout + parity_v1_cp.stderr)
            parity_v1 = json.loads(parity_v1_cp.stdout)
            self.assertTrue(parity_v1["parity"])
            self.assertTrue(parity_v1["manifest_provenance"]["ok"])
            self.assertTrue(parity_v1["active_release_pointer"]["ok"])

            keeper_proc = self._spawn_keeper(ps, keeper_copy, bridge_root, port)
            ping_v1 = _wait_for_rpc_version(port, ephemeral_secret, expected_version="rel-v1")
            active_agent_pid = int(ping_v1["result"]["pid"])
            self.assertEqual(ping_v1["result"]["source_head"], v1_sha)
            self.assertEqual(
                deploy._comparable_path(Path(ping_v1["result"]["release_dir"])),
                deploy._comparable_path(rel_v1),
            )
            drill_evidence["steps"]["step1_deploy_v1"] = {
                "parity_ok": parity_v1["parity"],
                "live_version": ping_v1["result"]["version"],
                "live_source_head": ping_v1["result"]["source_head"],
                "live_pid": active_agent_pid,
            }

            # --- STEP 2: Upgrade to rel-v2 -> atomic pointer update + real 40-char Git SHA ---
            rel_v2 = bridge_root / "runtime-releases" / "rel-v2" / "bridge-v3"
            stage_v2 = deploy.stage_release_dir(repo, rel_v2, ref=v2_sha)
            self.assertTrue(stage_v2["ok"])
            mf_v2 = json.loads((rel_v2 / deploy.MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual(mf_v2["source_head"], v2_sha)
            self.assertTrue(rel_manifest.is_hex40_commit(mf_v2["source_head"]))

            act_v2 = deploy.activate_release(bridge_root, rel_v2, repo=repo, release_name="rel-v2")
            self.assertTrue(act_v2["ok"])
            self.assertEqual(act_v2["source_head"], v2_sha)
            self.assertEqual(act_v2["previous"]["source_head"], v1_sha)

            parity_v2_cp = subprocess.run(
                [
                    sys.executable, str(TOOLS_DIR / "runtime_parity.py"),
                    "--installed", str(rel_v2),
                    "--ref", v2_sha,
                    "--repo", str(repo),
                    "--require-manifest",
                    "--bridge-root", str(bridge_root),
                ],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(parity_v2_cp.returncode, 0, parity_v2_cp.stdout + parity_v2_cp.stderr)
            parity_v2 = json.loads(parity_v2_cp.stdout)
            self.assertTrue(parity_v2["parity"])
            drill_evidence["steps"]["step2_upgrade_v2"] = {
                "parity_ok": parity_v2["parity"],
                "pointer_source_head": act_v2["source_head"],
                "previous_source_head": act_v2["previous"]["source_head"],
            }

            # --- STEP 3: Simulate restart / reboot -> PROVE keeper starts rel-v2 (NOT stale rel-v1!) ---
            self._stop_keeper_and_agent(keeper_proc, active_agent_pid, port)
            keeper_proc = None
            active_agent_pid = None

            keeper_proc = self._spawn_keeper(ps, keeper_copy, bridge_root, port)
            ping_v2 = _wait_for_rpc_version(port, ephemeral_secret, expected_version="rel-v2")
            active_agent_pid = int(ping_v2["result"]["pid"])
            self.assertEqual(ping_v2["result"]["version"], "rel-v2")
            self.assertEqual(ping_v2["result"]["source_head"], v2_sha)
            self.assertEqual(
                deploy._comparable_path(Path(ping_v2["result"]["release_dir"])),
                deploy._comparable_path(rel_v2),
            )
            self.assertIsNone(foreign_proc.poll(), "Unrelated process must remain untouched during restart")
            drill_evidence["steps"]["step3_restart_retains_v2"] = {
                "live_version": ping_v2["result"]["version"],
                "live_source_head": ping_v2["result"]["source_head"],
                "live_pid": active_agent_pid,
                "foreign_dummy_alive": foreign_proc.poll() is None,
            }

            # --- STEP 4: Safe rollback to rel-v1 -> keeper returns to rel-v1, owner state & foreign proc untouched ---
            rb = deploy.rollback_active_release(bridge_root, repo=repo)
            self.assertTrue(rb["ok"])
            self.assertEqual(rb["source_head"], v1_sha)
            self.assertEqual(rb["rolled_back_from"]["source_head"], v2_sha)

            self._stop_keeper_and_agent(keeper_proc, active_agent_pid, port)
            keeper_proc = None
            active_agent_pid = None

            keeper_proc = self._spawn_keeper(ps, keeper_copy, bridge_root, port)
            ping_rb = _wait_for_rpc_version(port, ephemeral_secret, expected_version="rel-v1")
            active_agent_pid = int(ping_rb["result"]["pid"])
            self.assertEqual(ping_rb["result"]["version"], "rel-v1")
            self.assertEqual(ping_rb["result"]["source_head"], v1_sha)

            # Owner state sentinels MUST be byte-exact and untouched.
            self.assertEqual(chat_perm_file.read_bytes(), chat_perm_bytes)
            self.assertEqual(stop_flag_file.read_bytes(), stop_flag_bytes)
            self.assertEqual(secret_file.read_bytes(), secret_bytes)
            # Foreign dummy process MUST STILL BE RUNNING!
            self.assertIsNone(foreign_proc.poll(), "Rollback must NEVER kill unrelated user processes")
            drill_evidence["steps"]["step4_rollback_v1"] = {
                "live_version": ping_rb["result"]["version"],
                "live_source_head": ping_rb["result"]["source_head"],
                "live_pid": active_agent_pid,
                "owner_state_intact": True,
                "foreign_dummy_alive": foreign_proc.poll() is None,
            }

            # --- STEP 5: Negative tamper tests -> fail closed on parity, pointer, and keeper ---
            self._stop_keeper_and_agent(keeper_proc, active_agent_pid, port)
            keeper_proc = None
            active_agent_pid = None

            # 5a. Tamper with a file inside rel-v2 -> parity & activate_release fail closed.
            (rel_v2 / "ff_win_v3_agent.py").write_bytes(b"AGENT_RELEASE = 'TAMPERED'\n")
            parity_tampered = subprocess.run(
                [
                    sys.executable, str(TOOLS_DIR / "runtime_parity.py"),
                    "--installed", str(rel_v2),
                    "--ref", v2_sha,
                    "--repo", str(repo),
                    "--require-manifest",
                ],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(parity_tampered.returncode, 1)
            self.assertFalse(json.loads(parity_tampered.stdout)["parity"])
            with self.assertRaisesRegex(RuntimeError, "ACTIVE_RELEASE_UNVERIFIED:RUNTIME_HASH_MISMATCH"):
                deploy.activate_release(bridge_root, rel_v2, repo=repo)

            # 5b. Tamper with active rel-v1 file -> Python pointer check AND PowerShell keeper fail closed!
            (rel_v1 / "ff_win_v3_main.py").write_bytes(b"# tampered entrypoint\n")
            ptr_tampered = deploy.verify_active_release_pointer(bridge_root, repo=repo)
            self.assertFalse(ptr_tampered["ok"])
            self.assertIn("RUNTIME_HASH_MISMATCH", str(ptr_tampered["error"]))

            probe_ps = (
                f". {str(keeper_copy)!r} -LoadFunctionsOnly -BridgeRoot {str(bridge_root)!r} -Port {port}; "
                "function Get-FF3AgentProcesses { return @() }; "
                "$res = Resolve-FF3ActiveRelease; "
                "$allowed = Test-FF3AgentStartAllowed; "
                "@{ ok = [bool]$res.ok; error = [string]$res.error; start_allowed = [bool]$allowed } | ConvertTo-Json -Compress"
            )
            ps_tampered = json.loads(
                subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", probe_ps], text=True)
            )
            self.assertFalse(ps_tampered["ok"])
            self.assertFalse(ps_tampered["start_allowed"])
            self.assertIn("ACTIVE_RELEASE_FILE_HASH_MISMATCH", ps_tampered["error"])

            # 5c. Stale c034e527 commit in installed manifest fails closed.
            mf_v2_path = rel_v2 / deploy.MANIFEST_NAME
            mf_stale = json.loads(mf_v2_path.read_text(encoding="utf-8"))
            mf_stale["source_head"] = "c034e527a77b737b266c3c7df8b8521032be6f8a"
            mf_v2_path.write_text(json.dumps(mf_stale), encoding="utf-8")
            stale_verify = deploy.verify_runtime(rel_v2, repo=repo)
            self.assertFalse(stale_verify["ok"])
            self.assertEqual(stale_verify["error"], "INSTALLED_MANIFEST_PROVENANCE_INVALID")

            drill_evidence["steps"]["step5_negative_tamper"] = {
                "parity_tampered_rc": parity_tampered.returncode,
                "python_pointer_error": ptr_tampered["error"],
                "keeper_ps_tampered": ps_tampered,
                "stale_commit_error": stale_verify["error"],
            }
            if preserve_evidence:
                (sandbox / "drill_evidence.json").write_text(
                    json.dumps(drill_evidence, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
        finally:
            self._stop_keeper_and_agent(keeper_proc, active_agent_pid, port)
            if foreign_proc.poll() is None:
                _terminate_pid(foreign_proc.pid)
                try:
                    foreign_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass


if __name__ == "__main__":
    unittest.main()
