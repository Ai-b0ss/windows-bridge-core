"""Regression tests for the safe C1 + C2 canary release and rollback workflow.

All tests execute strictly in disposable TemporaryDirectory locations on
ephemeral loopback ports. They never touch production installations, live
production ports, other git worktrees, or the visible desktop.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))

import canary_release_workflow as canary  # noqa: E402
from ff_hub import HubClient  # noqa: E402
from ff_hub_store import HubError  # noqa: E402
from ff_win_process_identity import process_creation_token  # noqa: E402


def _cancel_hub_session_reconciled(hub_client: HubClient, request_key: str, *, wait_seconds: float = 30.0) -> dict:
    """Cancel an active Hub session and reconcile via durable request_status if a reply is lost."""
    try:
        return hub_client.call("task_cancel", request_key=request_key)
    except HubError as exc:
        if exc.code != "HUB_UNREACHABLE":
            raise
        deadline = time.monotonic() + wait_seconds
        last_status = None
        while time.monotonic() < deadline:
            try:
                st = hub_client.call("request_status", {"request_key": request_key})
                last_status = st
                if st.get("state") == "completed":
                    return st.get("response") or {"closed": True, "reconciled": True}
                if st.get("state") in {"failed", "unknown"}:
                    raise AssertionError(f"task_cancel reached non-completed state after lost reply: {st}") from exc
            except HubError:
                pass
            time.sleep(0.25)
        raise AssertionError(
            f"task_cancel lost reply and did not complete within {wait_seconds}s: {last_status}"
        ) from exc


def _free_ports(count: int) -> list[int]:
    sockets = []
    ports: list[int] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
            while port in canary.FORBIDDEN_SHADOW_PORTS or port in ports:
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(("127.0.0.1", 0))
                port = int(sock.getsockname()[1])
            sockets.append(sock)
            ports.append(port)
        return ports
    finally:
        for sock in sockets:
            sock.close()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=25,
        check=True,
    )
    return cp.stdout.strip()


def _make_c1_source_zip(dest: Path, *, commit: str, marker_version: str) -> tuple[Path, str]:
    """Create a real, hash-verified C1 source ZIP using current C1 bridge-v3 modules."""
    files: dict[str, bytes] = {}
    bridge_src = ROOT / "runtime" / "bridge-v3"
    for src in sorted(bridge_src.glob("*.py")):
        data = src.read_bytes()
        if src.name == "ff_win_v3_agent.py":
            data = data + f"\n# canary-fixture-version={marker_version}\n".encode("utf-8")
        files[f"runtime/bridge-v3/{src.name}"] = data
    # Include tools/agent_entry.py so authenticated /agent/v1 probes work from release dir.
    files["tools/agent_entry.py"] = (ROOT / "tools" / "agent_entry.py").read_bytes()

    manifest = {
        "schema": "ff-gh-release-v1",
        "source_commit": commit,
        "public_source_commit": commit,
        "source_bytes_verified_against_commit": True,
        "files": {name: _sha256_bytes(data) for name, data in sorted(files.items())},
    }
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
        zf.writestr("release-manifest.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
    return dest, _sha256_bytes(dest.read_bytes())


def _make_c2_fixture_repo(repo: Path) -> tuple[str, str]:
    """Create a disposable C2 git repository with two pinned commits (v1 and v2)."""
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Canary Fixture")
    _git(repo, "config", "user.email", "canary-fixture@example.invalid")
    _git(repo, "config", "core.autocrlf", "false")

    idempotency_py = (
        "def resolve_idempotency_key(headers, body):\n"
        "    return headers.get('Idempotency-Key') or body.get('request_key')\n"
    )

    def server_code(version: str) -> str:
        return (
            "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
            "import json, os, sqlite3\n"
            "from pathlib import Path\n"
            "ROOT = Path(__file__).resolve().parent\n"
            "DB = ROOT / 'gateway.db'\n"
            "PORT = int(os.environ.get('GEMINI_GATEWAY_PORT', '21587'))\n"
            f"VERSION = {version!r}\n"
            "def init_db():\n"
            "    conn = sqlite3.connect(str(DB), timeout=5)\n"
            "    conn.execute('PRAGMA journal_mode=WAL')\n"
            "    conn.execute('CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, status TEXT NOT NULL, "\
            "browser_tab_tracked INTEGER DEFAULT 0, browser_tab_open INTEGER DEFAULT 0, "\
            "browser_tab_cleanup_uncertain INTEGER DEFAULT 0)')\n"
            "    conn.commit()\n"
            "    conn.close()\n"
            "class H(BaseHTTPRequestHandler):\n"
            "    def log_message(self, *a): pass\n"
            "    def do_GET(self):\n"
            "        if self.path == '/health':\n"
            "            body = json.dumps({'ok': True, 'service': 'gateway', 'version': VERSION, 'port': PORT}).encode()\n"
            "            self.send_response(200)\n"
            "            self.send_header('Content-Type', 'application/json')\n"
            "            self.send_header('Content-Length', str(len(body)))\n"
            "            self.end_headers()\n"
            "            self.wfile.write(body)\n"
            "            return\n"
            "        self.send_response(404)\n"
            "        self.end_headers()\n"
            "if __name__ == '__main__':\n"
            "    init_db()\n"
            "    srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)\n"
            "    srv.serve_forever()\n"
        )

    def unified_code(version: str) -> str:
        return (
            "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
            "import hmac, json, os, urllib.request\n"
            "from pathlib import Path\n"
            "PORT = int(os.environ.get('UNIFIED_API_PORT', '21588'))\n"
            "GATEWAY_PORT = int(os.environ.get('UNIFIED_GATEWAY_PORT', '21587'))\n"
            "OMNI_PORT = int(os.environ.get('UNIFIED_OMNI_PORT', '20128'))\n"
            "KEY_FILE = Path(os.environ.get('UNIFIED_API_KEY_FILE', str(Path(__file__).resolve().parent / 'gateway.key')))\n"
            f"VERSION = {version!r}\n"
            "OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
            "def probe(port, path):\n"
            "    try:\n"
            "        with OPENER.open(f'http://127.0.0.1:{port}{path}', timeout=1.5) as r:\n"
            "            return r.status == 200\n"
            "    except Exception:\n"
            "        return False\n"
            "class H(BaseHTTPRequestHandler):\n"
            "    def log_message(self, *a): pass\n"
            "    def do_GET(self):\n"
            "        if self.path == '/health':\n"
            "            body = json.dumps({'ok': True, 'service': 'OmniRouteUnifiedLocalAPI', 'version': VERSION, "
            "'port': PORT, 'gateway_port': GATEWAY_PORT, 'omni_port': OMNI_PORT}).encode()\n"
            "            self.send_response(200)\n"
            "            self.send_header('Content-Type', 'application/json')\n"
            "            self.send_header('Content-Length', str(len(body)))\n"
            "            self.end_headers()\n"
            "            self.wfile.write(body)\n"
            "            return\n"
            "        expected = 'Bearer ' + KEY_FILE.read_text(encoding='ascii').strip()\n"
            "        if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):\n"
            "            self.send_response(401)\n"
            "            self.end_headers()\n"
            "            return\n"
            "        if self.path == '/ready':\n"
            "            gw_ok = probe(GATEWAY_PORT, '/health')\n"
            "            omni_ok = probe(OMNI_PORT, '/api/monitoring/health')\n"
            "            code = 200 if (gw_ok and omni_ok) else 503\n"
            "            body = json.dumps({'ready': gw_ok and omni_ok, 'services': {'gateway': {'reachable': gw_ok}, "
            "'omniroute': {'reachable': omni_ok}}}).encode()\n"
            "            self.send_response(code)\n"
            "            self.send_header('Content-Type', 'application/json')\n"
            "            self.send_header('Content-Length', str(len(body)))\n"
            "            self.end_headers()\n"
            "            self.wfile.write(body)\n"
            "            return\n"
            "        self.send_response(404)\n"
            "        self.end_headers()\n"
            "if __name__ == '__main__':\n"
            "    srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)\n"
            "    srv.serve_forever()\n"
        )

    (repo / "idempotency_utils.py").write_text(idempotency_py, encoding="utf-8", newline="\n")
    (repo / "server.py").write_text(server_code("c2-v1"), encoding="utf-8", newline="\n")
    (repo / "unified_api.py").write_text(unified_code("c2-v1"), encoding="utf-8", newline="\n")
    (repo / "legacy_only.py").write_text("LEGACY = 1\n", encoding="utf-8", newline="\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "c2 baseline v1")
    v1 = _git(repo, "rev-parse", "HEAD")

    (repo / "server.py").write_text(server_code("c2-v2"), encoding="utf-8", newline="\n")
    (repo / "unified_api.py").write_text(unified_code("c2-v2"), encoding="utf-8", newline="\n")
    (repo / "legacy_only.py").unlink()
    (repo / "candidate_feature.py").write_text("CANDIDATE = 2\n", encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c2 candidate v2")
    v2 = _git(repo, "rev-parse", "HEAD")
    return v1, v2


class TestCanaryPinningAndBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="ff-canary-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_empty_or_malformed_sha256_fails_closed(self):
        for bad in ("", "   ", None, "1234", "g" * 64, "a" * 63, "a" * 65):
            with self.subTest(bad=bad):
                with self.assertRaises(canary.CanaryError) as ctx:
                    canary.validate_sha256(bad, "c1_zip_sha256")
                self.assertIn(ctx.exception.code, {"PINNED_SHA256_REQUIRED", "PINNED_SHA256_INVALID"})

    def test_empty_or_mutable_git_commit_fails_closed(self):
        for bad in ("", None, "HEAD", "main", "eadc261", "z" * 40):
            with self.subTest(bad=bad):
                with self.assertRaises(canary.CanaryError) as ctx:
                    canary.validate_git_commit(bad, "c2_commit")
                self.assertIn(ctx.exception.code, {"PINNED_COMMIT_REQUIRED", "PINNED_COMMIT_INVALID"})

    def test_forbidden_production_ports_and_collisions_are_rejected(self):
        for prod_port in sorted(canary.FORBIDDEN_SHADOW_PORTS):
            with self.subTest(prod_port=prod_port):
                with self.assertRaises(canary.CanaryError) as ctx:
                    canary.validate_shadow_ports({
                        "c1_rpc_port": prod_port,
                        "c1_hub_port": 49190,
                        "c2_gateway_port": 49587,
                        "c2_unified_port": 49588,
                    })
                self.assertEqual(ctx.exception.code, "SHADOW_PORT_FORBIDDEN_PRODUCTION_PORT")

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.validate_shadow_ports({
                "c1_rpc_port": 49173,
                "c1_hub_port": 49173,
                "c2_gateway_port": 49587,
                "c2_unified_port": 49588,
            })
        self.assertEqual(ctx.exception.code, "SHADOW_PORT_COLLISION")

    def test_forbidden_production_roots_and_unowned_dirs_rejected(self):
        fake_prod = self.base / "fake-prod-bridge"
        fake_prod.mkdir()
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.validate_shadow_root(fake_prod, extra_forbidden_roots=(fake_prod,))
        self.assertEqual(ctx.exception.code, "SHADOW_ROOT_FORBIDDEN_PRODUCTION_PATH")

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.validate_shadow_root(fake_prod / "nested", extra_forbidden_roots=(fake_prod,))
        self.assertEqual(ctx.exception.code, "SHADOW_ROOT_FORBIDDEN_PRODUCTION_PATH")

        unowned = self.base / "foreign-nonempty"
        unowned.mkdir()
        (unowned / "owner-data.txt").write_text("keep", encoding="utf-8")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.ensure_shadow_owner(unowned, create=True)
        self.assertEqual(ctx.exception.code, "SHADOW_ROOT_NOT_OWNED")

    @unittest.skipUnless(os.name == "nt", "Windows junction protection")
    def test_ntfs_junction_shadow_root_is_rejected(self):
        real_dir = self.base / "real-target"
        real_dir.mkdir()
        junction = self.base / "shadow-junction"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
            capture_output=True,
            check=True,
            timeout=10,
        )
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.validate_shadow_root(junction)
        self.assertEqual(ctx.exception.code, "REPARSE_POINT_FORBIDDEN")

    def test_c1_zip_tampered_internal_manifest_or_path_traversal_rejected(self):
        shadow = self.base / "shadow"
        commit = "1" * 40
        zip_path, valid_sha = _make_c1_source_zip(self.base / "c1.zip", commit=commit, marker_version="v1")

        # Wrong outer SHA-256 fails closed before extracting.
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c1_shadow(
                shadow,
                c1_zip=zip_path,
                c1_zip_sha256="0" * 64,
                c1_expected_commit=commit,
                rpc_port=49173,
                hub_port=49190,
            )
        self.assertEqual(ctx.exception.code, "PINNED_SHA256_MISMATCH")

        # Tamper a file inside ZIP while matching outer SHA-256 -> internal manifest mismatch!
        tampered = self.base / "tampered.zip"
        with zipfile.ZipFile(zip_path, "r") as zin, zipfile.ZipFile(tampered, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "runtime/bridge-v3/ff_win_v3_agent.py":
                    data = b"TAMPERED = True\n"
                zout.writestr(item, data)
        tampered_sha = _sha256_bytes(tampered.read_bytes())
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c1_shadow(
                shadow,
                c1_zip=tampered,
                c1_zip_sha256=tampered_sha,
                c1_expected_commit=commit,
                rpc_port=49173,
                hub_port=49190,
            )
        self.assertEqual(ctx.exception.code, "ARCHIVE_INTERNAL_HASH_MISMATCH")

        # Path traversal inside ZIP fails closed.
        traversal = self.base / "traversal.zip"
        with zipfile.ZipFile(traversal, "w") as zout:
            zout.writestr("../escape.py", b"bad")
            zout.writestr("release-manifest.json", b"{}")
        trav_sha = _sha256_bytes(traversal.read_bytes())
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c1_shadow(
                shadow,
                c1_zip=traversal,
                c1_zip_sha256=trav_sha,
                c1_expected_commit=commit,
                rpc_port=49173,
                hub_port=49190,
            )
        self.assertEqual(ctx.exception.code, "ARCHIVE_PATH_INVALID")

    def test_c2_dirty_repo_and_syntax_error_fail_closed(self):
        shadow = self.base / "shadow-c2"
        repo = self.base / "c2-repo"
        v1, v2 = _make_c2_fixture_repo(repo)

        # Dirty untracked/modified file in worktree fails when clean-head required.
        (repo / "server.py").write_text("# dirty uncommitted change\n", encoding="utf-8", newline="\n")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(
                shadow,
                c2_repo=repo,
                c2_commit=v2,
                gateway_port=49587,
                unified_port=49588,
            )
        self.assertEqual(ctx.exception.code, "C2_REPO_DIRTY")

        # Restore clean v2, then commit a broken syntax commit and verify staging rejects it.
        _git(repo, "checkout", "--", "server.py")
        (repo / "server.py").write_text("def broken(:\n", encoding="utf-8", newline="\n")
        _git(repo, "add", "server.py")
        _git(repo, "commit", "-q", "-m", "broken syntax")
        bad_commit = _git(repo, "rev-parse", "HEAD")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(
                shadow,
                c2_repo=repo,
                c2_commit=bad_commit,
                gateway_port=49587,
                unified_port=49588,
            )
        self.assertEqual(ctx.exception.code, "C2_SYNTAX_COMPILE_FAILED")


class TestSqliteBackupAndProcessIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="ff-canary-proc-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_sqlite_online_backup_live_wal_and_pinned_restore(self):
        src_db = self.base / "live_gateway.db"
        conn = sqlite3.connect(str(src_db), isolation_level=None)
        self.addCleanup(conn.close)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, status TEXT NOT NULL)")
        conn.execute("INSERT INTO jobs VALUES ('j1', 'completed'), ('j2', 'completed')")

        # Keep writer open while backing up strictly via SQLite Online Backup API!
        backup_db = self.base / "backups" / "gateway_backup.db"
        info = canary.sqlite_online_backup(src_db, backup_db, expected_tables=("jobs",))
        self.assertTrue(info["integrity_ok"])
        self.assertEqual(info["row_counts"]["jobs"], 2)
        self.assertEqual(len(info["backup_sha256"]), 64)

        # Mutate live DB, then verify wrong-SHA restore fails closed and right-SHA restores.
        conn.execute("INSERT INTO jobs VALUES ('j3', 'failed')")
        conn.close()

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.sqlite_restore_from_backup(backup_db, "0" * 64, src_db)
        self.assertEqual(ctx.exception.code, "SQLITE_BACKUP_HASH_MISMATCH")

        restored = canary.sqlite_restore_from_backup(backup_db, info["backup_sha256"], src_db)
        self.assertTrue(restored["restored"])
        self.assertTrue(restored["integrity_ok"])
        check = sqlite3.connect(str(src_db))
        try:
            rows = check.execute("SELECT id FROM jobs ORDER BY id").fetchall()
            self.assertEqual(rows, [("j1",), ("j2",)])
        finally:
            check.close()

    @unittest.skipUnless(os.name == "nt", "Windows kernel process identity and leases")
    def test_process_identity_lease_and_active_session_forbid_force_kill(self):
        shadow = self.base / "shadow-proc"
        owner = canary.ensure_shadow_owner(shadow, create=True)
        script = shadow / "state" / "dummy_worker.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")

        proc = subprocess.Popen(
            [sys.executable, str(script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            ident = canary.query_process_identity_exact(proc.pid)
            self.assertIsNotNone(ident)
            lease = canary.write_process_lease(
                shadow,
                role="c2_gateway",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(script),
                port=49587,
                release_id="rel-test-1",
                owner_scope_id=owner["owner_scope_id"],
            )
            verified = canary.verify_process_lease(shadow, "c2_gateway", require_alive=True, check_cmdline=True)
            self.assertTrue(verified["identity_matched"])
            self.assertTrue(verified["alive"])

            # 1) Tampered creation time (simulates PID reuse) -> MUST NOT kill process!
            lease_path = shadow / "leases" / "c2_gateway.lease.json"
            bad_ct = dict(lease, create_time_filetime=lease["create_time_filetime"] + 1)
            lease_path.write_text(json.dumps(bad_ct, indent=2), encoding="utf-8")
            result = canary.stop_leased_process(
                shadow,
                "c2_gateway",
                idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
            )
            self.assertFalse(result["terminated"])
            self.assertEqual(result["reason"], "PID_REUSED_OR_EXITED_NO_KILL")
            self.assertIsNone(proc.poll(), "Process must NOT be killed when creation time mismatches")

            # 2) Tampered executable_path -> MUST raise PROCESS_IDENTITY_MISMATCH and NOT kill!
            bad_exe = dict(lease, executable_path=str(shadow / "state" / "not-python.exe"))
            lease_path.write_text(json.dumps(bad_exe, indent=2), encoding="utf-8")
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                )
            self.assertEqual(ctx.exception.code, "PROCESS_IDENTITY_MISMATCH")
            self.assertIsNone(proc.poll())

            # 2b) Tampered owner_scope_id -> MUST raise PROCESS_LEASE_OWNER_MISMATCH and NOT kill!
            bad_owner = dict(lease, owner_scope_id="foreign-scope-id")
            lease_path.write_text(json.dumps(bad_owner, indent=2), encoding="utf-8")
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                )
            self.assertEqual(ctx.exception.code, "PROCESS_LEASE_OWNER_MISMATCH")
            self.assertIsNone(proc.poll())

            # 3) Valid lease, but ACTIVE SESSIONS present -> MUST REFUSE KILL!
            lease_path.write_text(json.dumps(lease, indent=2), encoding="utf-8")
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": False, "active_sessions": 2, "reason": "ACTIVE_SESSIONS_PRESENT"},
                )
            self.assertEqual(ctx.exception.code, "ACTIVE_SESSIONS_PRESENT")
            self.assertIsNone(proc.poll(), "Active session process must NEVER be force-killed")

            # 4) Valid lease, unknown session state -> fail closed!
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": False, "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL"},
                )
            self.assertEqual(ctx.exception.code, "SESSION_STATE_UNKNOWN_REFUSE_KILL")
            self.assertIsNone(proc.poll())

            # 5) Valid lease AND verified idle -> exact-handle stop succeeds cleanly!
            stopped = canary.stop_leased_process(
                shadow,
                "c2_gateway",
                idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
            )
            self.assertTrue(stopped["stopped"])
            self.assertIsNotNone(proc.wait(timeout=5))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


class TestEndToEndShadowStageHealthRollbackAndReceipts(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="ff-canary-e2e-")
        self.addCleanup(self._ordered_cleanup)
        self.base = Path(self.tmp.name)
        self.shadow = self.base / "shadow-root"
        self.c2_repo = self.base / "c2-repo"
        self.c2_v1, self.c2_v2 = _make_c2_fixture_repo(self.c2_repo)
        self.c1_v1_commit = "a" * 40
        self.c1_v2_commit = "b" * 40
        self.c1_v1_zip, self.c1_v1_sha = _make_c1_source_zip(
            self.base / "c1-v1.zip", commit=self.c1_v1_commit, marker_version="c1-v1"
        )
        self.c1_v2_zip, self.c1_v2_sha = _make_c1_source_zip(
            self.base / "c1-v2.zip", commit=self.c1_v2_commit, marker_version="c1-v2"
        )
        # Seed a mock read-only source gateway.db (representing baseline prod DB never mutated!)
        self.source_c2_db = self.base / "seed_prod_gateway.db"
        conn = sqlite3.connect(str(self.source_c2_db))
        conn.execute(
            "CREATE TABLE jobs(id TEXT PRIMARY KEY, status TEXT NOT NULL, "
            "browser_tab_tracked INTEGER DEFAULT 0, browser_tab_open INTEGER DEFAULT 0, "
            "browser_tab_cleanup_uncertain INTEGER DEFAULT 0)"
        )
        conn.execute("INSERT INTO jobs VALUES ('seed-1', 'completed', 0, 0, 0)")
        conn.commit()
        conn.close()
        self.source_c2_db_sha_before = _sha256_bytes(self.source_c2_db.read_bytes())

    def _ordered_cleanup(self):
        # Stop every owned shadow root BEFORE removing temp files; never mask stop failures
        # and never delete leases/ while owned shadow processes remain alive.
        stop_errors: list[tuple[str, Exception]] = []
        live_after_stop: list[dict] = []
        if self.base.is_dir():
            for marker in sorted(self.base.rglob("canary-shadow-owner.json")):
                shadow_dir = marker.parent
                try:
                    canary.stop_shadow_services(shadow_dir, ignore_missing=True)
                except Exception as exc:
                    stop_errors.append((str(shadow_dir), exc))
                leases_dir = shadow_dir / "leases"
                if leases_dir.is_dir():
                    for lf in sorted(leases_dir.glob("*.lease.json")):
                        role = lf.name[: -len(".lease.json")]
                        try:
                            lv = canary.verify_process_lease(shadow_dir, role, require_alive=False, check_cmdline=True)
                            if lv.get("alive"):
                                live_after_stop.append({"shadow": str(shadow_dir), "role": role, "pid": lv.get("pid")})
                        except Exception as exc:
                            live_after_stop.append({"shadow": str(shadow_dir), "role": role, "verify_error": repr(exc)})
        if stop_errors or live_after_stop:
            raise AssertionError(
                f"Shadow cleanup left live processes or failed to stop; preserved {self.base} "
                f"to keep process leases intact. stop_errors={stop_errors!r}, live_after_stop={live_after_stop!r}"
            )
        canary._retry_windows_fs_op(self.tmp.cleanup, timeout=3.0)

    @unittest.skipUnless(os.name == "nt", "Real Windows shadow E2E lifecycle")
    def test_full_c1_c2_shadow_upgrade_health_active_guard_rollback_and_receipts(self):
        c1_rpc_port, c1_hub_port, c2_gw_port, c2_uni_port, fake_omni_port = _free_ports(5)

        # 1) Stage baseline v1 for both C1 and C2 (with SQLite Online Backup API seeding C2 DB).
        _git(self.c2_repo, "checkout", "-q", self.c2_v1)
        stage_v1 = canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v1_zip,
            c1_zip_sha256=self.c1_v1_sha,
            c1_expected_commit=self.c1_v1_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v1,
            c2_source_db=self.source_c2_db,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="e2e-stage-v1",
        )
        self.assertTrue(stage_v1["ok"])
        self.assertEqual(stage_v1["c1"]["source_commit"], self.c1_v1_commit)
        self.assertEqual(stage_v1["c2"]["source_commit"], self.c2_v1)
        self.assertTrue((self.shadow / "state" / "c2" / "runtime" / "legacy_only.py").is_file())
        # Verify source DB was never mutated!
        self.assertEqual(_sha256_bytes(self.source_c2_db.read_bytes()), self.source_c2_db_sha_before)

        # Idempotent replay with same request_key returns deduplicated receipt without re-running.
        stage_v1_dup = canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v1_zip,
            c1_zip_sha256=self.c1_v1_sha,
            c1_expected_commit=self.c1_v1_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v1,
            c2_source_db=self.source_c2_db,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="e2e-stage-v1",
        )
        self.assertTrue(stage_v1_dup["deduplicated"])

        # Conflicting payload on same request_key fails closed.
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.run_shadow_stage(
                shadow_root=self.shadow,
                c1_zip=self.c1_v2_zip,
                c1_zip_sha256=self.c1_v2_sha,
                c1_expected_commit=self.c1_v2_commit,
                c2_repo=self.c2_repo,
                c2_commit=self.c2_v1,
                c1_rpc_port=c1_rpc_port,
                c1_hub_port=c1_hub_port,
                c2_gateway_port=c2_gw_port,
                c2_unified_port=c2_uni_port,
                c2_omni_port=fake_omni_port,
                request_key="e2e-stage-v1",
            )
        self.assertEqual(ctx.exception.code, "REQUEST_KEY_CONFLICT")

        # 2) Stage candidate v2 over v1 (verifies backup creation and retired file removal).
        _git(self.c2_repo, "checkout", "-q", self.c2_v2)
        stage_v2 = canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v2_zip,
            c1_zip_sha256=self.c1_v2_sha,
            c1_expected_commit=self.c1_v2_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v2,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="e2e-stage-v2",
        )
        self.assertTrue(stage_v2["ok"])
        self.assertFalse((self.shadow / "state" / "c2" / "runtime" / "legacy_only.py").exists())
        self.assertTrue((self.shadow / "state" / "c2" / "runtime" / "candidate_feature.py").is_file())
        pre_v2_c2_backup = stage_v2["c2"]["pre_stage_db_backup"]
        self.assertIsNotNone(pre_v2_c2_backup)

        # 3) Start shadow C1 RPC + C1 Hub + C2 Gateway + C2 Unified API and verify Health Contract.
        started = canary.start_shadow_services(
            self.shadow,
            start_c1_rpc=True,
            start_c1_hub=True,
            start_c2_gateway=True,
            start_c2_unified=True,
        )
        self.assertTrue(started["ok"])
        self.assertIn("c1_rpc", started["services"])
        self.assertIn("c1_hub", started["services"])
        self.assertIn("c2_gateway", started["services"])
        self.assertIn("c2_unified", started["services"])

        health = canary.verify_shadow_health(
            self.shadow,
            check_c1_rpc=True,
            check_c1_hub=True,
            check_c2_gateway=True,
            check_c2_unified=True,
            consecutive_passes=2,
            require_upstream_omniroute=False,
        )
        self.assertTrue(health["shadow_health_ok"], json.dumps(health, indent=2))
        self.assertTrue(health["checks"]["c1_rpc"]["ok"])
        self.assertTrue(health["checks"]["c1_hub"]["entry_v1_authenticated_ok"])
        self.assertEqual(health["checks"]["c2_unified"]["gateway_port"], c2_gw_port)
        # Honest upstream reporting: fake_omni_port is closed, so upstream_omniroute_ok MUST be False!
        self.assertFalse(health["upstream_omniroute_ok"])
        self.assertFalse(health["live_production_cutover_executed"])

        # 4) Open a real active Hub session -> rollback MUST be DENIED without killing Hub!
        hub_client = HubClient(self.shadow / "state" / "c1" / "hub", timeout=30.0)
        hub_client.call("session_open", {"agent_id": "canary-active", "task_id": "keep-alive"})
        try:
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.rollback_canary(self.shadow, confirm_shadow_rollback=True, request_key="rb-denied-hub")
            self.assertEqual(ctx.exception.code, "ACTIVE_SESSIONS_PRESENT")
            # Confirm Hub is STILL alive and session intact!
            self.assertEqual(len(hub_client.call("hub_status")["sessions"]), 1)
        finally:
            _cancel_hub_session_reconciled(hub_client, "cancel-canary-active")

        # 5) Insert an active job into shadow C2 gateway.db -> rollback MUST be DENIED without killing C2!
        c2_db_path = self.shadow / "state" / "c2" / "runtime" / "gateway.db"
        conn = sqlite3.connect(str(c2_db_path))
        conn.execute("INSERT INTO jobs VALUES ('active-job-1', 'running', 0, 0, 0)")
        conn.commit()
        conn.close()
        try:
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.rollback_canary(self.shadow, confirm_shadow_rollback=True, request_key="rb-denied-c2")
            self.assertEqual(ctx.exception.code, "ACTIVE_C2_JOBS_PRESENT")
            # Confirm C2 Gateway process is STILL alive!
            gw_lease = canary.verify_process_lease(self.shadow, "c2_gateway", require_alive=True)
            self.assertTrue(gw_lease["alive"])
        finally:
            conn = sqlite3.connect(str(c2_db_path))
            conn.execute("UPDATE jobs SET status='completed' WHERE id='active-job-1'")
            conn.commit()
            conn.close()

        # 6) Now all sessions/jobs are idle -> execute real rollback (including SQLite Backup API restore of C2 DB)!
        rb = canary.rollback_canary(
            self.shadow,
            confirm_shadow_rollback=True,
            restore_c2_db_backup=Path(pre_v2_c2_backup["backup_path"]),
            restore_c2_db_backup_sha256=pre_v2_c2_backup["backup_sha256"],
            request_key="rb-real-success",
        )
        self.assertTrue(rb["ok"])
        self.assertEqual(rb["c1"]["restored_release_id"], stage_v1["c1"]["release_id"])
        self.assertEqual(rb["c2"]["restored_release_id"], stage_v1["c2"]["release_id"])
        self.assertTrue(rb["c2"]["db_restored"])
        # Idempotent replay of a completed rollback MUST return ok=True and deduplicated=True!
        rb_dup = canary.rollback_canary(
            self.shadow,
            confirm_shadow_rollback=True,
            restore_c2_db_backup=Path(pre_v2_c2_backup["backup_path"]),
            restore_c2_db_backup_sha256=pre_v2_c2_backup["backup_sha256"],
            request_key="rb-real-success",
        )
        self.assertTrue(rb_dup["ok"])
        self.assertTrue(rb_dup["deduplicated"])
        self.assertEqual(rb_dup["status"], "rolled_back")
        # Confirm every shadow port was released and zero leased processes remain alive.
        for role in ("c1_hub", "c1_rpc", "c2_gateway", "c2_unified"):
            self.assertFalse(canary.verify_process_lease(self.shadow, role, require_alive=False)["alive"])
        for port in (c1_rpc_port, c1_hub_port, c2_gw_port, c2_uni_port):
            self.assertTrue(canary._is_loopback_port_free(port), f"port {port} still occupied after rollback stop")
        self.assertTrue((self.shadow / "state" / "c2" / "runtime" / "legacy_only.py").is_file())
        self.assertFalse((self.shadow / "state" / "c2" / "runtime" / "candidate_feature.py").exists())
        # Verify C2 source git repo HEAD was NEVER touched by rollback!
        self.assertEqual(_git(self.c2_repo, "rev-parse", "HEAD"), self.c2_v2)

        # Verify C2 gateway.db reverted to pre-v2 seed ('seed-1' present, 'active-job-1' gone).
        conn = sqlite3.connect(str(c2_db_path))
        try:
            ids = [r[0] for r in conn.execute("SELECT id FROM jobs ORDER BY id").fetchall()]
            self.assertEqual(ids, ["seed-1"])
        finally:
            conn.close()

        # Verify persistent SQLite receipts & unbroken hash chain survived rollback!
        store = canary.CanaryReceiptStore(self.shadow / "state" / "canary_receipts.sqlite3")
        chain = store.verify_receipt_chain()
        self.assertTrue(chain["ok"])
        self.assertGreaterEqual(chain["receipts_verified"], 5)
        # Verify entry-grants.sqlite3 receipts from /agent/v1 health check also survived rollback!
        eg_db = sqlite3.connect(str(self.shadow / "state" / "c1" / "hub" / "entry-grants.sqlite3"))
        try:
            actions = [r[0] for r in eg_db.execute("SELECT action FROM grant_receipts ORDER BY at").fetchall()]
            self.assertIn("issue", actions)
        finally:
            eg_db.close()

        # 7) Tampering receipt chain MUST be detected!
        rc_conn = sqlite3.connect(str(self.shadow / "state" / "canary_receipts.sqlite3"))
        rc_conn.execute("UPDATE canary_receipt_chain SET status='tampered' WHERE seq=1")
        rc_conn.commit()
        rc_conn.close()
        with self.assertRaises(canary.CanaryError) as ctx:
            store.verify_receipt_chain()
        self.assertEqual(ctx.exception.code, "RECEIPT_CHAIN_CORRUPTED")

    def test_owner_cutover_gate_fails_closed_without_readiness_and_approval(self):
        # Missing readiness & approval files fails closed.
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.verify_owner_cutover_gate(
                readiness_path=None,
                approval_path=None,
                expected_c1_zip_sha256=self.c1_v2_sha,
                expected_c2_commit=self.c2_v2,
            )
        self.assertEqual(ctx.exception.code, "OWNER_CUTOVER_READINESS_REQUIRED")

        readiness = self.base / "readiness.json"
        approval = self.base / "approval.json"
        readiness.write_text(json.dumps({
            "schema": "ff-canary-cutover-readiness-v1",
            "shadow_health_ok": True,
            "c1_zip_sha256": self.c1_v2_sha,
            "c2_commit": self.c2_v2,
            "receipt_chain_verified": True,
        }), encoding="utf-8")

        # Expired approval fails closed.
        approval.write_text(json.dumps({
            "schema": "ff-canary-owner-approval-v1",
            "approved": True,
            "c1_zip_sha256": self.c1_v2_sha,
            "c2_commit": self.c2_v2,
            "expires_epoch": time.time() - 60,
            "owner_statement": "Expired test approval",
            "active_sessions_drain_acknowledged": True,
        }), encoding="utf-8")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.verify_owner_cutover_gate(
                readiness_path=readiness,
                approval_path=approval,
                expected_c1_zip_sha256=self.c1_v2_sha,
                expected_c2_commit=self.c2_v2,
            )
        self.assertEqual(ctx.exception.code, "OWNER_APPROVAL_EXPIRED")

        # Mismatched artifact hash fails closed.
        approval.write_text(json.dumps({
            "schema": "ff-canary-owner-approval-v1",
            "approved": True,
            "c1_zip_sha256": self.c1_v1_sha,
            "c2_commit": self.c2_v2,
            "expires_epoch": time.time() + 600,
            "owner_statement": "Wrong hash approval",
            "active_sessions_drain_acknowledged": True,
        }), encoding="utf-8")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.verify_owner_cutover_gate(
                readiness_path=readiness,
                approval_path=approval,
                expected_c1_zip_sha256=self.c1_v2_sha,
                expected_c2_commit=self.c2_v2,
            )
        self.assertEqual(ctx.exception.code, "OWNER_APPROVAL_ARTIFACT_MISMATCH")

        # Valid readiness + valid unexpired approval still forbids automatic production restart!
        approval.write_text(json.dumps({
            "schema": "ff-canary-owner-approval-v1",
            "approved": True,
            "c1_zip_sha256": self.c1_v2_sha,
            "c2_commit": self.c2_v2,
            "expires_epoch": time.time() + 600,
            "owner_statement": "Verified manual cutover authorization test",
            "active_sessions_drain_acknowledged": True,
        }), encoding="utf-8")
        gate = canary.verify_owner_cutover_gate(
            readiness_path=readiness,
            approval_path=approval,
            expected_c1_zip_sha256=self.c1_v2_sha,
            expected_c2_commit=self.c2_v2,
        )
        self.assertTrue(gate["gate_verified"])
        self.assertFalse(gate["automatic_production_restart_allowed"])
        self.assertFalse(gate["live_production_mutated"])

    def test_c2_pinned_zip_staging_and_rollback_backup_sha_checks(self):
        shadow = self.base / "shadow-c2-zip"
        c2_zip = self.base / "c2-bundle.zip"
        with zipfile.ZipFile(c2_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("server.py", b"SERVER_V = 1\n")
            zf.writestr("unified_api.py", b"UNIFIED_V = 1\n")
            zf.writestr("idempotency_utils.py", b"IDEMP_V = 1\n")
            # Simulate stray host DB inside ZIP: must NEVER be copied into immutable release!
            zf.writestr("gateway.db", b"should-be-ignored")
        c2_sha = _sha256_bytes(c2_zip.read_bytes())

        # Empty / wrong C2 ZIP SHA-256 fails closed!
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(shadow, c2_zip=c2_zip, c2_zip_sha256="", gateway_port=49587, unified_port=49588)
        self.assertEqual(ctx.exception.code, "PINNED_SHA256_REQUIRED")

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(shadow, c2_zip=c2_zip, c2_zip_sha256="f" * 64, gateway_port=49587, unified_port=49588)
        self.assertEqual(ctx.exception.code, "PINNED_SHA256_MISMATCH")

        # Valid C2 ZIP SHA-256 succeeds and strips stray host gateway.db!
        staged = canary.stage_c2_shadow(
            shadow,
            c2_zip=c2_zip,
            c2_zip_sha256=c2_sha,
            c2_commit="c" * 40,
            gateway_port=49587,
            unified_port=49588,
        )
        self.assertTrue(staged["ok"])
        self.assertEqual(staged["verified_files"], 3)
        self.assertFalse((shadow / "releases" / "c2" / staged["release_id"] / "gateway.db").exists())

        # Older C2 baseline (server.py + unified_api.py without newer helper modules) stages cleanly,
        # while a bundle missing server.py or unified_api.py fails closed with C2_REQUIRED_FILE_MISSING.
        legacy_zip = self.base / "c2-legacy.zip"
        with zipfile.ZipFile(legacy_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("server.py", b"LEGACY_SERVER = 1\n")
            zf.writestr("unified_api.py", b"LEGACY_UNIFIED = 1\n")
        legacy_sha = _sha256_bytes(legacy_zip.read_bytes())
        legacy_staged = canary.stage_c2_shadow(
            shadow,
            c2_zip=legacy_zip,
            c2_zip_sha256=legacy_sha,
            c2_commit="d" * 40,
            gateway_port=49587,
            unified_port=49588,
        )
        self.assertTrue(legacy_staged["ok"])
        self.assertEqual(legacy_staged["verified_files"], 2)

        incomplete_zip = self.base / "c2-incomplete.zip"
        with zipfile.ZipFile(incomplete_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("server.py", b"ONLY_SERVER = 1\n")
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(
                shadow,
                c2_zip=incomplete_zip,
                c2_zip_sha256=_sha256_bytes(incomplete_zip.read_bytes()),
                c2_commit="e" * 40,
                gateway_port=49587,
                unified_port=49588,
            )
        self.assertEqual(ctx.exception.code, "C2_REQUIRED_FILE_MISSING")

        # Rollback with wrong baseline ZIP SHA-256 or wrong DB backup SHA-256 fails closed!
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.rollback_canary(
                shadow,
                confirm_shadow_rollback=True,
                c1_baseline_zip=self.c1_v1_zip,
                c1_baseline_zip_sha256="0" * 64,
            )
        self.assertEqual(ctx.exception.code, "PINNED_SHA256_MISMATCH")

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.rollback_canary(
                shadow,
                confirm_shadow_rollback=True,
                restore_c2_db_backup=self.source_c2_db,
                restore_c2_db_backup_sha256="0" * 64,
            )
        self.assertEqual(ctx.exception.code, "SQLITE_BACKUP_HASH_MISMATCH")

    @unittest.skipUnless(os.name == "nt", "Windows single-handle identity, port guards, and partial startup rollback")
    def test_single_handle_identity_port_guards_and_partial_startup_cleanup(self):
        # 1) Native single-handle NtQueryInformationProcess returns exact cmdline without PowerShell!
        self_ident = canary.query_process_identity_exact(os.getpid(), include_cmdline=True)
        self.assertIsNotNone(self_ident)
        self.assertIsInstance(self_ident.get("cmdline"), str)
        self.assertIn("python", self_ident["cmdline"].casefold())

        # 2) Stage C1 + C2, then occupy c2_gateway port with a local socket BEFORE starting:
        #    start_shadow_services must roll back the just-started c1_hub cleanly with ZERO leaks!
        c1_rpc_port, c1_hub_port, c2_gw_port, c2_uni_port, fake_omni_port = _free_ports(5)
        _git(self.c2_repo, "checkout", "-q", self.c2_v2)
        canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v2_zip,
            c1_zip_sha256=self.c1_v2_sha,
            c1_expected_commit=self.c1_v2_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v2,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="partial-start-stage",
        )
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        blocker.bind(("127.0.0.1", c2_gw_port))
        blocker.listen(1)
        try:
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.start_shadow_services(
                    self.shadow,
                    start_c1_rpc=False,
                    start_c1_hub=True,
                    start_c2_gateway=True,
                    start_c2_unified=False,
                )
            self.assertEqual(ctx.exception.code, "SHADOW_PORT_ALREADY_IN_USE")
        finally:
            blocker.close()

        # Verify c1_hub was rolled back cleanly (not orphaned!) and its port & lock are free!
        hub_lease = canary.verify_process_lease(self.shadow, "c1_hub", require_alive=False, check_cmdline=True)
        self.assertFalse(hub_lease["alive"])
        self.assertTrue(canary._is_loopback_port_free(c1_hub_port))
        self.assertTrue(canary._wait_hub_lock_released(self.shadow / "state" / "c1" / "hub", timeout=2.0))

        # 3) Start c1_hub + c2_gateway cleanly; duplicate start MUST fail closed with SHADOW_SERVICE_ALREADY_RUNNING,
        #    and re-staging C2 while c2_gateway is alive MUST fail closed with SHADOW_SERVICE_RUNNING!
        started = canary.start_shadow_services(
            self.shadow,
            start_c1_rpc=False,
            start_c1_hub=True,
            start_c2_gateway=True,
            start_c2_unified=False,
        )
        self.assertTrue(started["ok"])
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.start_shadow_services(
                self.shadow,
                start_c1_rpc=False,
                start_c1_hub=True,
                start_c2_gateway=False,
                start_c2_unified=False,
            )
        self.assertEqual(ctx.exception.code, "SHADOW_SERVICE_ALREADY_RUNNING")

        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c2_shadow(
                self.shadow,
                c2_repo=self.c2_repo,
                c2_commit=self.c2_v2,
                gateway_port=c2_gw_port,
                unified_port=c2_uni_port,
                omni_port=fake_omni_port,
            )
        self.assertEqual(ctx.exception.code, "SHADOW_SERVICE_RUNNING")

    @unittest.skipUnless(os.name == "nt", "Windows Hub cancel receipt reconciliation and graceful disconnect stop")
    def test_hub_cancel_lost_reply_reconciliation_and_graceful_stop_disconnect(self):
        c1_rpc_port, c1_hub_port = _free_ports(2)
        canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v1_zip,
            c1_zip_sha256=self.c1_v1_sha,
            c1_expected_commit=self.c1_v1_commit,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            skip_c2=True,
            request_key="hub-reconcile-stage",
        )
        canary.start_shadow_services(
            self.shadow,
            start_c1_rpc=False,
            start_c1_hub=True,
            start_c2_gateway=False,
            start_c2_unified=False,
        )
        hub_state = self.shadow / "state" / "c1" / "hub"
        hub_client = HubClient(hub_state, timeout=30.0)
        hub_client.call("session_open", {"agent_id": "reconcile-agent", "task_id": "lost-reply"})

        # Simulate lost reply after server executed task_cancel: first call runs task_cancel
        # on server but raises HUB_UNREACHABLE to caller; reconciliation via request_status succeeds!
        real_raw = hub_client.raw
        injected = {"dropped": False}

        def drop_first_cancel_reply(req):
            reply = real_raw(req)
            if req.get("op") == "task_cancel" and not injected["dropped"]:
                injected["dropped"] = True
                raise HubError("HUB_UNREACHABLE", "simulated lost reply after commit", retry_safe=False)
            return reply

        hub_client.raw = drop_first_cancel_reply
        reconciled = _cancel_hub_session_reconciled(hub_client, "cancel-lost-reply-01")
        self.assertTrue(reconciled["closed"])
        self.assertTrue(injected["dropped"])
        self.assertEqual(hub_client.call("hub_status")["sessions"], [])

        # Graceful stop when Hub reports HUB_BUSY -> fails closed as ACTIVE_SESSIONS_PRESENT without kill!
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stop_leased_process(
                self.shadow,
                "c1_hub",
                idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                graceful_stop=lambda: (_ for _ in ()).throw(canary.CanaryError("HUB_BUSY", "busy")),
            )
        self.assertEqual(ctx.exception.code, "ACTIVE_SESSIONS_PRESENT")
        self.assertTrue(canary.verify_process_lease(self.shadow, "c1_hub", require_alive=True)["alive"])

        # Graceful stop when socket drops while Hub stays alive -> fails closed (no force kill)!
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stop_leased_process(
                self.shadow,
                "c1_hub",
                idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                graceful_stop=lambda: (_ for _ in ()).throw(canary.CanaryError("HUB_UNREACHABLE", "timeout")),
                timeout_seconds=0.4,
            )
        self.assertEqual(ctx.exception.code, "HUB_UNREACHABLE")
        self.assertTrue(canary.verify_process_lease(self.shadow, "c1_hub", require_alive=True)["alive"])

        # Graceful stop where Hub actually shuts down AND socket drops mid-reply -> SYNCHRONIZE handle confirms exit!
        def shutdown_then_disconnect():
            canary._hub_rpc_call(hub_state, "hub_shutdown_idle", timeout=15.0)
            raise canary.CanaryError("HUB_UNREACHABLE", "simulated disconnect during shutdown")

        res = canary.stop_leased_process(
            self.shadow,
            "c1_hub",
            idle_checker=lambda: canary.inspect_c1_hub_active_sessions(hub_state, require_rpc_if_running=True),
            graceful_stop=shutdown_then_disconnect,
            post_exit_wait=lambda: canary._wait_hub_lock_released(hub_state, timeout=5.0),
        )
        self.assertTrue(res["stopped"])
        self.assertTrue(res["graceful"])
        self.assertFalse(canary.verify_process_lease(self.shadow, "c1_hub", require_alive=False)["alive"])
        self.assertTrue(canary._is_loopback_port_free(c1_hub_port))

    def test_receipt_cross_action_conflict_and_started_outcome_unknown(self):
        canary.ensure_shadow_owner(self.shadow, create=True)
        store = canary.CanaryReceiptStore(self.shadow / "state" / "canary_receipts.sqlite3")

        # 1) Cross-action reuse of request_key with identical payload MUST raise REQUEST_KEY_CONFLICT!
        run_id, cached = store.begin_run("stage_shadow", "shadow", request_key="shared-key-1", request_payload={"a": 1})
        self.assertIsNone(cached)
        store.finish_run(run_id, "succeeded", summary={"ok": True})
        with self.assertRaises(canary.CanaryError) as ctx:
            store.begin_run("rollback", "shadow", request_key="shared-key-1", request_payload={"a": 1})
        self.assertEqual(ctx.exception.code, "REQUEST_KEY_CONFLICT")

        # 2) Interrupted/crashed run stuck in 'started' MUST fail closed with REQUEST_OUTCOME_UNKNOWN!
        stuck_id, cached2 = store.begin_run("rollback", "shadow", request_key="interrupted-rb-1", request_payload={"x": 2})
        self.assertIsNone(cached2)
        self.assertTrue(stuck_id.startswith("crun-"))
        with self.assertRaises(canary.CanaryError) as ctx:
            store.begin_run("rollback", "shadow", request_key="interrupted-rb-1", request_payload={"x": 2})
        self.assertEqual(ctx.exception.code, "REQUEST_OUTCOME_UNKNOWN")

    @unittest.skipUnless(os.name == "nt", "Windows ordered teardown lease preservation")
    def test_ordered_cleanup_preserves_leases_when_stop_is_refused(self):
        c1_rpc_port, c1_hub_port = _free_ports(2)
        canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v1_zip,
            c1_zip_sha256=self.c1_v1_sha,
            c1_expected_commit=self.c1_v1_commit,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            skip_c2=True,
            request_key="cleanup-preserve-stage",
        )
        canary.start_shadow_services(
            self.shadow,
            start_c1_rpc=False,
            start_c1_hub=True,
            start_c2_gateway=False,
            start_c2_unified=False,
        )
        hub_client = HubClient(self.shadow / "state" / "c1" / "hub", timeout=30.0)
        hub_client.call("session_open", {"agent_id": "cleanup-guard", "task_id": "busy"})
        try:
            # Ordered cleanup MUST fail loudly and keep leases/c1_hub.lease.json intact (never orphan!).
            with self.assertRaises(AssertionError) as ctx:
                self._ordered_cleanup()
            self.assertIn("ACTIVE_SESSIONS_PRESENT", str(ctx.exception))
            self.assertTrue((self.shadow / "leases" / "c1_hub.lease.json").is_file())
            self.assertTrue(canary.verify_process_lease(self.shadow, "c1_hub", require_alive=True)["alive"])
        finally:
            _cancel_hub_session_reconciled(hub_client, "cancel-cleanup-guard")

    @unittest.skipUnless(os.name == "nt", "Windows 4-factor executable hash, cmdline boundary, and fail-closed kill handle")
    def test_4factor_executable_hash_cmdline_boundary_and_fail_closed_kill_handle(self):
        from unittest import mock

        owner = canary.ensure_shadow_owner(self.shadow, create=True)
        script = self.shadow / "state" / "dummy_worker.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")

        # Cmdline path matching MUST enforce argument boundaries (no prefix-collision spoofing!).
        self.assertFalse(
            canary._cmdline_contains_path(
                f'"{sys.executable}" "{script}.evil"',
                str(script),
            )
        )
        self.assertTrue(
            canary._cmdline_contains_path(
                f'"{sys.executable}" "{script}" --worker',
                str(script),
            )
        )

        proc = subprocess.Popen(
            [sys.executable, str(script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            ident = canary.query_process_identity_exact(proc.pid)
            self.assertIsNotNone(ident)
            expected_exe_sha = canary.sha256_file(Path(ident["executable_path"]))
            lease = canary.write_process_lease(
                self.shadow,
                role="c2_gateway",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(script),
                port=_free_ports(1)[0],
                release_id="rel-hash-test",
                owner_scope_id=owner["owner_scope_id"],
            )
            # Factor 3 MUST bind the cryptographic SHA-256 hash of the executable image!
            self.assertEqual(lease.get("executable_sha256"), expected_exe_sha)
            verified = canary.verify_process_lease(self.shadow, "c2_gateway", require_alive=True, check_cmdline=True)
            self.assertEqual(verified.get("executable_sha256"), expected_exe_sha)

            lease_path = self.shadow / "leases" / "c2_gateway.lease.json"

            # Negative 1: Tampered executable_sha256 -> PROCESS_IDENTITY_MISMATCH, MUST NOT kill!
            bad_hash_lease = dict(lease, executable_sha256="0" * 64)
            lease_path.write_text(json.dumps(bad_hash_lease, indent=2), encoding="utf-8")
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    self.shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                )
            self.assertEqual(ctx.exception.code, "PROCESS_IDENTITY_MISMATCH")
            self.assertIsNone(proc.poll(), "Process must NEVER be killed when executable_sha256 mismatches")

            # Negative 2: Missing executable_sha256 -> PROCESS_LEASE_INVALID, MUST NOT kill!
            no_hash_lease = {k: v for k, v in lease.items() if k != "executable_sha256"}
            lease_path.write_text(json.dumps(no_hash_lease, indent=2), encoding="utf-8")
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.stop_leased_process(
                    self.shadow,
                    "c2_gateway",
                    idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                )
            self.assertEqual(ctx.exception.code, "PROCESS_LEASE_INVALID")
            self.assertIsNone(proc.poll())

            # Negative 3: Unreadable cmdline on the kill handle MUST fail closed (never kill on None/empty!).
            lease_path.write_text(json.dumps(lease, indent=2), encoding="utf-8")
            real_query_cmd = canary._query_handle_cmdline
            calls = {"n": 0}

            def fail_on_kill_handle(handle):
                calls["n"] += 1
                # First call is verify_process_lease; second call is the actual TerminateProcess handle!
                if calls["n"] >= 2:
                    return None
                return real_query_cmd(handle)

            with mock.patch.object(canary, "_query_handle_cmdline", side_effect=fail_on_kill_handle), \
                 mock.patch.object(canary, "_query_process_cmdline_cim", return_value=None):
                with self.assertRaises(canary.CanaryError) as ctx:
                    canary.stop_leased_process(
                        self.shadow,
                        "c2_gateway",
                        idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
                    )
                self.assertEqual(ctx.exception.code, "PROCESS_IDENTITY_MISMATCH")
                self.assertIsNone(proc.poll(), "Kill handle MUST fail closed when cmdline cannot be read")

            # Valid 4-factor lease stops the verified idle process cleanly.
            stopped = canary.stop_leased_process(
                self.shadow,
                "c2_gateway",
                idle_checker=lambda: {"idle_verified": True, "active_sessions": 0},
            )
            self.assertTrue(stopped["stopped"])
            self.assertIsNotNone(proc.wait(timeout=5))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    def test_sqlite_locked_backup_restore_and_readonly_receipts_fail_closed(self):
        # 1) Read-only receipt verification on missing DB must NOT create file and MUST fail closed!
        missing_receipts = self.base / "never-created" / "canary_receipts.sqlite3"
        ro_store = canary.CanaryReceiptStore(missing_receipts, readonly=True)
        self.assertFalse(missing_receipts.exists())
        with self.assertRaises(canary.CanaryError) as ctx:
            ro_store.verify_receipt_chain()
        self.assertEqual(ctx.exception.code, "RECEIPT_CHAIN_CORRUPTED")
        self.assertFalse(missing_receipts.exists())

        # 2) SQLite locked receipt DB fails closed with structured SQLITE_RECEIPT_LOCKED!
        rc_path = self.base / "locked-receipts.sqlite3"
        rw_store = canary.CanaryReceiptStore(rc_path, timeout=0.3)
        lock_conn = sqlite3.connect(str(rc_path), isolation_level=None, timeout=1.0)
        try:
            lock_conn.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(canary.CanaryError) as ctx:
                rw_store.begin_run("stage_shadow", "shadow", request_key="locked-key-1")
            self.assertEqual(ctx.exception.code, "SQLITE_RECEIPT_LOCKED")
        finally:
            if lock_conn.in_transaction:
                lock_conn.execute("ROLLBACK")
            lock_conn.close()

        # 3) SQLite online backup fails FAST (bounded deadline, never hangs!) on EXCLUSIVE-locked
        #    DELETE-mode DB with zero leftover .bkp.tmp files and cleanly released handles!
        excl_db = self.base / "excl_source.db"
        c_excl = sqlite3.connect(str(excl_db), isolation_level=None)
        try:
            c_excl.execute("PRAGMA journal_mode=DELETE")
            c_excl.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, status TEXT)")
            c_excl.execute("INSERT INTO jobs VALUES ('j0', 'completed')")
            c_excl.execute("BEGIN EXCLUSIVE")
            c_excl.execute("INSERT INTO jobs VALUES ('j1', 'running')")
            out_bkp = self.base / "backups" / "should_not_exist.db"
            t0 = time.monotonic()
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.sqlite_online_backup(excl_db, out_bkp, timeout=0.35)
            elapsed = time.monotonic() - t0
            self.assertEqual(ctx.exception.code, "SQLITE_BACKUP_LOCKED")
            self.assertLess(elapsed, 2.5, f"Preflight EXCLUSIVE lock backup hung ({elapsed:.2f}s)")
            self.assertFalse(out_bkp.exists())
            self.assertEqual(list(out_bkp.parent.glob("*.bkp.tmp*")), [])

            # 3b) Adversarial mid-backup SQLITE_BUSY race (preflight bypassed, lock held DURING
            #     sqlite3.Connection.backup): bounded progress deadline MUST abort cleanly without
            #     hanging, close both handles, and leave ZERO 0-byte .bkp.tmp files!
            from unittest import mock

            t1 = time.monotonic()
            with mock.patch.object(canary, "_sqlite_preflight_readable", return_value=None):
                with self.assertRaises(canary.CanaryError) as ctx_mid:
                    canary.sqlite_online_backup(excl_db, out_bkp, timeout=0.35, pages=1)
            elapsed_mid = time.monotonic() - t1
            self.assertEqual(ctx_mid.exception.code, "SQLITE_BACKUP_LOCKED")
            self.assertLess(elapsed_mid, 2.5, f"Mid-backup SQLITE_BUSY hung ({elapsed_mid:.2f}s)")
            self.assertFalse(out_bkp.exists())
            self.assertEqual(list(out_bkp.parent.glob("*.bkp.tmp*")), [])

            # 3c) Same bounded deadline applies to sqlite_restore_from_backup on EXCLUSIVE-locked source!
            excl_sha = canary.sha256_file(excl_db)
            restored_dst = self.base / "backups" / "restore_should_not_exist.db"
            t2 = time.monotonic()
            with self.assertRaises(canary.CanaryError) as ctx_res:
                canary.sqlite_restore_from_backup(excl_db, excl_sha, restored_dst, timeout=0.35)
            elapsed_res = time.monotonic() - t2
            self.assertEqual(ctx_res.exception.code, "SQLITE_BACKUP_LOCKED")
            self.assertLess(elapsed_res, 2.5, f"Locked restore source hung ({elapsed_res:.2f}s)")
            self.assertFalse(restored_dst.exists())
            self.assertEqual(list(restored_dst.parent.glob("*.restore.tmp*")), [])
        finally:
            if c_excl.in_transaction:
                c_excl.execute("ROLLBACK")
            c_excl.close()

        # After lock release, online backup succeeds cleanly with full integrity!
        ok_bkp = self.base / "backups" / "unlocked_ok.db"
        ok_info = canary.sqlite_online_backup(excl_db, ok_bkp, expected_tables=("jobs",), timeout=5.0)
        self.assertTrue(ok_info["integrity_ok"])
        self.assertEqual(ok_info["row_counts"]["jobs"], 1)

        # 4) SQLite restore MUST refuse locked WAL target WITHOUT deleting target-wal or losing live rows!
        if os.name == "nt":
            target_db = self.base / "live_wal_target.db"
            bkp_db = self.base / "clean_backup.db"
            c_live = sqlite3.connect(str(target_db), isolation_level=None)
            try:
                c_live.execute("PRAGMA journal_mode=WAL")
                c_live.execute("PRAGMA wal_autocheckpoint=0")
                c_live.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, status TEXT)")
                c_live.execute("INSERT INTO jobs VALUES ('seed', 'completed')")
                bkp_info = canary.sqlite_online_backup(target_db, bkp_db, expected_tables=("jobs",))
                # Write a new row that lives only in -wal while connection stays open!
                c_live.execute("INSERT INTO jobs VALUES ('uncheckpointed-wal-row', 'running')")
                wal_path = Path(str(target_db) + "-wal")
                self.assertTrue(wal_path.is_file() and wal_path.stat().st_size > 0)

                with self.assertRaises(canary.CanaryError) as ctx:
                    canary.sqlite_restore_from_backup(
                        bkp_db,
                        bkp_info["backup_sha256"],
                        target_db,
                        timeout=0.3,
                    )
                self.assertEqual(ctx.exception.code, "SQLITE_TARGET_LOCKED")
                self.assertTrue(wal_path.is_file(), "Locked restore MUST NEVER unlink live target -wal file!")
            finally:
                c_live.close()

            # Confirm the live WAL row survived the refused restore intact!
            c_verify = sqlite3.connect(str(target_db))
            try:
                ids = [r[0] for r in c_verify.execute("SELECT id FROM jobs ORDER BY id").fetchall()]
                self.assertEqual(ids, ["seed", "uncheckpointed-wal-row"])
            finally:
                c_verify.close()

    @unittest.skipUnless(os.name == "nt", "Windows C2 health identity, wildcard port occupation, C1 running guard, and baseline pin")
    def test_c2_health_identity_port_occupied_and_rollback_baseline_pinning(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        c1_rpc_port, c1_hub_port, c2_gw_port, c2_uni_port, fake_omni_port = _free_ports(5)
        _git(self.c2_repo, "checkout", "-q", self.c2_v1)
        canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v1_zip,
            c1_zip_sha256=self.c1_v1_sha,
            c1_expected_commit=self.c1_v1_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v1,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="ident-stage-v1",
        )
        _git(self.c2_repo, "checkout", "-q", self.c2_v2)
        canary.run_shadow_stage(
            shadow_root=self.shadow,
            c1_zip=self.c1_v2_zip,
            c1_zip_sha256=self.c1_v2_sha,
            c1_expected_commit=self.c1_v2_commit,
            c2_repo=self.c2_repo,
            c2_commit=self.c2_v2,
            c1_rpc_port=c1_rpc_port,
            c1_hub_port=c1_hub_port,
            c2_gateway_port=c2_gw_port,
            c2_unified_port=c2_uni_port,
            c2_omni_port=fake_omni_port,
            request_key="ident-stage-v2",
        )

        # 1) Wildcard 0.0.0.0 SO_REUSEADDR listener (foreign process port) MUST be detected as occupied!
        wild = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        wild.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        wild.bind(("0.0.0.0", c2_gw_port))
        wild.listen(1)
        try:
            self.assertFalse(canary._is_loopback_port_free(c2_gw_port))
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.start_shadow_services(
                    self.shadow,
                    start_c1_rpc=False,
                    start_c1_hub=True,
                    start_c2_gateway=True,
                    start_c2_unified=False,
                )
            self.assertEqual(ctx.exception.code, "SHADOW_PORT_ALREADY_IN_USE")
        finally:
            wild.close()

        # 2) Start real C1 Hub + C2 Gateway + C2 Unified and verify kernel listener_pid_verified == True!
        canary.start_shadow_services(
            self.shadow,
            start_c1_rpc=False,
            start_c1_hub=True,
            start_c2_gateway=True,
            start_c2_unified=True,
        )
        health = canary.verify_shadow_health(
            self.shadow,
            check_c1_rpc=False,
            check_c1_hub=True,
            check_c2_gateway=True,
            check_c2_unified=True,
            consecutive_passes=1,
        )
        self.assertTrue(health["shadow_health_ok"])
        self.assertTrue(health["checks"]["c1_hub"].get("listener_pid_verified"))
        self.assertTrue(health["checks"]["c2_gateway"].get("listener_pid_verified"))
        self.assertTrue(health["checks"]["c2_unified"].get("listener_pid_verified"))

        # 3) Re-staging C1 while c1_hub is alive (even with 0 active sessions!) MUST fail closed!
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.stage_c1_shadow(
                self.shadow,
                c1_zip=self.c1_v1_zip,
                c1_zip_sha256=self.c1_v1_sha,
                c1_expected_commit=self.c1_v1_commit,
                rpc_port=c1_rpc_port,
                hub_port=c1_hub_port,
            )
        self.assertEqual(ctx.exception.code, "SHADOW_SERVICE_RUNNING")

        # 4) Rollback with tampered lease executable_sha256 MUST fail closed BEFORE stopping ANY process!
        gw_lease_path = self.shadow / "leases" / "c2_gateway.lease.json"
        orig_gw_lease_text = gw_lease_path.read_text(encoding="utf-8")
        gw_lease_obj = json.loads(orig_gw_lease_text)
        gw_lease_path.write_text(json.dumps({**gw_lease_obj, "executable_sha256": "f" * 64}), encoding="utf-8")
        try:
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.rollback_canary(self.shadow, confirm_shadow_rollback=True, request_key="rb-lease-mismatch")
            self.assertEqual(ctx.exception.code, "PROCESS_IDENTITY_MISMATCH")
            # Neither C2 Gateway nor C1 Hub was killed!
            self.assertTrue(canary.verify_process_lease(self.shadow, "c1_hub", require_alive=True)["alive"])
            self.assertIsNotNone(canary.query_process_identity_exact(gw_lease_obj["pid"]))
        finally:
            gw_lease_path.write_text(orig_gw_lease_text, encoding="utf-8")

        # 5) Rollback with c1_baseline_zip pointing to v2 while previous_release_id is v1 MUST fail closed!
        canary.stop_shadow_services(self.shadow, ignore_missing=True)
        with self.assertRaises(canary.CanaryError) as ctx:
            canary.rollback_canary(
                self.shadow,
                confirm_shadow_rollback=True,
                c1_baseline_zip=self.c1_v2_zip,
                c1_baseline_zip_sha256=self.c1_v2_sha,
                request_key="rb-wrong-baseline-pin",
            )
        self.assertEqual(ctx.exception.code, "PINNED_SHA256_MISMATCH")

        # 6) Impostor listener on c2_gateway port (owned by test PID, NOT leased dummy worker PID):
        #    verify_shadow_health MUST reject with HEALTH_IDENTITY_MISMATCH!
        class _ImpostorHandler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps({"ok": True, "service": "gateway", "port": c2_gw_port}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        impostor_srv = ThreadingHTTPServer(("127.0.0.1", c2_gw_port), _ImpostorHandler)
        impostor_thr = threading.Thread(target=impostor_srv.serve_forever, daemon=True)
        impostor_thr.start()
        fake_script = self.shadow / "state" / "c2" / "runtime" / "server.py"
        # Spawn a harmless sleeper whose cmdline contains fake_script path (via -c comment? No, run a separate sleeper inside shadow!)
        sleeper_script = self.shadow / "state" / "c2" / "impostor_sleeper.py"
        sleeper_script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
        sleeper = subprocess.Popen(
            [sys.executable, str(sleeper_script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            owner = canary.ensure_shadow_owner(self.shadow, create=False)
            sl_ident = canary.query_process_identity_exact(sleeper.pid)
            self.assertIsNotNone(sl_ident)
            canary.write_process_lease(
                self.shadow,
                role="c2_gateway",
                pid=sleeper.pid,
                create_time_filetime=sl_ident["create_time_filetime"],
                executable_path=sl_ident["executable_path"],
                entrypoint_path=str(sleeper_script),
                port=c2_gw_port,
                release_id=canary._read_json(self.shadow / "state" / "c2" / "active.json")["release_id"],
                owner_scope_id=owner["owner_scope_id"],
            )
            with self.assertRaises(canary.CanaryError) as ctx:
                canary.verify_shadow_health(
                    self.shadow,
                    check_c1_rpc=False,
                    check_c1_hub=False,
                    check_c2_gateway=True,
                    check_c2_unified=False,
                    consecutive_passes=1,
                )
            self.assertEqual(ctx.exception.code, "HEALTH_IDENTITY_MISMATCH")
        finally:
            impostor_srv.shutdown()
            impostor_srv.server_close()
            if sleeper.poll() is None:
                sleeper.kill()
                sleeper.wait(timeout=5)
            # Clean up temporary sleeper script so manifest stays clean
            sleeper_script.unlink(missing_ok=True)



if __name__ == "__main__":
    unittest.main()
