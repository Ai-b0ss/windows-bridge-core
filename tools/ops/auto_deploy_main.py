"""Gated auto-deploy for FF Hub from Ai-b0ss/windows-bridge-core main branch.

Rules:
- Never deploys unless both `portable-syntax` and `candidate-install` CI checks
  on the target main commit are completed with conclusion == "success".
- Never touches live running files in-place: deploys into a fresh
  `runtime-releases/bridge-<sha7>/bridge-v3/` directory and updates
  `state/active-release.json` with pinned `previous` backup.
- Automatically rolls back to the previous release if the new Hub fails to
  respond to `hub_status` within 25 seconds.
- Disabled immediately if `autodeploy.stop.flag` exists.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time

REPO = "Ai-b0ss/windows-bridge-core"
REPO_URL = f"https://github.com/{REPO}.git"
REQUIRED_CHECKS = ("portable-syntax", "candidate-install")

BRIDGE_ROOT = Path(os.environ.get("FF_BRIDGE_ROOT") or (Path(os.environ.get("LOCALAPPDATA", ".")) / "FF-Windows-Bridge"))
STATE_DIR = BRIDGE_ROOT / "state" / "hub"
ACTIVE_RELEASE = BRIDGE_ROOT / "state" / "active-release.json"
RELEASES_ROOT = BRIDGE_ROOT / "runtime-releases"
RUNTIME_DIR = BRIDGE_ROOT / "state" / "hub-runtime"
STOP_FLAG = RUNTIME_DIR / "autodeploy.stop.flag"
LOG_PATH = RUNTIME_DIR / "auto-deploy.log"
LOCK_PATH = RUNTIME_DIR / "auto-deploy.lock"


def log(msg: str) -> None:
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.is_file() and LOG_PATH.stat().st_size > 512 * 1024:
            old = LOG_PATH.with_suffix(".log.old")
            old.unlink(missing_ok=True)
            LOG_PATH.rename(old)
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def run_cmd(cmd: list[str], cwd: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def get_remote_main_sha() -> str | None:
    r = run_cmd(["gh", "api", f"repos/{REPO}/commits/main", "--jq", ".sha"], timeout=15)
    if r.returncode != 0:
        log(f"ERROR gh_main_sha rc={r.returncode} err={(r.stderr or '').strip()[:160]}")
        return None
    sha = (r.stdout or "").strip()
    return sha if len(sha) == 40 else None


def ci_is_green(sha: str) -> tuple[bool, dict[str, str]]:
    r = run_cmd(
        ["gh", "api", f"repos/{REPO}/commits/{sha}/check-runs",
         "--jq", "[.check_runs[] | {name: .name, status: .status, conclusion: .conclusion}]"],
        timeout=15,
    )
    if r.returncode != 0 or not (r.stdout or "").strip():
        return False, {"error": f"rc={r.returncode}"}
    runs = json.loads(r.stdout)
    latest: dict[str, str] = {}
    for item in runs:
        name = str(item.get("name") or "")
        st = str(item.get("status") or "")
        conc = str(item.get("conclusion") or "")
        latest[name] = conc if st == "completed" else st
    ok = all(latest.get(req) == "success" for req in REQUIRED_CHECKS)
    return ok, latest


def deploy_commit(full_sha: str) -> int:
    short_sha = full_sha[:7]
    rel_root = RELEASES_ROOT / f"bridge-{short_sha}"
    dst = rel_root / "bridge-v3"

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"wbc-autodeploy-{short_sha}-"))
    try:
        rc = run_cmd(["git", "clone", "--depth", "1", "-c", "core.autocrlf=false", REPO_URL, str(tmp_dir)], timeout=60)
        if rc.returncode != 0:
            log(f"ERROR clone_failed sha={short_sha} err={(rc.stderr or '').strip()[:160]}")
            return 2
        cloned_sha = run_cmd(["git", "rev-parse", "HEAD"], cwd=str(tmp_dir), timeout=10).stdout.strip()
        if cloned_sha != full_sha:
            log(f"SKIP sha_moved expected={short_sha} got={cloned_sha[:7]}")
            return 0

        src = tmp_dir / "runtime" / "bridge-v3"
        if not (src / "ff_hub.py").is_file():
            log(f"ERROR missing_ff_hub sha={short_sha}")
            return 2

        if rel_root.exists():
            shutil.rmtree(rel_root, ignore_errors=True)
        shutil.copytree(src, dst)

        py_compile.compile(str(dst / "ff_hub.py"), doraise=True)
        py_compile.compile(str(dst / "cua_owner_chrome_secondary.py"), doraise=True)
    except Exception as exc:
        log(f"ERROR stage_failed sha={short_sha} exc={type(exc).__name__}:{str(exc)[:160]}")
        shutil.rmtree(rel_root, ignore_errors=True)
        return 2
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    cur = json.loads(ACTIVE_RELEASE.read_text(encoding="utf-8-sig"))
    bak_path = BRIDGE_ROOT / "state" / f"active-release.json.bak-autodeploy-{short_sha}"
    shutil.copy2(ACTIVE_RELEASE, bak_path)

    prev_entry = {
        "agent_entrypoint": cur.get("agent_entrypoint"),
        "agent_entrypoint_sha256": cur.get("agent_entrypoint_sha256"),
        "manifest_sha256": cur.get("manifest_sha256"),
        "playwright_root": cur.get("playwright_root"),
        "release_dir": cur.get("release_dir"),
        "release_id": cur.get("release_id"),
        "release_name": cur.get("release_name"),
        "source_head": cur.get("source_head"),
    }
    new_ar = dict(cur)
    new_ar["previous"] = prev_entry
    new_ar["release_name"] = f"bridge-{short_sha}"
    new_ar["release_dir"] = str(dst)
    new_ar["source_head"] = full_sha
    new_ar["agent_entrypoint_sha256"] = hashlib.sha256((dst / "ff_win_v3_main.py").read_bytes()).hexdigest()
    new_ar["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ACTIVE_RELEASE.write_text(json.dumps(new_ar, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Stop current Hub so hub_keeper.py launches the new release
    ep_path = STATE_DIR / "endpoint.json"
    old_pid = 0
    try:
        old_pid = int(json.loads(ep_path.read_text(encoding="utf-8-sig")).get("pid") or 0)
    except Exception:
        pass
    if old_pid > 0:
        run_cmd(["taskkill", "/PID", str(old_pid), "/F"], timeout=10)

    sys.path.insert(0, str(dst))
    from ff_hub import HubClient

    healthy = False
    new_pid = 0
    for _ in range(16):
        time.sleep(1.5)
        try:
            ep = json.loads(ep_path.read_text(encoding="utf-8-sig"))
            pid = int(ep.get("pid") or 0)
            pkg = str(ep.get("package") or "")
            if pid > 0 and pid != old_pid and f"bridge-{short_sha}" in pkg:
                st = HubClient(STATE_DIR, timeout=5.0).call("hub_status")
                if int(st.get("pid") or 0) == pid:
                    healthy = True
                    new_pid = pid
                    break
        except Exception:
            pass

    if not healthy:
        shutil.copy2(bak_path, ACTIVE_RELEASE)
        try:
            bad_pid = int(json.loads(ep_path.read_text(encoding="utf-8-sig")).get("pid") or 0)
            if bad_pid > 0 and bad_pid != old_pid:
                run_cmd(["taskkill", "/PID", str(bad_pid), "/F"], timeout=10)
        except Exception:
            pass
        log(f"ROLLED_BACK sha={short_sha} reason=new_hub_unhealthy")
        return 3

    log(f"DEPLOYED sha={short_sha} old_pid={old_pid} new_pid={new_pid}")
    rotate_old_releases(new_ar)
    return 0


def rotate_old_releases(ar: dict, keep_max_bridge: int = 3) -> None:
    try:
        protected: set[str] = set()
        for raw in (ar.get("release_dir"), (ar.get("previous") or {}).get("release_dir"), ar.get("playwright_root")):
            if raw:
                p = Path(raw)
                if p.parent == RELEASES_ROOT:
                    protected.add(p.name)
                elif p.parent.parent == RELEASES_ROOT:
                    protected.add(p.parent.name)
        bridge_dirs = sorted(
            [d for d in RELEASES_ROOT.iterdir() if d.is_dir() and d.name.startswith("bridge-")],
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
        for d in bridge_dirs[:keep_max_bridge]:
            protected.add(d.name)
        removed = []
        for d in bridge_dirs[keep_max_bridge:]:
            if d.name in protected:
                continue
            try:
                shutil.rmtree(d)
                removed.append(d.name)
            except OSError:
                pass
        if removed:
            log(f"ROTATED_OLD_RELEASES removed={removed}")
    except Exception as exc:
        log(f"ROTATE_ERROR exc={type(exc).__name__}")


def main() -> int:
    if STOP_FLAG.exists():
        log("SKIP stop_flag_present")
        return 0
    if not ACTIVE_RELEASE.is_file():
        log("ERROR active_release_missing")
        return 1

    # Simple stale-aware lock (10 min max age)
    if LOCK_PATH.exists() and (time.time() - LOCK_PATH.stat().st_mtime) < 600:
        return 0
    try:
        LOCK_PATH.write_text(str(os.getpid()), encoding="utf-8")
        cur = json.loads(ACTIVE_RELEASE.read_text(encoding="utf-8-sig"))
        cur_head = str(cur.get("source_head") or "").strip()
        remote_sha = get_remote_main_sha()
        if not remote_sha:
            return 1
        if remote_sha == cur_head:
            log(f"UP_TO_DATE sha={remote_sha[:7]}")
            return 0
        green, checks = ci_is_green(remote_sha)
        if not green:
            log(f"WAIT_CI sha={remote_sha[:7]} checks={json.dumps(checks, ensure_ascii=True)}")
            return 0
        return deploy_commit(remote_sha)
    finally:
        LOCK_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
