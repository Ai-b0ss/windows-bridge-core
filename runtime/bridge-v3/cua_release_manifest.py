from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cua-release-manifest/v1"
TEMPLATE_SOURCE_COMMIT = "HEAD_RESOLVED_AT_RELEASE_BUILD"
KNOWN_STALE_COMMITS = frozenset({
    "c034e527a77b737b266c3c7df8b8521032be6f8a",  # legacy ancestor monorepo (2026-10-13)
    "abd6666b1fc630e84debeef961d0b60da9d0e631",  # legacy ancestor monorepo (2026-09-27)
    "8f5104895aa51212e86bdd9cf2922197ef026210",  # legacy ancestor monorepo (2026-09-30)
})
_HEX40_RE = re.compile(r"^[0-9a-f]{40}\Z", re.ASCII)
COMPONENTS = (
    "docs/HIDDEN_PANEL_AGENT_GUIDE.md",
    "tools/ff_win_v3_agent.py",
    "tools/ff_win_v3_gui.py",
    "tools/ff_win_v3_extras.py",
    "tools/ff_win_v3_documents.py",
    "tools/ff_win_v3_security.py",
    "tools/ff_win_v3_upgrade.py",
    "tools/ff_win_v3_direct.py",
    "tools/ff_win_v3_main.py",
    "tools/ff_win_request_journal.py",
    "tools/ff_win_evidence.py",
    "tools/cua_task_authority.py",
    "tools/cua_task_routes.py",
    "tools/cua_assistant_workflow.py",
    "tools/cua_office_artifacts.py",
    "tools/ff_win_v3_keeper.ps1",
    "tools/ff_win_v3_workflow_deploy.ps1",
    "tools/ff_win_keeper_restore.ps1",
    "tools/ff_win_stop_bridge.ps1",
    "tools/cua_router.py",
    "tools/cua_sidecar_supervisor.py",
    "tools/cua_bridge_v3.py",
    "tools/cua_app_api.py",
    "tools/cua_winapp_persistent.py",
    "tools/cua_experience_cache.py",
    "tools/cua_semantic_resources.py",
    "tools/cua_global_resources.py",
    "tools/cua_browser_profiles.py",
    "tools/cua_restricted_execution.py",
    "tools/cua_restricted_rpc.py",
    "tools/cua_hidden_desktop.py",
    "tools/cua_windows_paths.py",
    "tools/cua_desktop_identity.py",
    "tools/cua_hidden_worker.py",
    "tools/cua_hidden_capture.py",
    "tools/cua_hidden_apps.py",
    "tools/cua_owned_editor_launch.py",
    "tools/cua_vscode_native.py",
    "tools/cua_vscode_extension.cjs",
    "tools/cua_app_resolver.py",
    "tools/cua_universal_fastpath.py",
    "tools/cua_cli_discovery.py",
    "tools/cua_tool_preparation.py",
    "tools/cua_windows_mcp.py",
    "tools/cua_programmatic_discovery.py",
    "tools/cua_session_continuation.py",
    "tools/cua_browser_rpc.mjs",
    "tools/cua_browser_sidecar.mjs",
    "tools/cua_browser_playwright.mjs",
    "tools/cua_browser_companion.py",
    "tools/cua_browser_companion_host.cs",
    "tools/cua_browser_companion_install.ps1",
    "tools/cua_browser_extension_rpc.ps1",
    "tools/install_cua_browser_runtime.ps1",
    "tools/package.json",
    "tools/package-lock.json",
    "browser_companion/manifest.json",
    "browser_companion/service_worker.js",
    "browser_companion/download_state.mjs",
    "tools/cua_native_sidecar.py",
    "tools/cua_native_core.py",
    "tools/cua_native_supervisor.py",
    "tools/cua_native_uia3.py",
    "tools/cua_native_waits.py",
    "tools/cua_native_hwnd.py",
    "tools/cua_native_winapp.py",
    "tools/cua_native_router_adapter.py",
    "tools/build_cua_native_uia3_sidecar.ps1",
    "tools/cua_native_uia3_sidecar.cs",
    "tools/cua_input_arbiter.py",
    "tools/cua_input_windows.py",
    "tools/cua_input_router_adapter.py",
    "tools/cua_physical_runtime.py",
    "tools/cua_physical_input_windows.py",
    "tools/cua_capture_contract.py",
    "tools/cua_visual_action_gate.py",
    "tools/cua_vision_runtime.py",
    "tools/cua_visual_detector_sidecar.py",
    "tools/cua_windows_ocr_sidecar.ps1",
    "tools/cua_wgc_native_probe/DxgiProbe.cs",
    "tools/cua_wgc_native_probe/PixelReadback.cs",
    "tools/cua_wgc_native_probe/Program.cs",
    "tools/cua_wgc_native_probe/SidecarHost.cs",
    "tools/cua_wgc_native_probe/cua_wgc_native_probe.csproj",
    "tools/cua_wgc_native_probe/packages.lock.json",
    "tools/cua_owner_approval_controller/Program.cs",
    "tools/cua_owner_approval_controller/cua_owner_approval_controller.csproj",
    "tools/cua_wgc_native_probe/run_probe.ps1",
    "tools/cua_g0_post_reboot_validate.py",
    "tools/cua_release_manifest.py",
    "tools/cua_runtime_deploy.py",
    "tools/cua_lifecycle.py",
    "tools/cua_owner_chrome_logon.ps1",
    ".github/workflows/cua-integration-offline.yml",
    ".github/workflows/ff-win-keeper-restore.yml",
    ".github/workflows/ff-win-v3-bootstrap.yml",
    ".github/workflows/ff-win-v3-refresh-keeper.yml",
    ".github/workflows/ff-win-v3-restart.yml",
    ".github/workflows/ff-win-v3-start-keeper.yml",
    ".github/workflows/ff-win-v3-sync.yml",
)


def runtime_target_for_component(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if normalized == "docs/HIDDEN_PANEL_AGENT_GUIDE.md":
        return "HIDDEN-PANEL-GUIDE.md"
    if normalized.startswith("tools/"):
        return normalized[len("tools/"):]
    if normalized.startswith("browser_companion/"):
        return normalized
    return None


RUNTIME_SOURCE_MAP = {
    source: target
    for source in COMPONENTS
    if (target := runtime_target_for_component(source)) is not None
}



def _run(argv: list[str], cwd: Path) -> str:
    cp = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=15, check=False)
    if cp.returncode != 0:
        raise RuntimeError(f"COMMAND_FAILED:{argv[0]}:{cp.stderr.strip()[:300]}")
    return cp.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()



def is_hex40_commit(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX40_RE.fullmatch(value))


def git_commit_exists(repo: Path, commit: str) -> bool:
    if not is_hex40_commit(commit):
        return False
    cp = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", commit],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return cp.returncode == 0 and cp.stdout.strip() == "commit"


def validate_commit_sha(commit: Any, *, repo: Path | None = None) -> str:
    if not isinstance(commit, str) or not commit:
        raise RuntimeError("SOURCE_COMMIT_MISSING")
    lower = commit.lower()
    if lower in KNOWN_STALE_COMMITS:
        raise RuntimeError(f"STALE_SOURCE_COMMIT_FORBIDDEN:{commit}")
    if not is_hex40_commit(commit):
        raise RuntimeError(f"SOURCE_COMMIT_INVALID:{commit}")
    if repo is not None and (repo / ".git").exists():
        if not git_commit_exists(repo, commit):
            raise RuntimeError(f"SOURCE_COMMIT_UNKNOWN_IN_GIT:{commit}")
    return commit


def compute_install_release_id(source_head: str, files: list[dict[str, Any]]) -> str:
    identity = {"head": source_head, "files": files}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_installed_manifest_provenance(
    manifest: Any, *, repo: Path | None = None
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema") != "cua-runtime-install/v1":
        raise RuntimeError("INSTALLED_MANIFEST_SCHEMA_INVALID")
    source_head = validate_commit_sha(manifest.get("source_head"), repo=repo)
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("INSTALLED_MANIFEST_FILES_INVALID")
    expected_release_id = compute_install_release_id(source_head, files)
    if manifest.get("release_id") != expected_release_id:
        raise RuntimeError("INSTALLED_MANIFEST_RELEASE_ID_MISMATCH")
    return {
        "ok": True,
        "source_head": source_head,
        "release_id": expected_release_id,
        "file_count": len(files),
    }


def resolve_ref(repo: Path, ref: str = "HEAD") -> str:
    head = _run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], repo)
    return validate_commit_sha(head, repo=repo)


def git_blob_bytes(repo: Path, ref: str, rel: str) -> bytes:
    cp = subprocess.run(
        ["git", "show", f"{ref}:{rel}"],
        cwd=repo,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"GIT_BLOB_UNAVAILABLE:{rel}")
    return cp.stdout


def component_records_from_git(repo: Path, ref: str = "HEAD") -> list[dict[str, Any]]:
    head = resolve_ref(repo, ref)
    records: list[dict[str, Any]] = []
    for rel in COMPONENTS:
        raw = git_blob_bytes(repo, head, rel)
        records.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return records


def component_records(repo: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for rel in COMPONENTS:
        path = repo / rel
        if not path.is_file():
            raise RuntimeError(f"COMPONENT_MISSING:{rel}")
        records.append({"path": rel, "bytes": path.stat().st_size, "sha256": _sha256(path)})
    return records


def runtime_record(repo: Path) -> dict[str, str | None]:
    try:
        node = _run(["node", "--version"], repo)
    except Exception:
        node = None
    return {
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "node": node,
        "platform": platform.platform(),
    }


def live_status() -> dict[str, Any]:
    if os.name != "nt":
        return {"supported": False}
    import cua_lifecycle

    try:
        result = cua_lifecycle.status()
    except Exception as exc:
        return {"supported": True, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"supported": True, **result}


def build_manifest(repo: Path, *, include_live: bool = False) -> dict[str, Any]:
    repo = repo.resolve()
    head = _run(["git", "rev-parse", "HEAD"], repo)
    dirty = bool(_run(["git", "status", "--porcelain"], repo))
    try:
        base = _run(["git", "merge-base", "HEAD", "main"], repo)
    except Exception:
        base = None
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": {"head": head, "base": base, "dirty": dirty},
        "components": component_records(repo),
        "runtime": runtime_record(repo),
    }
    if include_live:
        result["live"] = live_status()
    return result


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a hash-pinned CUA release-candidate evidence manifest")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-live", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    ns = parser.parse_args()
    try:
        payload = build_manifest(ns.repo, include_live=ns.include_live)
        if ns.require_clean and payload["git"]["dirty"]:
            raise RuntimeError("WORKTREE_DIRTY")
        atomic_write_json(ns.output, payload)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "output": str(ns.output), "head": payload["git"]["head"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
