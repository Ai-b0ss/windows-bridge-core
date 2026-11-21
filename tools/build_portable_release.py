"""Offline reproducible Full Core ZIP repackager.

Only audited public source paths and SHA-locked vendor binary assets are included.
Does NOT clone or copy historical private Git refs or host credentials.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

PREVIOUS_RELEASE_SHA = "46e43217fe6cace1f7a55c8aa00afba694fd03926c276565671a7566cee0d540"
TEMPLATE_SOURCE_COMMIT = "HEAD_RESOLVED_AT_RELEASE_BUILD"
KNOWN_STALE_COMMITS = frozenset({
    "c034e527a77b737b266c3c7df8b8521032be6f8a",  # legacy ancestor monorepo (2026-10-13)
    "abd6666b1fc630e84debeef961d0b60da9d0e631",  # legacy ancestor monorepo (2026-09-27)
    "8f5104895aa51212e86bdd9cf2922197ef026210",  # legacy ancestor monorepo (2026-09-30)
})
_HEX40_RE = re.compile(r"^[0-9a-f]{40}\Z", re.ASCII)
ASSET_HASHES = {
    "assets/python-3.13.9-embed-amd64.zip": "91d828c2da3a029b41699e918674a0cb379c02cf20dab9c501306885f837402a",
    "assets/node-v22.14.0-win-x64.zip": "55b639295920b219bb2acbcfa00f90393a2789095b7323f79475c9f34795f217",
    "assets/gh_2.101.0_windows_amd64.zip": "bc6c814367b193cd8e713611d61e36013c0ef843b8f516458fe3eda039192794",
}
ROOT_FILES = {
    "install.ps1", "ff-release-common.ps1", "START-HERE.cmd",
    "INSTALL-FRIEND.cmd", "CHECK-BRIDGE.cmd", "PAIR-REMOTE-SUPPORT.cmd",
    "STOP-REMOTE-SUPPORT.cmd", "STOP-REMOTE-SUPPORT.ps1",
    "ADDONS.cmd", "OPTIONAL-ADDONS.md", "REMOTE-PAIRING.md",
    "CHATGPT-REMOTE-CONTROL.md",
}
TOOL_FILES = {"tools/bridge_remote_gh.py", "tools/optional_addons.py", "tools/cua_cold_rollback_bundle.py", "tools/cua_cold_recovery_watchdog.py",
              "tools/private_desktop_client.py","tools/private_desktop_runtime.py", "tools/agent_entry.py",
              "tools/canary_release_workflow.py", "tools/canary_cutover_c1_c2.ps1", "tools/canary_rollback_c1_c2.ps1"}
TEXT_EXTENSIONS = (".py", ".ps1", ".cmd", ".json", ".mjs", ".js", ".cs", ".md", ".txt")
SECRET_PATTERNS = (
    rb"gh[pousr]_[A-Za-z0-9]{24,}", rb"github_pat_[A-Za-z0-9_]{30,}",
    rb"sk-(?:proj-)?[A-Za-z0-9_-]{24,}", rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex40_commit(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX40_RE.fullmatch(value))


def git_commit_exists(repo: Path, commit: str) -> bool:
    if not is_hex40_commit(commit):
        return False
    done = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", commit],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode == 0 and done.stdout.strip() == "commit"


def validate_source_commit(
    commit: object, *, repo: Path | None = None, allow_template: bool = False
) -> str:
    if not isinstance(commit, str) or not commit.strip() or commit != commit.strip():
        raise ValueError("SOURCE_COMMIT_MISSING_OR_INVALID")
    if commit.lower() in KNOWN_STALE_COMMITS:
        raise ValueError("STALE_SOURCE_COMMIT_FORBIDDEN: " + commit)
    if allow_template and commit == TEMPLATE_SOURCE_COMMIT:
        return TEMPLATE_SOURCE_COMMIT
    if not is_hex40_commit(commit):
        raise ValueError("SOURCE_COMMIT_NOT_HEX40: " + commit)
    if repo is not None and (repo / ".git").exists() and not git_commit_exists(repo, commit):
        raise ValueError("SOURCE_COMMIT_UNKNOWN_IN_GIT: " + commit)
    return commit


def verify_release_manifest_provenance(
    manifest: object, *, repo: Path | None = None, mode: str = "assembled"
) -> dict:
    """Validate release-manifest.json provenance for template or assembled builds."""
    if not isinstance(manifest, dict) or manifest.get("schema") != "ff-gh-release-v1":
        raise ValueError("RELEASE_MANIFEST_SCHEMA_INVALID")
    if mode == "template":
        source_commit = manifest.get("source_commit")
        if isinstance(source_commit, str) and source_commit.lower() in KNOWN_STALE_COMMITS:
            raise ValueError("STALE_SOURCE_COMMIT_FORBIDDEN: " + source_commit)
        if source_commit != TEMPLATE_SOURCE_COMMIT:
            raise ValueError(
                "TEMPLATE_SOURCE_COMMIT_MUST_BE_PLACEHOLDER: expected "
                + TEMPLATE_SOURCE_COMMIT
                + ", got "
                + repr(source_commit)
            )
        if manifest.get("source_bytes_verified_against_commit") is True:
            raise ValueError("TEMPLATE_CANNOT_CLAIM_ASSEMBLED_VERIFICATION")
        public_commit = manifest.get("public_source_commit")
        if public_commit is not None:
            raise ValueError("TEMPLATE_CANNOT_CARRY_PUBLIC_SOURCE_COMMIT")
        return {"ok": True, "mode": mode, "source_commit": source_commit}
    if mode != "assembled":
        raise ValueError("UNKNOWN_PROVENANCE_MODE: " + str(mode))
    source_commit = validate_source_commit(
        manifest.get("source_commit"), repo=repo, allow_template=False
    )
    public_commit = validate_source_commit(
        manifest.get("public_source_commit"), repo=repo, allow_template=False
    )
    if source_commit != public_commit:
        raise ValueError("SOURCE_COMMIT_PUBLIC_MISMATCH")
    if manifest.get("source_bytes_verified_against_commit") is not True:
        raise ValueError("SOURCE_BYTES_NOT_VERIFIED_AGAINST_COMMIT")
    return {"ok": True, "mode": mode, "source_commit": source_commit}


def bundled_subtree_file(name: str) -> bool:
    path = Path(name)
    return (path.parts[0] in {"runtime", "tests"} and
            not {"__pycache__", "node_modules"} & set(path.parts) and
            path.suffix.lower() not in {".pyc", ".pyd", ".exe", ".dll", ".zip"})


def source_tree(repo: Path) -> dict[str, bytes]:
    bundle = {}
    for path in sorted(ROOT_FILES | TOOL_FILES):
        file = repo / path
        if not file.is_file() or file.is_symlink():
            raise ValueError("Required allowed public file missing or linked: " + path)
        bundle[path] = file.read_bytes()
    for subtree in ("runtime", "tests"):
        root = repo / subtree
        if not root.is_dir():
            raise ValueError("Required public source tree missing: " + subtree)
        for file in sorted(root.rglob("*")):
            name = file.relative_to(repo).as_posix()
            # npm ci installs reproducible dependencies locally for tests.
            # Never bundle their untracked bytes or accidentally package a
            # vendor token/cache. Still reject any unexpected source file or
            # symlink outside the dependency directory.
            if "node_modules" in file.relative_to(repo).parts:
                continue
            if file.is_symlink():
                raise ValueError("Public source file/link not allowed: " + str(file))
            if file.is_file() and bundled_subtree_file(name):
                bundle[name] = file.read_bytes()
    if "runtime/bridge-v3/ff_win_v3_main.py" not in bundle:
        raise ValueError("Core runtime entrypoint missing")
    return bundle


def verify_source_commit(repo: Path, contents: dict[str, bytes]) -> str:
    """Bind every packaged source byte to HEAD, including untracked/ignored files.

    Compare bytes from git's object database, not status/index timestamps or
    diff (which can trust assume-unchanged/skip-worktree flags). Pin HEAD once
    so concurrent branch movement cannot relabel the archive.
    """
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "HEAD^{commit}"],
                          capture_output=True, text=True, check=True).stdout.strip()
    validate_source_commit(head, repo=repo, allow_template=False)
    raw = subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                          "-C", str(repo), "archive", "--format=tar", head],
                         capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        entries = {member.name: member for member in archive.getmembers()}
        for name, entry in entries.items():
            if entry.isfile() and bundled_subtree_file(name) and name not in contents:
                raise ValueError("COMMITTED_SOURCE_MISSING_FROM_BUNDLE: " + name)
        for name, actual in contents.items():
            entry = entries.get(name)
            if entry is None or not entry.isfile():
                raise ValueError("BUNDLED_SOURCE_NOT_IN_COMMIT: " + name)
            if archive.extractfile(entry).read() != actual:
                raise ValueError("BUNDLED_SOURCE_DIFFERS_FROM_COMMIT: " + name)
    return head


def refresh_source_manifest(repo: Path) -> dict:
    """Refresh the checked-in template; assemble still verifies release provenance.

    A committed manifest file cannot hold its own Git commit SHA due to SHA-1
    circularity. Replace any stale/legacy 40-char commit SHA (or any Git checkout
    template) with TEMPLATE_SOURCE_COMMIT so provenance is never stuck at an
    obsolete ancestor commit, while assemble() stamps and verifies the exact
    40-char Git HEAD into built release archives.
    """
    path = repo / "release-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    contents = source_tree(repo)
    # Keep asset/README records supplied by the previous portable release.
    files = {name: digest for name, digest in manifest["files"].items()
             if not name.startswith(("runtime/", "tests/")) and
             name not in ROOT_FILES | TOOL_FILES}
    files.update({name: sha(data) for name, data in contents.items()})
    manifest["files"] = dict(sorted(files.items()))
    current_commit = manifest.get("source_commit")
    if (
        (repo / ".git").exists()
        or not isinstance(current_commit, str)
        or not current_commit.strip()
        or current_commit.lower() in KNOWN_STALE_COMMITS
        or is_hex40_commit(current_commit)
    ):
        manifest["source_commit"] = TEMPLATE_SOURCE_COMMIT
        manifest.pop("public_source_commit", None)
        manifest.pop("source_bytes_verified_against_commit", None)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {
        "ok": True,
        "output": str(path),
        "source_files": len(contents),
        "source_commit": manifest.get("source_commit"),
    }


def assemble(repo: Path, previous: Path, output: Path) -> dict:
    if output.resolve() == previous.resolve():
        raise ValueError("Refuse to overwrite source release")
    if not previous.is_file() or sha(previous.read_bytes()) != PREVIOUS_RELEASE_SHA:
        raise ValueError("PREVIOUS_RELEASE_SHA256_MISMATCH")
    contents = source_tree(repo)
    head = verify_source_commit(repo, contents)
    with zipfile.ZipFile(previous) as z:
        manifest = json.loads(z.read("release-manifest.json"))
        if manifest.get("schema") != "ff-gh-release-v1":
            raise ValueError("Unrecognized source release")
        for asset, expected in ASSET_HASHES.items():
            raw = z.read(asset)
            if sha(raw) != expected:
                raise ValueError("Pinned vendor asset changed: " + asset)
            contents[asset] = raw
        previous_readme = z.read("README-FIRST.md").decode("utf-8")
    normalized_readme = re.sub(r"Remote Core Beta\s*\d*", "Windows Bridge v3 Full Core", previous_readme)
    readme = normalized_readme + (
        "\n\n## Windows Bridge v3 Full Core — Optional addons & verified provenance\n"
        f"- Verified public source commit: `{head}` (`release-manifest.json`).\n"
        "- Includes `ADDONS.cmd` and `tools/optional_addons.py` for offline SHA-256-pinned\n"
        "  `browser-runtime.zip` / `visual-runtime.zip` installation (`OPTIONAL-ADDONS.md`).\n"
        "- Local setup binds strictly to `127.0.0.1` until you explicitly pair a remote transport.\n"
    )
    contents["README-FIRST.md"] = readme.encode("utf-8")
    matches = []
    for path, data in contents.items():
        if path.lower().endswith(TEXT_EXTENSIONS):
            for expression in SECRET_PATTERNS:
                if re.search(expression, data):
                    matches.append(path)
    if matches:
        raise ValueError("Likely credential pattern in a bundled file (paths only): " + str(sorted(set(matches))))
    # Every bundled source byte was compared against the pinned commit above.
    manifest.update({
        "runtime_contract": "ff-full-core-remote-addon-v3",
        "public_source_commit": head,
        # The installer consumes this legacy key. Never inherit the previous
        # package's source identity while replacing all runtime source bytes.
        "source_commit": head,
        "source_bytes_verified_against_commit": True,
        "files": {name: sha(data) for name, data in sorted(contents.items())},
    })
    contents["release-manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", allowZip64=True) as z:
        for name, data in sorted(contents.items()):
            entry = zipfile.ZipInfo(name, (2026, 10, 25, 0, 0, 0))
            entry.create_system = 0
            entry.external_attr = 0o644 << 16
            method = zipfile.ZIP_STORED if name in ASSET_HASHES else zipfile.ZIP_DEFLATED
            z.writestr(entry, data, compress_type=method, compresslevel=6)
    with zipfile.ZipFile(output) as z:
        bad = z.testzip()
        if bad:
            raise ValueError("OUTPUT_ZIP_CRC_FAILED")
        checked = json.loads(z.read("release-manifest.json"))
        verify_release_manifest_provenance(checked, repo=repo, mode="assembled")
        if checked.get("source_commit") != head:
            raise ValueError("OUTPUT_MANIFEST_COMMIT_MISMATCH")
        for path, expected in checked["files"].items():
            if sha(z.read(path)) != expected:
                raise ValueError("OUTPUT_MANIFEST_HASH_FAILED: " + path)
    with output.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    return {"ok": True, "output": str(output), "bytes": output.stat().st_size,
            "sha256": digest, "files": len(contents),
            "public_source_commit": head, "source_release_sha256": PREVIOUS_RELEASE_SHA}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic offline Windows Bridge portable ZIP builder")
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--previous-release", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--refresh-source-manifest", action="store_true",
                    help="Refresh checked-in source hashes without building or attesting a release")
    opts = ap.parse_args(argv)
    if opts.refresh_source_manifest:
        if opts.previous_release or opts.output:
            ap.error("--refresh-source-manifest cannot be combined with release build arguments")
        result = refresh_source_manifest(opts.repo)
    else:
        if not opts.previous_release or not opts.output:
            ap.error("release builds require --previous-release and --output")
        result = assemble(opts.repo, opts.previous_release, opts.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
