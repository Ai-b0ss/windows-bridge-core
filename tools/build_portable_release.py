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
TOOL_FILES = {"tools/bridge_remote_gh.py", "tools/optional_addons.py"}
TEXT_EXTENSIONS = (".py", ".ps1", ".cmd", ".json", ".mjs", ".js", ".cs", ".md", ".txt")
SECRET_PATTERNS = (
    rb"gh[pousr]_[A-Za-z0-9]{24,}", rb"github_pat_[A-Za-z0-9_]{30,}",
    rb"sk-(?:proj-)?[A-Za-z0-9_-]{24,}", rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundled_subtree_file(name: str) -> bool:
    path = Path(name)
    return (path.parts[0] in {"runtime", "tests"} and
            "__pycache__" not in path.parts and
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
            if file.is_symlink():
                raise ValueError("Public source file/link not allowed: " + str(file))
            if file.is_file():
                name = file.relative_to(repo).as_posix()
                if bundled_subtree_file(name):
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
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
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
    """Refresh the checked-in template; assemble still verifies release provenance."""
    path = repo / "release-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    contents = source_tree(repo)
    # Keep asset/README records supplied by the previous portable release.
    files = {name: digest for name, digest in manifest["files"].items()
             if not name.startswith(("runtime/", "tests/")) and
             name not in ROOT_FILES | TOOL_FILES}
    files.update({name: sha(data) for name, data in contents.items()})
    manifest["files"] = dict(sorted(files.items()))
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "output": str(path), "source_files": len(contents)}


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
    readme = previous_readme + (
        "\n\n## Remote Core Beta 3 — Optional addons\n"
        "This version includes ADDONS.cmd and tools/optional_addons.py.\n"
        "Run ADDONS.cmd status, or install a separately obtained,\n"
        "SHA-256 pinned browser-runtime.zip / visual-runtime.zip.\n"
        "Nothing downloads without you supplying a file. Read OPTIONAL-ADDONS.md.\n"
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
