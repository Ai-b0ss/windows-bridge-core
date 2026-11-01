"""Build a new-version ZIP for the owner's installed ChatGPT plugin.

ChatGPT's "Загрузить новую версию" (Upload new version) expects the same layout the
plugin was downloaded with ("Скачать ZIP плагина"): `.app.json`, `.codex-plugin/plugin.json`
and `skills/`. This takes that downloaded ZIP, keeps its app binding and metadata, bumps the
patch version and replaces `skills/` with `skills/windows-bridge` from Git (LF bytes).

usage: build_chatgpt_plugin.py <downloaded-plugin.zip> <out.zip> [--ref origin/main]
"""
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = "skills/windows-bridge"


def git_bytes(ref: str, path: str) -> bytes:
    return subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT, check=True, capture_output=True).stdout


def skill_files(ref: str) -> list[str]:
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", ref, SKILL_DIR], cwd=ROOT, check=True,
                         capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line]


def bump(version: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise SystemExit(f"unexpected plugin version {version!r}")
    major, minor, patch = map(int, match.groups())
    return f"{major}.{minor}.{patch + 1}"


def build(source: Path, out: Path, ref: str) -> dict:
    with zipfile.ZipFile(source) as z:
        names = z.namelist()
        for required in (".app.json", ".codex-plugin/plugin.json"):
            if required not in names:
                raise SystemExit(f"{source.name} has no {required}; not a ChatGPT plugin download")
        app = z.read(".app.json")
        meta = json.loads(z.read(".codex-plugin/plugin.json"))
    old = meta["version"]
    meta["version"] = bump(old)
    files = skill_files(ref)
    if f"{SKILL_DIR}/SKILL.md" not in files:
        raise SystemExit(f"{ref} has no {SKILL_DIR}/SKILL.md")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(".app.json", app)
        z.writestr(".codex-plugin/plugin.json", json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
        for name in files:
            z.writestr(name, git_bytes(ref, name))
    return {"old_version": old, "new_version": meta["version"], "skill_files": len(files), "out": str(out)}


if __name__ == "__main__":
    args = sys.argv[1:]
    ref = "origin/main"
    if "--ref" in args:
        index = args.index("--ref")
        ref = args[index + 1]
        del args[index:index + 2]
    if len(args) != 2:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(args[0]), Path(args[1]), ref), indent=2))
