"""Build deterministic, sanitized *skills-only* Windows Bridge install ZIPs.

This creates host-installable source archives; it does NOT connect accounts,
register an MCP server, grant permissions or install the plugin for the owner.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re
import zipfile

SCHEMA="https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
FILENAMES=(
    "SKILL.md",
    "references/API.md",
    "references/APP_ROUTES.md",
    "references/PERMISSIONS.md",
    "references/TROUBLESHOOTING.md",
)
BLOCK=(
    rb"gh[pousr]_[A-Za-z0-9]{24,}",
    rb"github_pat_[A-Za-z0-9_]{30,}",
    rb"sk-(?:proj-)?[A-Za-z0-9_-]{24,}",
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    rb"(?i)C:\\Users\\[^\\\s]{3,}",
    rb"(?i)WIN-[A-Z0-9]{8,}",
)


def contents(root: Path):
    source=root/"skills"/"windows-bridge"
    data={}
    for rel in FILENAMES:
        path=source/rel
        if not path.is_file() or path.is_symlink():
            raise ValueError("SKILL_REQUIRED_SOURCE_MISSING_OR_LINKED")
        raw=path.read_bytes().replace(b"\r\n", b"\n")
        for pattern in BLOCK:
            if re.search(pattern,raw):
                raise ValueError("SKILL_SOURCE_PRIVATE_DATA_MATCH")
        # References to repository documents are outside both install ZIP
        # layouts. Keep bundled links local; make repo-only links explicit.
        current="skills/windows-bridge/"+rel
        def link(match):
            target=match.group(2)
            if target.startswith(("https://","http://","#")):
                return match.group(0)
            normalized=posixpath.normpath(posixpath.join(posixpath.dirname(current),target))
            if normalized.startswith("skills/windows-bridge/"):
                bundled=normalized.removeprefix("skills/windows-bridge/")
                if bundled not in FILENAMES:
                    raise ValueError("SKILL_BUNDLED_REFERENCE_MISSING")
                return match.group(0)
            if normalized.startswith("../") or not (root/normalized).is_file():
                raise ValueError("SKILL_REPOSITORY_REFERENCE_MISSING")
            return match.group(1)+"https://github.com/Ai-b0ss/windows-bridge-core/blob/main/"+normalized+")"
        data[rel]=re.sub(r"(\[[^\]]+\]\()([^\s)]+)\)",link,raw.decode()).encode()
    if not data["SKILL.md"].startswith(b"---\nname: windows-bridge\n"):
        raise ValueError("SKILL_FRONTMATTER_INVALID")
    return data


def write_zip(output: Path, entries: dict[str,bytes]):
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,"w") as z:
        for name,raw in sorted(entries.items()):
            info=zipfile.ZipInfo(name,(2026,10,25,0,0,0))
            info.create_system=0
            info.external_attr=0o644<<16
            z.writestr(info,raw,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(output) as z:
        if z.testzip() is not None or set(z.namelist())!=set(entries):
            raise ValueError("SKILL_ZIP_VERIFY_FAILED")
    with output.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def build(root: Path,output: Path,mode: str):
    source=contents(root)
    if mode=="skill":
        entries=dict(source)
    elif mode=="plugin":
        entries={"skills/windows-bridge/"+k:v for k,v in source.items()}
        plugin={
            "$schema":SCHEMA,
            "name":"windows-bridge-agent",
            "version":"0.1.0",
            "description":"Owner-authorized Windows Bridge task workflow: programmatic routes first, hidden UI fallback, trusted chat consent and independent outcome verification.",
            "repository":"https://github.com/Ai-b0ss/windows-bridge-core",
            "extensions":{"com.openai":{"onboardingSkill":"./skills/setup/SKILL.md"}},
        }
        entries["plugin.json"]=json.dumps(plugin,sort_keys=True,indent=2).encode()
        entries["skills/setup/SKILL.md"]=(
            "---\nname: setup-windows-bridge\n"
            "description: Verify existing Windows Bridge MCP connection and owner consent before using the windows-bridge agent skill.\n---\n\n"
            "This onboarding checks that the owner has separately connected the Windows Bridge app in ChatGPT and that device_status/device_ping and bridge_capabilities return expected results. "
            "It does not collect passwords, create hidden permissions, or install a remote agent automatically. "
            "A GitHub source/ZIP is not evidence of ChatGPT skill installation. "
            "Ask the owner to authorize the app's normal connection flow if unavailable; then test on a harmless read-only task in a new chat.\n"
        ).encode()
    else:
        raise ValueError("UNKNOWN_PACKAGING_MODE")
    digest=write_zip(output,entries)
    return {"mode":mode,"sha256":digest,"bytes":output.stat().st_size,
            "files":len(entries),"installed_in_chatgpt":False,"remote_permission_granted":False}


def build_existing(root: Path, original: Path, output: Path, version: str):
    """Update a complete Codex-layout plugin without losing its registered MCP.

    Original configuration is private input. Never publish this output as the
    generic skills-only release. This function performs no host installation.
    """
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("PLUGIN_VERSION_INVALID")
    if original.resolve()==output.resolve():
        raise ValueError("PLUGIN_ORIGINAL_MUST_BE_PRESERVED")
    with zipfile.ZipFile(original) as z:
        members=z.infolist()
        if len({item.filename for item in members})!=len(members):
            raise ValueError("PLUGIN_DUPLICATE_MEMBER")
        if sum(item.file_size for item in members)>64*1024*1024:
            raise ValueError("PLUGIN_ORIGINAL_TOO_LARGE")
        for item in members:
            parts=item.filename.split("/")
            if item.filename.startswith("/") or ".." in parts or "\\" in item.filename or ":" in item.filename or (item.external_attr>>16)&0o170000==0o120000:
                raise ValueError("PLUGIN_UNSAFE_MEMBER")
        data={item.filename:z.read(item) for item in members if not item.is_dir()}
    manifest_path=".codex-plugin/plugin.json"
    if "plugin.json" in data or manifest_path not in data or ".app.json" not in data:
        raise ValueError("EXISTING_CODEX_APP_LAYOUT_REQUIRED")
    meta=json.loads(data[manifest_path])
    app=json.loads(data[".app.json"])
    if not meta.get("name") or meta.get("apps")!="./.app.json" or not isinstance(app.get("apps"),dict) or not app["apps"]:
        raise ValueError("EXISTING_PLUGIN_MAPPING_INVALID")
    original_mapping=data[".app.json"]
    original_identity=meta["name"]
    meta["version"]=version
    meta["skills"]="./skills/"
    data[manifest_path]=(json.dumps(meta,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
    for path,raw in contents(root).items():
        data["skills/windows-bridge/"+path]=raw
    digest=write_zip(output,data)
    with zipfile.ZipFile(output) as z:
        if z.read(".app.json")!=original_mapping or json.loads(z.read(manifest_path))["name"]!=original_identity:
            raise ValueError("PLUGIN_IDENTITY_OR_MAPPING_CHANGED")
    return {"mode":"existing-plugin","version":version,"sha256":digest,
            "bytes":output.stat().st_size,"files":len(data),
            "mcp_mapping_byte_identical":True,"identity_preserved":True,
            "installed_in_chatgpt":False,"remote_permission_granted":False}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo",type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--mode",choices=["skill","plugin","existing-plugin"],required=True)
    ap.add_argument("--original",type=Path)
    ap.add_argument("--version")
    args=ap.parse_args()
    if args.mode=="existing-plugin":
        if not args.original or not args.version:
            ap.error("existing-plugin requires --original and --version")
        result=build_existing(args.repo,args.original,args.output,args.version)
    else:
        result=build(args.repo,args.output,args.mode)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
