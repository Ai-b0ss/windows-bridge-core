"""Build deterministic, sanitized *skills-only* Windows Bridge install ZIPs.

This creates host-installable source archives; it does NOT connect accounts,
register an MCP server, grant permissions or install the plugin for the owner.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
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
        data[rel]=raw
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


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo",type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--mode",choices=["skill","plugin"],required=True)
    args=ap.parse_args()
    print(json.dumps(build(args.repo,args.output,args.mode),sort_keys=True))


if __name__=="__main__":
    main()
