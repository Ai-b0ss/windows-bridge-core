"""Integrity scanner for pinned Playwright coreBundle.js builds.

Detects unauthorized local debug patches (e.g., dumping extension connect URLs
or tokens via fs writes, hardcoded local user/audit paths) and fails closed.
Never reads any external user file, secret, cookie, or token.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_FINDINGS = 50

_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "FORBIDDEN_DEBUG_ARTIFACT_NAME",
        re.compile(r"pw_connect_url", re.IGNORECASE),
        "Unauthorized Playwright connect URL debug artifact reference",
    ),
    (
        "FORBIDDEN_AUDIT_PATH_LITERAL",
        re.compile(r"ChatGPT_Conversation_Audit", re.IGNORECASE),
        "Unauthorized local audit directory literal",
    ),
    (
        "HARDCODED_WINDOWS_USER_PATH",
        re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[/\\]{1,2}Users[/\\]{1,2}", re.IGNORECASE),
        "Hardcoded local Windows user profile path literal",
    ),
    (
        "HARDCODED_POSIX_USER_PATH",
        re.compile(r"/Users/[A-Za-z0-9._-]+/"),
        "Hardcoded local POSIX user profile path literal",
    ),
    (
        "RAW_REQUIRE_FS_WRITE",
        re.compile(
            r"require\s*\(\s*['\"](?:node:)?fs['\"]\s*\)\s*\.\s*"
            r"(?:writeFileSync|appendFileSync|writeFile|promises\s*\.\s*writeFile)"
        ),
        "Direct unbundled fs write call injected into coreBundle.js",
    ),
    (
        "SUSPICIOUS_FS_WRITE_CONNECT_OR_TOKEN",
        re.compile(
            r"(?:writeFileSync|appendFileSync|writeFile)\s*\([^;\n]{0,240}"
            r"(?:connect|token|relay|pw_|audit|extension|ws://|chrome-extension://|\.txt\b)",
            re.IGNORECASE,
        ),
        "File write referencing extension connect URL, token, relay, or text dump",
    ),
)


class PlaywrightIntegrityError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, *, details: dict[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.details = dict(details or {})


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return line, col


def scan_core_bundle(bundle_path: str | Path) -> dict[str, Any]:
    """Scan a single playwright-core/lib/coreBundle.js file for unauthorized patches."""
    path = Path(bundle_path)
    resolved_str = str(path)
    try:
        if not path.exists():
            return {
                "ok": False,
                "status": "missing",
                "error_code": "PLAYWRIGHT_CORE_BUNDLE_MISSING",
                "bundle_path": resolved_str,
                "sha256": None,
                "size_bytes": None,
                "findings": [],
                "finding_count": 0,
            }
        if not path.is_file():
            return {
                "ok": False,
                "status": "unreadable",
                "error_code": "PLAYWRIGHT_CORE_BUNDLE_UNREADABLE",
                "bundle_path": resolved_str,
                "sha256": None,
                "size_bytes": None,
                "findings": [],
                "finding_count": 0,
            }
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return {
            "ok": False,
            "status": "unreadable",
            "error_code": "PLAYWRIGHT_CORE_BUNDLE_UNREADABLE",
            "bundle_path": resolved_str,
            "sha256": None,
            "size_bytes": None,
            "findings": [],
            "finding_count": 0,
        }

    digest = hashlib.sha256(raw).hexdigest()
    size_bytes = len(raw)
    findings: list[dict[str, Any]] = []
    total_count = 0

    for rule_name, pattern, reason in _RULES:
        for match in pattern.finditer(text):
            total_count += 1
            if len(findings) < MAX_FINDINGS:
                line, column = _line_and_column(text, match.start())
                findings.append(
                    {
                        "rule": rule_name,
                        "line": line,
                        "column": column,
                        "reason": reason,
                    }
                )

    if total_count > 0:
        return {
            "ok": False,
            "status": "tampered",
            "error_code": "PLAYWRIGHT_CORE_BUNDLE_TAMPERED",
            "bundle_path": resolved_str,
            "sha256": digest,
            "size_bytes": size_bytes,
            "findings": findings,
            "finding_count": total_count,
        }

    return {
        "ok": True,
        "status": "clean",
        "error_code": None,
        "bundle_path": resolved_str,
        "sha256": digest,
        "size_bytes": size_bytes,
        "findings": [],
        "finding_count": 0,
    }


def _read_playwright_core_version(root: Path) -> str | None:
    pkg = root / "node_modules" / "playwright-core" / "package.json"
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
        version = data.get("version")
        return str(version) if isinstance(version, str) and version else None
    except (OSError, ValueError):
        return None


def scan_playwright_root(
    playwright_root: str | Path,
    *,
    require_present: bool = True,
) -> dict[str, Any]:
    """Scan `<playwright_root>/node_modules/playwright-core/lib/coreBundle.js`."""
    root = Path(playwright_root).resolve()
    bundle = root / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"
    version = _read_playwright_core_version(root)
    if not bundle.exists() and not require_present:
        return {
            "ok": True,
            "status": "not_installed",
            "error_code": None,
            "playwright_root": str(root),
            "bundle_path": str(bundle),
            "playwright_core_version": version,
            "sha256": None,
            "size_bytes": None,
            "findings": [],
            "finding_count": 0,
        }
    result = scan_core_bundle(bundle)
    return {
        "ok": result["ok"],
        "status": result["status"],
        "error_code": result["error_code"],
        "playwright_root": str(root),
        "bundle_path": result["bundle_path"],
        "playwright_core_version": version,
        "sha256": result["sha256"],
        "size_bytes": result["size_bytes"],
        "findings": result["findings"],
        "finding_count": result["finding_count"],
    }


def assert_playwright_integrity(
    playwright_root: str | Path,
    *,
    require_present: bool = True,
) -> dict[str, Any]:
    """Verify Playwright coreBundle.js integrity or raise PlaywrightIntegrityError."""
    result = scan_playwright_root(playwright_root, require_present=require_present)
    if not result["ok"]:
        raise PlaywrightIntegrityError(
            str(result["error_code"] or "PLAYWRIGHT_CORE_BUNDLE_TAMPERED"),
            details=result,
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify pinned playwright-core coreBundle.js contains no unauthorized debug patches."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--playwright-root", help="Directory containing node_modules/playwright-core")
    target.add_argument("--core-bundle", help="Direct path to playwright-core/lib/coreBundle.js")
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Return ok=true (status=not_installed) when coreBundle.js is not installed under --playwright-root",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON (enabled by default)",
    )
    args = parser.parse_args(argv)

    if args.core_bundle:
        result = scan_core_bundle(args.core_bundle)
    else:
        result = scan_playwright_root(args.playwright_root, require_present=not args.allow_missing)

    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")
    if result["ok"]:
        return 0
    if result["status"] == "tampered":
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
