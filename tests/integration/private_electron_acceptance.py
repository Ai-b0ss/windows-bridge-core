"""Verify installed Electron editors on a private Desktop with isolated profiles and fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import psutil

from hidden_chrome_smoke import Gate, check
from private_observer import Observer
from cua_owned_editor_launch import editor_path
from ff_win_process_identity import process_creation_token, process_identity_matches


def test_editor(gate, observer, app, executable):
    fixture = gate.out / f"{app}-fixture.json"
    fixture.write_bytes(b'{"value":42,"untouched":"fixture"}\n')
    expected = '{"value":47,"untouched":"fixture"}\n'
    session = gate.new(f"start-{app}-private")
    launch = gate.request(session, {"command": "editor.launch", "app": app, "document_path": str(fixture)},
                          f"launch-{app}-editor")
    gate.own_tree(launch["pid"])
    browser_process = psutil.Process(launch["pid"])
    token = process_creation_token(browser_process.pid)
    check(Path(browser_process.exe()).resolve() == executable.resolve(), "EDITOR_IMAGE_CHANGED")
    check(browser_process.ppid() == session["worker_pid"] and process_identity_matches(browser_process.pid, token),
          "EDITOR_PROCESS_NOT_OWNED")
    check(launch["desktop"] == session["desktop"] and observer.window(launch["desktop"], launch["hwnd"], launch["pid"]),
          "EDITOR_OS_DESKTOP")
    check(launch["route"] == "NATIVE_EDITOR_API" and launch["physical_input_used"] is False, "EDITOR_WRONG_ROUTE")

    observed = gate.request(session, {"command": "editor.observe", "hwnd": launch["hwnd"]})
    mutation = {"command": "editor.replace_save", "hwnd": launch["hwnd"], "generation": observed["generation"],
                "ref": observed["ref"], "expected_text": observed["document"]["text"], "replacement_text": expected}
    saved = gate.request(session, mutation, f"save-{app}-fixture")
    effect = fixture.read_bytes()
    digest = hashlib.sha256(effect).hexdigest()
    check(effect == expected.encode("utf-8") and json.loads(effect) == {"value": 47, "untouched": "fixture"},
          "EDITOR_INDEPENDENT_READBACK")
    check(saved["native_editor_edit"] and saved["native_document_save"] and saved["saved_sha256"] == digest,
          "EDITOR_SAVE_NOT_VERIFIED")
    cached = gate.request(session, mutation, f"save-{app}-fixture")
    check(cached == saved and fixture.read_bytes() == effect, "EDITOR_SAVE_NOT_DEDUPLICATED")
    gate.request(session, mutation, f"stale-{app}-fixture", expect="EDITOR_OBSERVATION_CHANGED")
    try:
        observation = gate.request(session, {"command": "uia_observe", "hwnd": launch["hwnd"], "options": {"max_items": 64}})
    except RuntimeError as exc:
        ui = {"status": "NOT_VERIFIED", "reason": str(exc)}
    else:
        count = len(observation.get("entities", []))
        ui = {"status": "PASS" if count else "NO_ENTITIES", "observed_entities": count}

    closed = gate.close(session, f"close-{app}-editor")
    check(closed["cleanup_verified"], "EDITOR_JOB_NOT_REAPED")
    [cleanup] = closed["editor_profile_cleanup"]
    profile = Path(cleanup["root"])
    check(profile.is_relative_to(gate.root / "state/owned-editor"), "EDITOR_PROFILE_CROSSES_RUNTIME")
    check(cleanup["removed"] and not profile.exists(), "EDITOR_PROFILE_LEAK")
    deadline = time.monotonic() + 5
    while process_identity_matches(browser_process.pid, token):
        check(time.monotonic() < deadline, "EDITOR_PROCESS_LEAK")
        time.sleep(0.1)
    return {"status": "PASS", "route": launch["route"], "desktop_placement": True, "generic_uia_observation": ui,
            "independent_file_sha256": digest, "duplicate_and_stale_receipt_checked": True,
            "profile_removed_from_isolated_runtime": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    check(os.name == "nt", "WINDOWS_REQUIRED")
    options.output.mkdir(parents=True, exist_ok=False)
    result = {"status": "FAIL", "editors": {}}
    with tempfile.TemporaryDirectory(prefix="ff-electron-") as sandbox:
        gate = Gate(Path(sandbox) / "proof")
        observer = Observer()
        try:
            gate.start()
            for app in ("vscode", "cursor"):
                executable = editor_path(app)
                if executable is None:
                    result["editors"][app] = {"status": "BLOCKED", "reason": "EDITOR_APP_NOT_INSTALLED"}
                else:
                    try:
                        result["editors"][app] = test_editor(gate, observer, app, executable)
                    except Exception as exc:
                        result["editors"][app] = {"status": "FAIL", "error": getattr(exc, "code", str(exc)).replace(sandbox, "<isolated>")}
            states = {item["status"] for item in result["editors"].values()}
            result["status"] = "FAIL" if "FAIL" in states else "PASS" if "PASS" in states else "BLOCKED"
        except Exception as exc:
            result["error"] = getattr(exc, "code", str(exc)).replace(sandbox, "<isolated>")
        finally:
            try:
                gate.cleanup()
            except Exception as exc:
                result.update(status="FAIL", cleanup_error=str(exc).replace(sandbox, "<isolated>"))
            gate.log.close()
            observation = observer.finish(gate.out, gate.owned)
            observation["clipboard_sequence_values"] = len({sample["clipboard_sequence"] for sample in observer.samples})
            result.update(owner_observer=observation,
                          owned_processes_closed=not any(process_identity_matches(*p) for p in gate.owned))
            if not observation["samples"] or observation["error"] or observation["foreground_owned"] or observation["private_input"]:
                result.update(status="FAIL", owner_observation_failed=True)
    (options.output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
