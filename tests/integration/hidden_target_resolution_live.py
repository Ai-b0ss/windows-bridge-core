"""Opt-in real Chromium DOM acceptance for hidden-target resolution; no owner profile."""
from pathlib import Path
import sys
from unittest.mock import patch
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_owner_chrome_secondary import OwnerChromeHiddenSecondaryManager, OwnerChromeSecondaryError

URL = "https://example.com/task"
OWNER = "isolated-agent\x1fisolated-task"
TAB = "hsec-fixture"

def main():
    mgr = OwnerChromeHiddenSecondaryManager(profile_dir_name="Default")
    mgr._targets[TAB] = {"tab_id": TAB, "target_id": "fixture", "owner": OWNER,
                         "url": URL, "title": "", "snapshot": None}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page()
            page.route("https://example.com/**", lambda route: route.fulfill(
                content_type="text/html",
                body='<html><body><button type="submit" onclick="window.clicked=(window.clicked||0)+1">Task</button></body></html>'))
            page.goto(URL)
            def evaluate(rec, expression, **kwargs):
                return page.evaluate(expression)
            def observe():
                return mgr.call("observe", {"owner": OWNER, "tab_id": TAB})
            def act(target):
                return mgr.call("act", {"owner": OWNER, "tab_id": TAB,
                                        "operation": "click", "target": target})
            def assert_error(target, code):
                try:
                    act(target)
                except OwnerChromeSecondaryError as err:
                    assert err.code == code, (err.code, code)
                else:
                    raise AssertionError("expected " + code)
            with patch.object(mgr, "_eval", side_effect=evaluate):
                obs = observe()
                control = obs["controls"][0]
                result = act({"ref": control["ref"], "snapshot": obs["snapshot"]})
                assert result["acted"] and page.evaluate("window.clicked") == 1
                print("PASS nested snapshot, real click")

                obs = observe()
                locator = obs["controls"][0]["locator"]
                page.evaluate("""() => {
                    document.body.innerHTML = '<button disabled>Task</button><button style="display:none">Task</button><button type="submit" onclick="window.clicked++">Task</button>';
                }""")
                assert_error({"ref": obs["controls"][0]["ref"], "snapshot": obs["snapshot"]}, "TARGET_STALE")
                assert page.evaluate("window.clicked") == 1
                assert act(locator)["acted"] and page.evaluate("window.clicked") == 2
                print("PASS replacement resolved semantically; stale numeric ref rejected; hidden/disabled duplicates ignored")

                page.evaluate("""() => {
                    document.body.innerHTML = '';
                    setTimeout(() => {document.body.innerHTML = '<button type="submit" onclick="window.clicked++">Task</button>';}, 180);
                }""")
                result = act(locator)
                assert result["resolution_attempts"] >= 2 and page.evaluate("window.clicked") == 3
                print("PASS bounded hydration wait, one click")

                page.evaluate("""() => {
                    document.body.innerHTML += '<button type="submit" onclick="window.clicked++">Task</button>';
                }""")
                assert_error(locator, "TARGET_AMBIGUOUS")
                assert page.evaluate("window.clicked") == 3
                print("PASS two visible matches rejected")

                page.goto("https://example.com/other")
                assert_error(locator, "TAB_DOCUMENT_CHANGED")
                assert page.evaluate("window.clicked||0") == 0
                print("PASS changed document URL rejected")
        finally:
            browser.close()
    print("REAL_CHROMIUM_TARGET_RESOLUTION_OK")

if __name__ == "__main__":
    main()
