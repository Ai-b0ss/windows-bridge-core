import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from bridge_remote_gh import BridgeRemoteError, verify, discover, submit, await_result, main

REPO = "Ai-b0ss/windows-bridge-support-20261024"
DEV = "WIN-TEST-LAPTOP-32"
TASK_BODY = "FF_GH_INBOX_V2 " + json.dumps({"device": DEV, "generation": 0})


class FakeAPI:
    def __init__(self, private=True, login="Ai-b0ss", device=DEV):
        self.private, self.login, self.device = private, login, device
        self.sent = []
        self.response = None

    def api(self, path, body=None):
        if path == "repos/" + REPO:
            return {"private": self.private, "owner": {"login": "Ai-b0ss"}}
        if path == "user":
            return {"login": self.login}
        if path.endswith("/issues?state=open&per_page=100"):
            return [{"number": 12, "title": "[FF-GH-INBOX] " + self.device,
                     "body": TASK_BODY},
                    {"number": 3, "title": "[FF-GH-INBOX] stale",
                     "body": "FF_GH_INBOX_V2 " + json.dumps({"device": DEV, "redirect": 12})}]
        if path.endswith("/issues/12/comments") and body is not None:
            self.sent.append(json.loads(body["body"]))
            return {"id": 888}
        if path.endswith("/issues/comments/888"):
            return {"body": json.dumps(self.response)}
        raise AssertionError("Unexpected GitHub endpoint: " + path)


class TestPrivateRemoteClient(unittest.TestCase):
    def test_private_operator_only(self):
        verify(FakeAPI(), REPO)
        with self.assertRaises(BridgeRemoteError):
            verify(FakeAPI(private=False), REPO)
        with self.assertRaises(BridgeRemoteError):
            verify(FakeAPI(login="random-collaborator"), REPO)

    def test_exact_device_and_no_redirect(self):
        api = FakeAPI()
        self.assertEqual(discover(api, REPO), {DEV: 12})
        with self.assertRaises(BridgeRemoteError):
            main(["--repo", REPO, "--device", "WIN-OTHER", "--op", "ping"], api=api)
        self.assertEqual(api.sent, [])

    def test_round_trip_and_target_verification(self):
        api = FakeAPI()
        cid, taskid = submit(api, REPO, 12, DEV, "ping", {})
        self.assertEqual(cid, 888)
        self.assertEqual(api.sent[0]["schema"], "ff-win-github-comment-v5")
        self.assertEqual(api.sent[0]["target_device"], DEV)
        api.response = {"schema": "ff-win-github-comment-result-v5",
                        "device": DEV, "task": {"task_id": taskid}, "outcome": "PASS"}
        self.assertEqual(await_result(api, REPO, cid, taskid, DEV, 2, 0.1)["outcome"], "PASS")
        api.response["device"] = "WIN-SOMEONE-ELSE"
        with self.assertRaises(BridgeRemoteError):
            await_result(api, REPO, cid, taskid, DEV, 2, 0.1)

    def test_bad_operation_rejected(self):
        with self.assertRaises(BridgeRemoteError):
            submit(FakeAPI(), REPO, 12, DEV, "ping;shutdown", {})

    def test_list_without_execution(self):
        api = FakeAPI()
        self.assertEqual(main(["--repo", REPO, "--list"], api=api), 0)
        self.assertEqual(api.sent, [])


if __name__ == "__main__":
    unittest.main()
