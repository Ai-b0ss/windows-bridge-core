"""Actual headless agent task: strict owned workspace, cost gates, no GUI."""
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
import cua_antigravity_task as module
from cua_antigravity_task import VendorTaskError, execute_headless_task, _subscription_gate
from cua_cli_first_policy import _gui_target


class FakeJob:
    created = []
    next_response = {"status": "SUCCESS", "response": "PROOF:42"}
    change_context = False
    create_file = False
    def __init__(self, argv, *, cwd, env):
        self.__class__.created.append({"argv": list(argv), "cwd": cwd, "env": dict(env)})
        context = Path(cwd) / "context.txt"
        assert context.read_text(encoding="utf-8") == "The answer is 42."
        if self.__class__.change_context:
            context.write_text("tampered!", encoding="utf-8")
        if self.__class__.create_file:
            (Path(cwd) / "unexpected.txt").write_text("should fail")
        self.stdout = io.BytesIO(json.dumps(self.__class__.next_response).encode())
        self.stderr = io.BytesIO(b"some private diagnostic that must stay private")
        self.stdin = io.BytesIO()
        self.closed = False
    def wait(self, timeout=None):
        return 0
    def active_members(self):
        return 0
    def close(self):
        self.closed = True


class TestHeadlessTask(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.args = {"command": "task_execute", "app": "Antigravity",
                     "task": "antigravity.assistant", "operation": "headless.answer",
                     "agent_id": "ci-agent", "task_id": "ci-free-001",
                     "prompt": "Answer from context.txt only", "context": "The answer is 42.",
                     "expected_response": "PROOF:42"}
        FakeJob.created = []
        FakeJob.next_response = {"status": "SUCCESS", "response": "PROOF:42"}
        FakeJob.change_context = FakeJob.create_file = False
        self.pinned = patch.object(module, "_subscription_gate", return_value=Path("/fake/agy.exe"))
        self.pinned.start()
        self.addCleanup(self.pinned.stop)

    def run_task(self, args=None):
        return execute_headless_task(args if args is not None else self.args,
                                     bridge_root=self.root, process_factory=FakeJob)

    def test_model_task_runs_with_genuine_owned_workspace_and_expected_proof(self):
        with patch.dict(module.os.environ, {"GEMINI_API_KEY": "PRIVATE_KEY_NO_INHERIT",
                                            "AGY_DANGEROUS_FLAG": "PRIVATE"}, clear=False):
            result = self.run_task()
        self.assertEqual(result["state"], "COMPLETED")
        self.assertTrue(result["model_called"])
        self.assertEqual(result["response"], "PROOF:42")
        self.assertFalse(result["result_verification"]["independent_semantic_verification"])
        self.assertTrue(result["billing"]["existing_subscription_quota_consumed"])
        self.assertFalse(result["billing"]["no_charge_guarantee_from_vendor"])
        self.assertEqual(result["effects"]["foreground_used"], False)
        self.assertEqual(len(FakeJob.created), 1)
        command = FakeJob.created[0]["argv"]
        self.assertIn("--sandbox", command)
        self.assertIn("gemini-3.8-flash-medium", command)
        self.assertNotIn("--dangerously-skip-permissions", command)
        env = FakeJob.created[0]["env"]
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertNotIn("AGY_DANGEROUS_FLAG", env)
        self.assertEqual(list((self.root / "owned-agent-tasks").iterdir()), [])

    def test_unknown_real_world_answer_is_not_misrepresented_as_completed(self):
        args = dict(self.args)
        del args["expected_response"]
        result = self.run_task(args)
        self.assertEqual(result["state"], "OUTCOME_UNKNOWN")
        self.assertIsNone(result["result_verification"]["matches_expected"])
        self.assertEqual(result["response"], "PROOF:42")

    def test_failed_model_and_changed_files_never_get_success_receipts(self):
        for state in ("ERROR", "WAITING", "CANCELED"):
            with self.subTest(state=state):
                FakeJob.next_response = {"status": state, "response": "PROOF:42"}
                with self.assertRaises(VendorTaskError) as caught:
                    self.run_task()
                self.assertEqual(caught.exception.code, "AGY_TASK_MODEL_DID_NOT_SUCCEED")
        FakeJob.next_response = {"status": "SUCCESS", "response": "PROOF:42"}
        for attr in ("change_context", "create_file"):
            with self.subTest(attr=attr):
                setattr(FakeJob, attr, True)
                with self.assertRaises(VendorTaskError) as caught:
                    self.run_task()
                self.assertEqual(caught.exception.code, "AGY_TASK_WORKSPACE_MUTATED")
                setattr(FakeJob, attr, False)

    def test_unexpected_paid_gui_and_model_overrides_fail_without_execution(self):
        for key, value in (
            ("model", "paid-model"), ("approved", True),
            ("paid_api", True), ("enable_credits", True),
            ("allow_gui", True), ("workspace", str(self.root)),
            ("dangerously_skip_permissions", True),
        ):
            with self.subTest(key=key):
                with self.assertRaises(VendorTaskError) as error:
                    self.run_task({**self.args, key: value})
                self.assertEqual(error.exception.code, "AGY_TASK_UNEXPECTED_ARGUMENT")
                self.assertEqual(FakeJob.created, [])

    def test_readonly_agent_is_exact_cli_first_exception_not_gui_grant(self):
        self.assertIsNone(_gui_target(None, self.args, "computer_use"))
        for operation in ("launch_app", "act", "headless.edit"):
            args = dict(self.args)
            args["operation"] = operation
            self.assertIsNotNone(_gui_target(None, args, "computer_use"))

    def test_readonly_request_validation_fail_closed(self):
        for key, val in (("app", "Cursor"), ("task", "antigravity.edit_files"),
                         ("task_id", ""), ("prompt", ""),
                         ("context", ""), ("context", "x"*32769),
                         ("expected_response", {"not": "text"})):
            with self.subTest(key=key):
                with self.assertRaises(VendorTaskError):
                    self.run_task({**self.args,key:val})
                self.assertFalse(FakeJob.created)

    def test_paid_credits_and_external_provider_are_rejected(self):
        self.pinned.stop()
        local = self.root / "local"
        local.mkdir()
        home = self.root / "home"
        settings = home / ".gemini" / "antigravity-cli" / "settings.json"
        settings.parent.mkdir(parents=True)
        exe = local / "agy" / "bin" / "agy.exe"
        exe.parent.mkdir(parents=True)
        exe.write_text("fixture")
        with patch.object(module, "os", SimpleNamespace(name="nt", environ={})), \
                patch.object(module, "_allowed_path", return_value=True):
            for config, expected in (
                ({"useG1Credits": True}, "AGY_PAID_CREDITS_FORBIDDEN"),
                ({"useG1Credits": "false"}, "AGY_PAID_CREDITS_FORBIDDEN"),
                ({"modelProvider": "gemini"}, "AGY_EXTERNAL_API_PROVIDER_FORBIDDEN"),
            ):
                with self.subTest(config=config):
                    settings.write_text(json.dumps(config))
                    with self.assertRaises(VendorTaskError) as err:
                        _subscription_gate(home, local)
                    self.assertEqual(err.exception.code, expected)
        self.pinned.start()

    def test_actual_rpc_dispatch_uses_single_canonical_entrypoint(self):
        from cua_bridge_v3 import CuaBridgeControlPlane
        class Plane(CuaBridgeControlPlane):
            def __init__(self):
                self.root = Path("/fake/bridge")
        plane = Plane()
        with patch("cua_antigravity_task.execute_headless_task",
                   return_value={"schema":"ff-vendor-task-result-v1"}) as task:
            result = plane.dispatch(self.args)
        self.assertEqual(result["schema"], "ff-vendor-task-result-v1")
        self.assertEqual(task.call_count, 1)
        self.assertEqual(task.call_args.kwargs["bridge_root"], plane.root)


if __name__ == "__main__":
    unittest.main()
