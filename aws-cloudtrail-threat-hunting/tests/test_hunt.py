import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloud_hunt", ROOT / "src" / "hunt.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CloudHuntTests(unittest.TestCase):
    def test_sample_rules(self):
        rules = {x["rule"] for x in module.hunt(module.load(ROOT / "fixtures" / "events.jsonl"))}
        self.assertEqual(rules, {"root_account_activity", "iam_permission_or_identity_change",
                                 "logging_configuration_change", "role_assumption_review"})
    def test_failed_changes_ignored(self):
        self.assertEqual(module.hunt([{"eventName": "StopLogging", "errorCode": "AccessDenied"}]), [])
    def test_unrelated_activity(self):
        self.assertEqual(module.hunt([{"eventName": "DescribeInstances", "userIdentity": {"type": "IAMUser"}}]), [])
    def test_root_is_identified(self):
        self.assertEqual(module.hunt([{"eventName": "ConsoleLogin", "userIdentity": {"type": "Root"}}])[0]["severity"], "high")
    def test_assume_role_is_review_only(self):
        self.assertEqual(module.hunt([{"eventName": "AssumeRole"}])[0]["severity"], "low")
    def test_nonobject_rejected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "events.jsonl"
            p.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(p)

if __name__ == "__main__":
    unittest.main()
