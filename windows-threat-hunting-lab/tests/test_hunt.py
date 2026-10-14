import importlib.util
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hunt_module", ROOT / "src" / "hunt.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class HuntTests(unittest.TestCase):
    def test_four_detection_types(self):
        rules = {f["rule"] for f in mod.hunt(mod.load(ROOT / "fixtures" / "sample_events.jsonl"))}
        self.assertEqual(rules, {"suspicious_powershell", "privileged_group_change", "scheduled_task_created", "success_after_failures"})
    def test_clean_powershell(self):
        self.assertEqual(mod.hunt([{"event_id": 4688, "image": "powershell.exe", "command_line": "powershell.exe -NoProfile"}]), [])
    def test_unprivileged_group(self):
        self.assertEqual(mod.hunt([{"event_id": 4732, "group": "Users"}]), [])
    def test_four_failures_not_enough(self):
        rows = [dict(event_id=4625, timestamp=f"2026-10-14T12:00:0{i}Z", host="test", user="x", source_ip="192.0.2.1") for i in range(4)]
        rows.append(dict(rows[0], event_id=4624, timestamp="2026-10-14T12:00:10Z"))
        self.assertEqual(mod.hunt(rows), [])
    def test_separate_accounts(self):
        rows = [dict(event_id=4625, timestamp=f"2026-10-14T12:00:0{i}Z", host="test", user="x", source_ip="192.0.2.1") for i in range(5)]
        rows.append(dict(rows[0], event_id=4624, user="other", timestamp="2026-10-14T12:00:10Z"))
        self.assertEqual(mod.hunt(rows), [])
    def test_reject_nonobject(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.jsonl"
            p.write_text("[]\n")
            with self.assertRaises(ValueError):
                mod.load(p)

if __name__ == "__main__":
    unittest.main()
