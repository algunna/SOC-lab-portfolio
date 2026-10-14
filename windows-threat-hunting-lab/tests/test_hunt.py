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
    def test_powershell_abbreviations_and_prefixes(self):
        commands = {
            "powershell.exe -e SQBFAFgA": ["encoded command"],
            "powershell.exe -ec SQBFAFgA": ["encoded command"],
            "powershell.exe /enc SQBFAFgA": ["encoded command"],
            "powershell.exe \u2013EncodedCommand SQBFAFgA": ["encoded command"],
            "powershell.exe -nop -enc\tSQBFAFgA": ["encoded command"],
            "powershell.exe -ep bypass -w hidden -File a.ps1": ["execution policy bypass", "hidden window"],
            "powershell.exe -ExecutionPolicy  Bypass": ["execution policy bypass"],
        }
        for command, expected in commands.items():
            with self.subTest(command=command):
                findings = mod.hunt([{"event_id": 4688, "image": "powershell.exe", "command_line": command}])
                self.assertEqual([f["evidence"] for f in findings], [expected])
    def test_powershell_benign_switches(self):
        for command in ("powershell.exe -ExecutionPolicy RemoteSigned", "powershell.exe -WindowStyle Normal", "powershell.exe -Command Get-Date"):
            with self.subTest(command=command):
                self.assertEqual(mod.hunt([{"event_id": 4688, "image": "powershell.exe", "command_line": command}]), [])
    def test_universal_group_change(self):
        findings = mod.hunt([{"event_id": 4756, "group": "Enterprise Admins"}])
        self.assertEqual([f["rule"] for f in findings], ["privileged_group_change"])
    def test_failures_with_mixed_case_and_offsets(self):
        users = ["labuser", "LabUser", "LABUSER", "Labuser", "labUser"]
        rows = [dict(event_id=4625, timestamp=f"2026-10-14T14:00:0{i}+02:00", host="test", user=u, source_ip="192.0.2.1") for i, u in enumerate(users)]
        rows.append(dict(event_id=4624, timestamp="2026-10-14T12:00:10Z", host="TEST", user="labuser", source_ip="192.0.2.1"))
        findings = mod.hunt(rows)
        self.assertEqual([f["rule"] for f in findings], ["success_after_failures"])
        self.assertEqual(findings[0]["source_ip"], "192.0.2.1")
    def test_success_outside_window(self):
        rows = [dict(event_id=4625, timestamp=f"2026-10-14T12:00:0{i}Z", host="test", user="x", source_ip="192.0.2.1") for i in range(5)]
        rows.append(dict(rows[0], event_id=4624, timestamp="2026-10-14T12:06:00Z"))
        self.assertEqual(mod.hunt(rows), [])
    def test_bad_timestamp_and_event_id_types(self):
        self.assertEqual(mod.hunt([{"event_id": 4688, "timestamp": 1}, {"event_id": "x"}, {"timestamp": None}]), [])
    def test_reject_nonobject(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.jsonl"
            p.write_text("[]\n")
            with self.assertRaises(ValueError):
                mod.load(p)

if __name__ == "__main__":
    unittest.main()
