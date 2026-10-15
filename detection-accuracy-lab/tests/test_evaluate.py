"""Synthetic detector-policy tests; results are NOT estimates of live accuracy."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_policy_evaluation", ROOT / "src/evaluate.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
MATRIX = ROOT / "fixtures/labeled_scenarios.json"


class AccuracyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(MATRIX.read_text(encoding="utf-8"))

    def evaluate(self):
        return module.evaluate(json.dumps(self.data).encode("utf-8"))

    def test_all_labeled_synthetic_scenarios_match(self):
        report = module.evaluate(MATRIX.read_bytes())
        self.assertEqual(report["scenario_count"], 32)
        self.assertEqual(report["matching_scenarios"], 32)
        self.assertEqual(report["mismatches"], [])
        self.assertIs(report["live_detection_accuracy_measured"], False)
        self.assertIs(report["production_false_positive_rate_measured"], False)

    def test_every_detector_rule_has_positive_and_negative_scenarios(self):
        report = self.evaluate()
        self.assertEqual(set(report["confusion_by_rule"]), {"windows", "cloudtrail"})
        for detector, rules in report["confusion_by_rule"].items():
            for name, counts in rules.items():
                with self.subTest(detector=detector, rule=name):
                    self.assertGreater(counts["tp"], 0)
                    self.assertGreater(counts["tn"], 0)
                    self.assertEqual(counts["fp"], 0)
                    self.assertEqual(counts["fn"], 0)
                    self.assertEqual(sum(counts.values()),
                                     sum(case["detector"] == detector
                                         for case in self.data["scenarios"]))

    def test_simulated_false_negative_reported_without_raw_events(self):
        case = next(c for c in self.data["scenarios"] if c["id"] == "win-encoded-command")
        case["expected_rules"] = ["privileged_group_change"]
        report = self.evaluate()
        self.assertEqual(report["matching_scenarios"], 31)
        self.assertEqual(report["mismatches"], [{
            "scenario_id": "win-encoded-command",
            "missing_rules": ["privileged_group_change"],
            "unexpected_rules": ["suspicious_powershell"],
        }])

    def test_simulated_unexpected_detection(self):
        case = next(c for c in self.data["scenarios"] if c["id"] == "aws-describe-instances")
        case["expected_rules"] = ["root_account_activity"]
        report = self.evaluate()
        self.assertEqual(report["matching_scenarios"], 31)
        self.assertEqual(report["confusion_by_rule"]["cloudtrail"]["root_account_activity"]["fn"], 1)

    def test_no_raw_event_content_in_report(self):
        report = json.dumps(self.evaluate())
        for sensitive in ("LAB-WS01", "labuser", "192.0.2.10", "198.51.100.5",
                          "EncodedCommand", "AttachRolePolicy", "QUJD", "command_line",
                          "source_ip", "eventTime", "sourceIPAddress"):
            self.assertNotIn(sensitive, report)

    def test_duplicate_scenario_ids_refused(self):
        self.data["scenarios"][1]["id"] = self.data["scenarios"][0]["id"]
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_unknown_rule_and_detector_refused(self):
        self.data["scenarios"][0]["expected_rules"] = ["hypothetical_unknown"]
        with self.assertRaises(ValueError):
            self.evaluate()
        self.data["scenarios"][0]["expected_rules"] = ["suspicious_powershell"]
        self.data["scenarios"][0]["detector"] = "splunk_live"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_invalid_mode_refused(self):
        self.data["scope"] = "real_world_accuracy"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_missing_events_and_nonobject_events_refused(self):
        self.data["scenarios"][0]["events"] = []
        with self.assertRaises(ValueError):
            self.evaluate()
        self.data["scenarios"][0]["events"] = ["synthetic-not-object"]
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_duplicate_json_keys_and_invalid_json_refused(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            module.evaluate(b'{"schema_version":"1.0","schema_version":"1.0"}')
        with self.assertRaises(ValueError):
            module.evaluate(b"{not-json")

    def test_oversized_input_and_excess_scenarios_refused(self):
        with self.assertRaises(ValueError):
            module.evaluate(b"X" * (module.MAX_INPUT_BYTES + 1))
        self.data["scenarios"] *= 3
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_windows_missing_identity_is_not_joined(self):
        ids = ["win-no-source-ip", "win-no-user", "win-no-host"]
        cases = [c for c in self.data["scenarios"] if c["id"] in ids]
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(id=case["id"]):
                self.assertEqual(module.DETECTORS["windows"].hunt(case["events"]), [])

    def test_cli_report_exclusive_and_synthetic_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "policy-summary.json"
            command = [sys.executable, str(ROOT / "src/evaluate.py"), "--out", str(output)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            record = json.loads(output.read_text())
            self.assertEqual(record["matching_scenarios"], 32)
            self.assertEqual(record["scope"], "synthetic_policy_only")
            self.assertFalse(record["production_false_positive_rate_measured"])
            second = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(json.loads(output.read_text()), record)


if __name__ == "__main__":
    unittest.main()
