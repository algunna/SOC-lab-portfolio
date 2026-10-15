"""Safety, quarantine, and manual recovery tests for offline batch-health reports."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("offline_batch_health", ROOT / "src" / "batch_health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
SAMPLE = json.loads((ROOT.parent / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


class BatchHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def input(self, name, content=None):
        file = self.root / name
        file.write_text(json.dumps(SAMPLE) if content is None else content, encoding="utf-8")
        return file

    def run_batch(self, files, folder="batch"):
        target = self.root / folder
        result = health.process(files, target)
        self.assertEqual(json.loads((target / "health.json").read_text()), result)
        return result, target

    def test_valid_single_alert_and_correlated_candidate(self):
        result, target = self.run_batch([self.input("alert.json")])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["stage"], "complete")
        self.assertEqual(result["counts"], {"accepted": 1, "rejected": 0, "duplicates": 0, "candidates": 1})
        self.assertTrue((target / "ingestion.json").is_file())
        self.assertTrue((target / "correlation.json").is_file())
        self.assertFalse((target / "quarantine.json").exists())

    def test_valid_three_source_fixture(self):
        source = ROOT.parent / "splunk-readonly-connector/fixtures/synthetic_saved_search_alerts.jsonl"
        spec = importlib.util.spec_from_file_location("health_splunk_normalize", ROOT.parent / "splunk-readonly-connector/src/normalize.py")
        normalize = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(normalize)
        alerts = normalize.transform_jsonl(source.read_bytes())
        fixture = self.input("alerts.jsonl", "\n".join(json.dumps(a) for a in alerts))
        result, _ = self.run_batch([fixture])
        self.assertEqual(result["counts"]["accepted"], 3)
        self.assertEqual(result["counts"]["candidates"], 3)

    def test_malformed_json_quarantined_without_raw_log(self):
        bad = self.input("bad.jsonl", '{"secret":"PASSWORD-DO-NOT-LEAK"')
        result, target = self.run_batch([bad])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["stage"], "ingestion")
        self.assertFalse((target / "ingestion.json").exists())
        self.assertFalse((target / "correlation.json").exists())
        quarantine = (target / "quarantine.json").read_text()
        self.assertNotIn("PASSWORD-DO-NOT-LEAK", quarantine)
        self.assertNotIn(str(bad), quarantine)
        self.assertIn("invalid_json", quarantine)

    def test_validation_errors_cannot_leak_submitted_secrets(self):
        alert = copy.deepcopy(SAMPLE)
        alert["severity"] = "SECRET-DO-NOT-LEAK"
        bad = self.input("invalid.json", json.dumps(alert))
        result, target = self.run_batch([bad])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["counts"]["rejected"], 1)
        self.assertNotIn("SECRET-DO-NOT-LEAK", (target / "health.json").read_text())
        self.assertNotIn("SECRET-DO-NOT-LEAK", (target / "quarantine.json").read_text())

    def test_mixed_batch_rejected_entirely_no_partial_accepted_output(self):
        good = self.input("good.json")
        bad = self.input("bad.jsonl", "{broken")
        result, target = self.run_batch([good, bad])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["counts"]["accepted"], 1)
        self.assertFalse((target / "ingestion.json").exists())
        self.assertFalse((target / "correlation.json").exists())
        issues = json.loads((target / "quarantine.json").read_text())["issues"]
        self.assertEqual(issues, [{"source_index": 2, "line": 1, "reason": "invalid_json"}])

    def test_preflight_missing_file_and_safe_metadata(self):
        missing = self.root / "SECRET-NAME.json"
        result, target = self.run_batch([missing])
        self.assertEqual(result["stage"], "preflight")
        self.assertEqual(result["counts"]["rejected"], 1)
        self.assertEqual(json.loads((target / "quarantine.json").read_text())["issues"][0]["reason"], "input_unavailable")
        self.assertNotIn("SECRET-NAME", (target / "quarantine.json").read_text())

    def test_oversized_input_rejected_without_reading(self):
        file = self.input("big.json", "x" * (health.MAX_FILE_BYTES + 1))
        result, target = self.run_batch([file])
        self.assertEqual(result["stage"], "preflight")
        self.assertIn("input_too_large", (target / "quarantine.json").read_text())
        self.assertFalse((target / "ingestion.json").exists())

    def test_unsupported_file_extension_rejected(self):
        file = self.input("input.txt")
        result, target = self.run_batch([file])
        self.assertEqual(result["stage"], "preflight")
        self.assertIn("unsupported_extension", (target / "quarantine.json").read_text())

    def test_symlink_input_rejected(self):
        target = self.input("normal.json")
        link = self.root / "linked.json"
        link.symlink_to(target)
        result, folder = self.run_batch([link])
        self.assertEqual(result["stage"], "preflight")
        self.assertIn("symlink_refused", (folder / "quarantine.json").read_text())

    def test_conflicting_source_event_identity_blocked(self):
        other = copy.deepcopy(SAMPLE)
        other["source"]["record_id"] = "different-record"
        file = self.input("events.jsonl", json.dumps(SAMPLE) + "\n" + json.dumps(other))
        result, target = self.run_batch([file])
        self.assertEqual(result["status"], "blocked")
        self.assertIn("conflicting_event_id", (target / "quarantine.json").read_text())

    def test_explicit_manual_recovery_to_different_output_dir(self):
        file = self.input("retry.json", "{broken")
        first, target = self.run_batch([file], "failed-attempt")
        self.assertEqual(first["status"], "blocked")
        file.write_text(json.dumps(SAMPLE), encoding="utf-8")
        second, recovered = self.run_batch([file], "new-attempt")
        self.assertEqual(second["status"], "passed")
        self.assertEqual(json.loads((target / "health.json").read_text())["status"], "blocked")
        self.assertFalse((target / "ingestion.json").exists())
        self.assertTrue((recovered / "ingestion.json").exists())

    def test_existing_directory_refused_with_no_overwrite(self):
        file = self.input("alert.json")
        folder = self.root / "already-used"
        folder.mkdir()
        marker = folder / "important.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            health.process([file], folder)
        self.assertEqual(marker.read_text(), "preserve")

    def test_correlation_failure_is_sanitized_and_blocked(self):
        file = self.input("alert.json")
        with patch.object(health.correlation, "group_alerts", side_effect=ValueError("SECRET-LOG-BODY")):
            result, target = self.run_batch([file])
        self.assertEqual(result["stage"], "correlation")
        self.assertIn("correlation_failed", (target / "quarantine.json").read_text())
        self.assertNotIn("SECRET-LOG-BODY", (target / "quarantine.json").read_text())
        self.assertFalse((target / "ingestion.json").exists())

    def test_limit_source_files(self):
        source = self.input("one.json")
        with self.assertRaises(ValueError):
            health.process([source] * (health.MAX_SOURCES + 1), self.root / "too-many")
        self.assertFalse((self.root / "too-many").exists())

    def test_accepted_limit_blocks_full_batch(self):
        source = self.input("one.json")
        with patch.object(health, "MAX_ALERTS", 0):
            result, target = self.run_batch([source])
        self.assertEqual(result["stage"], "ingestion")
        self.assertIn("too_many_alerts", (target / "quarantine.json").read_text())
        self.assertFalse((target / "ingestion.json").exists())


if __name__ == "__main__":
    unittest.main()
