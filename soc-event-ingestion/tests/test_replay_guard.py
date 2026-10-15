"""Cross-invocation replay protections for synthetic normalized SOC alerts."""
import copy
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_persistent_replay_test", ROOT / "src" / "replay_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
cspec = importlib.util.spec_from_file_location("soc_correlation_replay_test", ROOT.parent / "soc-incident-correlation/src/correlate.py")
correlation = importlib.util.module_from_spec(cspec)
cspec.loader.exec_module(correlation)
SAMPLE = json.loads((ROOT.parent / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


def report(*alerts):
    return {"schema_version": "1.0", "accepted": list(alerts), "rejected": [],
            "duplicates": [], "counts": {"accepted": len(alerts), "rejected": 0, "duplicates": 0}}


class ReplayGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "local-state.db"
        self.num = 0

    def stage(self, value):
        self.num += 1
        output = self.root / f"filtered-{self.num}.json"
        data = guard.run(value, self.db, output)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), data)
        return data

    def test_first_batch_accepted(self):
        result = self.stage(report(SAMPLE))
        self.assertEqual(result["counts"]["accepted"], 1)
        self.assertEqual(result["replay_guard"], {"new": 1, "skipped": 0})
        self.assertEqual(len(correlation.group_alerts(result)["incident_candidates"]), 1)

    def test_repeating_same_batch_skips_replay(self):
        self.stage(report(SAMPLE))
        repeated = self.stage(report(SAMPLE))
        self.assertEqual(repeated["accepted"], [])
        self.assertEqual(repeated["replay_guard"], {"new": 0, "skipped": 1})
        self.assertEqual(correlation.group_alerts(repeated)["counts"]["candidates"], 0)

    def test_new_event_id_same_observation_is_replay(self):
        self.stage(report(SAMPLE))
        altered = copy.deepcopy(SAMPLE)
        altered["event_id"] = "win-lab-reexport-02"
        self.assertEqual(self.stage(report(altered))["replay_guard"]["skipped"], 1)

    def test_different_records_accepted(self):
        self.stage(report(SAMPLE))
        changed = copy.deepcopy(SAMPLE)
        changed["event_id"] = "win-lab-002"
        changed["source"]["record_id"] = "synthetic-4688-002"
        result = self.stage(report(changed))
        self.assertEqual(result["counts"]["accepted"], 1)

    def test_same_event_id_changed_observation_conflicts_and_rolls_back(self):
        self.stage(report(SAMPLE))
        changed = copy.deepcopy(SAMPLE)
        changed["source"]["record_id"] = "synthetic-4688-002"
        with self.assertRaisesRegex(ValueError, "Conflicting reused"):
            guard.run(report(changed), self.db, self.root / "failed.json")
        self.assertFalse((self.root / "failed.json").exists())
        self.assertEqual(self.stage(report(SAMPLE))["replay_guard"]["skipped"], 1)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM observed").fetchone()[0], 1)

    def test_same_record_changed_evidence_is_conflict(self):
        self.stage(report(SAMPLE))
        changed = copy.deepcopy(SAMPLE)
        changed["evidence"][0]["description"] = "Different evidence supplied"
        with self.assertRaisesRegex(ValueError, "Conflicting previously"):
            guard.run(report(changed), self.db, self.root / "failed.json")

    def test_mixed_new_and_conflicting_batch_is_fully_rolled_back(self):
        self.stage(report(SAMPLE))
        new = copy.deepcopy(SAMPLE)
        new["event_id"] = "win-lab-999"
        new["source"]["record_id"] = "synthetic-new-999"
        wrong = copy.deepcopy(SAMPLE)
        wrong["title"] = "Tampered alert"
        with self.assertRaises(ValueError):
            guard.run(report(new, wrong), self.db, self.root / "failed.json")
        self.assertFalse((self.root / "failed.json").exists())
        self.assertEqual(self.stage(report(new))["counts"]["accepted"], 1)

    def test_rejected_report_blocked_before_state_file_creation(self):
        bad = report(SAMPLE)
        bad["rejected"] = [{"line": 1, "errors": ["malformed"]}]
        bad["counts"]["rejected"] = 1
        with self.assertRaises(ValueError):
            guard.run(bad, self.db, self.root / "failed.json")
        self.assertFalse(self.db.exists())
        self.assertFalse((self.root / "failed.json").exists())

    def test_mismatched_counts_blocked(self):
        bad = report(SAMPLE)
        bad["counts"]["accepted"] = 2
        with self.assertRaisesRegex(ValueError, "counts"):
            guard.run(bad, self.db, self.root / "invalid.json")

    def test_invalid_alert_blocked(self):
        wrong = copy.deepcopy(SAMPLE)
        wrong["severity"] = "supercritical"
        with self.assertRaisesRegex(ValueError, "event-contract"):
            guard.run(report(wrong), self.db, self.root / "invalid.json")

    def test_repeated_within_one_report_blocked(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            guard.run(report(SAMPLE, SAMPLE), self.db, self.root / "invalid.json")

    def test_existing_output_not_overwritten(self):
        output = self.root / "exists.json"
        output.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            guard.run(report(SAMPLE), self.db, output)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.db.exists())

    def test_output_failure_rolls_back_database_insert(self):
        with sqlite3.connect(":memory:", isolation_level=None) as db:
            db.executescript(guard.SCHEMA)
            def fail(_):
                raise OSError("simulated file write failure")
            with self.assertRaises(OSError):
                guard.process(report(SAMPLE), db, write_output=fail)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM observed").fetchone()[0], 0)

    def test_state_stores_hashes_not_full_log_fields(self):
        self.stage(report(SAMPLE))
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT observation_key, event_key, payload_hash FROM observed").fetchone()
        self.assertTrue(all(len(key) == 64 for key in row))
        content = json.dumps(row)
        self.assertNotIn("Encoded PowerShell", content)
        self.assertNotIn("LAB", content)

    def test_skipped_duplicates_preserve_original_count(self):
        self.stage(report(SAMPLE))
        r = report(SAMPLE)
        r["duplicates"] = [{"file": "synthetic.jsonl", "line": 2, "event_id": SAMPLE["event_id"]}]
        r["counts"]["duplicates"] = 1
        result = self.stage(r)
        self.assertEqual(result["counts"]["duplicates"], 2)
        self.assertEqual(result["replay_guard"]["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
