"""Pipeline 14: cross-batch alias binding and synthetic-source change tests."""
import copy
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

guard = module("replay_alias_guard_tests", "soc-event-ingestion/src/replay_guard.py")
bridge = module("replay_alias_bridge_tests", "detection-accuracy-lab/src/to_soc_alerts.py")
fixture = ROOT / "detection-accuracy-lab/fixtures/labeled_scenarios.json"


def report(alerts):
    return {"schema_version": "1.0", "accepted": copy.deepcopy(alerts),
            "rejected": [], "duplicates": [],
            "counts": {"accepted": len(alerts), "rejected": 0, "duplicates": 0}}


class AliasBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "state.db"
        self.number = 0
        self.alerts = bridge.bridge(fixture.read_bytes())
        self.first = self.alerts[0]

    def apply(self, alerts):
        self.number += 1
        output = self.dir / f"result-{self.number}.json"
        value = guard.run(report(alerts), self.db, output)
        self.assertEqual(json.loads(output.read_text()), value)
        return value

    def aliases(self):
        with sqlite3.connect(self.db) as db:
            return db.execute(
                "SELECT event_key,observation_key,payload_hash FROM event_aliases ORDER BY event_key"
            ).fetchall()

    def test_initial_synthetic_batch_and_repeat(self):
        first = self.apply(self.alerts)
        self.assertEqual(first["counts"]["accepted"], len(self.alerts))
        again = self.apply(self.alerts)
        self.assertEqual(again["counts"]["accepted"], 0)
        self.assertEqual(again["replay_guard"]["skipped"], len(self.alerts))
        self.assertEqual(len(self.aliases()), len(self.alerts))

    def test_new_event_id_old_observation_is_remembered(self):
        self.apply([self.first])
        alias = copy.deepcopy(self.first)
        alias["event_id"] = "lab-reexport-123"
        second = self.apply([alias])
        self.assertEqual(second["replay_guard"], {"new": 0, "skipped": 1})
        self.assertEqual(len(self.aliases()), 2)

    def test_replay_alias_cannot_be_used_for_different_observation(self):
        self.apply([self.first])
        alias = copy.deepcopy(self.first)
        alias["event_id"] = "lab-reexport-123"
        self.apply([alias])
        conflicting = copy.deepcopy(self.first)
        conflicting["event_id"] = "lab-reexport-123"
        conflicting["source"]["record_id"] = "synthetic-different-observation"
        bad_out = self.dir / "refused.json"
        with self.assertRaisesRegex(ValueError, "Conflicting reused"):
            guard.run(report([conflicting]), self.db, bad_out)
        self.assertFalse(bad_out.exists())
        self.assertEqual(len(self.aliases()), 2)

    def test_conflict_in_mixed_batch_rolls_back_new_alias_and_observation(self):
        self.apply([self.first])
        alias = copy.deepcopy(self.first)
        alias["event_id"] = "lab-remember-me"
        self.apply([alias])
        fresh = copy.deepcopy(self.first)
        fresh["event_id"] = "lab-brand-new"
        fresh["source"]["record_id"] = "fresh-record"
        conflicting = copy.deepcopy(self.first)
        conflicting["event_id"] = "lab-remember-me"
        conflicting["source"]["record_id"] = "wrong-record"
        out = self.dir / "not-created.json"
        with self.assertRaises(ValueError):
            guard.run(report([fresh, conflicting]), self.db, out)
        self.assertFalse(out.exists())
        self.assertEqual(len(self.aliases()), 2)
        self.assertEqual(self.apply([fresh])["counts"]["accepted"], 1)

    def test_record_payload_change_rejected_even_for_new_event_id(self):
        self.apply([self.first])
        changed = copy.deepcopy(self.first)
        changed["event_id"] = "lab-renamed-event"
        changed["evidence"][0]["description"] = "Synthetic alternate evidence label"
        with self.assertRaisesRegex(ValueError, "Conflicting previously observed"):
            guard.run(report([changed]), self.db, self.dir / "reject.json")

    def test_original_primary_event_is_still_bound_after_alias(self):
        self.apply([self.first])
        alias = copy.deepcopy(self.first)
        alias["event_id"] = "lab-second-event"
        self.apply([alias])
        wrong = copy.deepcopy(self.first)
        wrong["source"]["record_id"] = "different-observation"
        with self.assertRaisesRegex(ValueError, "Conflicting reused"):
            guard.run(report([wrong]), self.db, self.dir / "reject.json")

    def test_existing_legacy_sqlite_state_is_migrated(self):
        observation, event, fingerprint = guard.keys(self.first)
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE observed (observation_key TEXT PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL)")
            db.execute("INSERT INTO observed VALUES (?,?,?)", (observation, event, fingerprint))
        replay = self.apply([self.first])
        self.assertEqual(replay["replay_guard"]["skipped"], 1)
        self.assertEqual(len(self.aliases()), 1)
        renamed = copy.deepcopy(self.first)
        renamed["event_id"] = "lab-legacy-export"
        self.assertEqual(self.apply([renamed])["replay_guard"]["skipped"], 1)
        self.assertEqual(len(self.aliases()), 2)

    def test_conflicting_preexisting_database_is_refused(self):
        observation, event, fingerprint = guard.keys(self.first)
        with sqlite3.connect(self.db) as db:
            db.executescript(guard.SCHEMA)
            db.execute("INSERT INTO observed VALUES (?,?,?)", (observation, event, fingerprint))
            db.execute("INSERT INTO event_aliases VALUES (?,?,?)", (event, "forged-observation", fingerprint))
        out = self.dir / "not-created.json"
        with self.assertRaisesRegex(ValueError, "database conflicts"):
            guard.run(report([self.first]), self.db, out)
        self.assertFalse(out.exists())

    def test_changed_synthetic_source_same_detector_rule_changes_evidence(self):
        original = json.loads(fixture.read_text(encoding="utf-8"))
        altered = copy.deepcopy(original)
        scenario = next(s for s in altered["scenarios"] if s["id"] == "win-encoded-command")
        scenario["events"][0]["command_line"] = "powershell.exe -EncodedCommand REVG"
        changed = bridge.bridge(json.dumps(altered).encode("utf-8"))
        old = next(a for a in self.alerts if a["rule_id"] == "windows.powershell.suspicious")
        # Several scenarios share a rule; compare exact stable IDs.
        fresh = next(a for a in changed if a["event_id"] == old["event_id"])
        self.assertEqual(old["source"]["record_id"], fresh["source"]["record_id"])
        self.assertNotEqual(old["evidence"], fresh["evidence"])
        self.apply([old])
        with self.assertRaisesRegex(ValueError, "Conflicting reused"):
            guard.run(report([fresh]), self.db, self.dir / "modified-source.json")

    def test_db_contains_only_hashed_identifiers(self):
        self.apply([self.first])
        alternate = copy.deepcopy(self.first)
        alternate["event_id"] = "lab-second-id"
        self.apply([alternate])
        rows = self.aliases()
        self.assertTrue(all(len(field) == 64 for row in rows for field in row))
        self.assertNotIn(self.first["actor"], repr(rows))
        self.assertNotIn(self.first["asset"], repr(rows))


if __name__ == "__main__":
    unittest.main()
