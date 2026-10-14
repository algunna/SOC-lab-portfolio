"""Read-only case snapshot regression tests against temporary synthetic databases."""
import hashlib
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_case_snapshot_test", ROOT / "src" / "case_snapshot.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
aspec = importlib.util.spec_from_file_location("soc_adapter_test", ROOT / "src" / "adapter.py")
adapter = importlib.util.module_from_spec(aspec)
aspec.loader.exec_module(adapter)
dspec = importlib.util.spec_from_file_location("soc_dashboard_test", ROOT / "src" / "dashboard.py")
dashboard = importlib.util.module_from_spec(dspec)
dspec.loader.exec_module(dashboard)


class ReadOnlyCasesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbfile = Path(self.temp.name) / "cases.db"
        with sqlite3.connect(self.dbfile) as db:
            db.executescript("""
            CREATE TABLE cases(id INTEGER PRIMARY KEY, title TEXT NOT NULL,
                               severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                               created_at TEXT NOT NULL);
            CREATE TABLE history(id INTEGER PRIMARY KEY, case_id INTEGER,
                                 kind TEXT, detail TEXT, recorded_at TEXT);
            """)
            db.execute("INSERT INTO cases(id, title, severity, status, created_at) VALUES (1, ?, ?, ?, ?)",
                       ("<script>alert(1)</script>", "high", "investigating", "2026-10-14T12:00:00+00:00"))
            db.execute("INSERT INTO history(case_id,kind,detail,recorded_at) VALUES (1,'note','PRIVATE HISTORY','now')")
    def test_read_existing_case(self):
        rows = snapshot.read_cases(self.dbfile)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(set(rows[0]), {"id", "title", "severity", "status"})
    def test_snapshot_does_not_change_db(self):
        before = hashlib.sha256(self.dbfile.read_bytes()).hexdigest()
        self.assertEqual(len(snapshot.read_cases(self.dbfile)), 1)
        self.assertEqual(before, hashlib.sha256(self.dbfile.read_bytes()).hexdigest())
    def test_unknown_db_not_created(self):
        path = self.dbfile.parent / "absent.db"
        with self.assertRaises(FileNotFoundError):
            snapshot.read_cases(path)
        self.assertFalse(path.exists())
    def test_reject_wrong_schema(self):
        with sqlite3.connect(self.dbfile) as db:
            db.execute("ALTER TABLE cases RENAME TO unrelated")
        with self.assertRaises(ValueError):
            snapshot.read_cases(self.dbfile)
    def test_reject_unrecognized_severity(self):
        with sqlite3.connect(self.dbfile) as db:
            db.execute("UPDATE cases SET severity = 'untrusted'")
        with self.assertRaises(ValueError):
            snapshot.read_cases(self.dbfile)
    def test_reject_excessive_case_count(self):
        with sqlite3.connect(self.dbfile) as db:
            db.executemany("INSERT INTO cases(title,severity,status,created_at) VALUES ('demo','low','open','now')",
                           [() for _ in range(snapshot.MAX_CASES)])
        with self.assertRaisesRegex(ValueError, "demo limit"):
            snapshot.read_cases(self.dbfile)
    def test_html_safe_end_to_end(self):
        data = {"alerts": [], "candidates": [], "cases": snapshot.read_cases(self.dbfile)}
        page = dashboard.render(data)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("PRIVATE HISTORY", page)
    def test_adapter_with_cases(self):
        alert = json.loads((ROOT.parent / "soc-event-contract" / "examples" / "windows_alert.json").read_text())
        report = {"accepted": [alert], "rejected": []}
        correlate = {"version": "0.2", "incident_candidates": [
            {"candidate_id": "candidate-synthetic", "classification": "unverified", "alert_ids": [alert["event_id"]]}
        ]}
        data = adapter.build(report, correlate, cases=snapshot.read_cases(self.dbfile))
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["cases"][0]["status"], "investigating")


if __name__ == "__main__":
    unittest.main()
