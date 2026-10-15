"""Synthetic end-to-end SOC walkthrough: explicit approval and evidence integrity."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("soc_demo_runner", ROOT / "soc-demo/scripts/run_demo.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class SyntheticDemoTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.output = Path(self.workspace.name) / "soc-demo"

    def test_prepare_never_creates_a_case(self):
        demo.prepare(self.output)
        self.assertFalse((self.output / "cases.db").exists())
        self.assertFalse((self.output / "approved-dashboard.json").exists())
        initial = json.loads((self.output / "dashboard.json").read_text())
        self.assertEqual([len(initial[name]) for name in ("alerts", "candidates", "cases")], [3, 3, 0])
        self.assertEqual(demo.check_manifest(self.output), self.output)

    def test_prepare_will_not_overwrite_existing_directory(self):
        demo.prepare(self.output)
        with self.assertRaises(FileExistsError):
            demo.prepare(self.output)

    def test_promotion_requires_explicit_approval_flag(self):
        demo.prepare(self.output)
        report = json.loads((self.output / "correlation.json").read_text())
        candidate = report["incident_candidates"][0]["candidate_id"]
        with self.assertRaisesRegex(ValueError, "Explicit"):
            demo.approve_demo_case(self.output, candidate, "synthetic-reviewer")
        self.assertFalse((self.output / "cases.db").exists())

    def test_approved_case_has_expected_status_and_history(self):
        demo.prepare(self.output)
        candidate = json.loads((self.output / "correlation.json").read_text())["incident_candidates"][0]
        report = demo.approve_demo_case(self.output, candidate["candidate_id"], "synthetic-reviewer", approve=True)
        self.assertEqual(len(report["cases"]), 1)
        self.assertEqual(report["cases"][0]["severity"], candidate["highest_severity"])
        self.assertEqual(set(report["cases"][0]), {"id", "title", "severity", "status"})
        self.assertEqual([len(report[k]) for k in ("alerts", "candidates")], [3, 3])
        self.assertEqual(report["cases"][0]["status"], "open")
        import sqlite3
        with sqlite3.connect(self.output / "cases.db") as db:
            kinds = [row[0] for row in db.execute("SELECT kind FROM history ORDER BY id")]
            self.assertIn("created", kinds)
            self.assertIn("evidence", kinds)
            self.assertIn("note", kinds)
            approved = db.execute("SELECT approved_by FROM promoted_candidates").fetchone()[0]
            self.assertEqual(approved, "synthetic-reviewer")

    def test_same_case_cannot_be_approved_twice(self):
        demo.prepare(self.output)
        candidate = json.loads((self.output / "correlation.json").read_text())["incident_candidates"][0]["candidate_id"]
        demo.approve_demo_case(self.output, candidate, "reviewer", approve=True)
        with self.assertRaisesRegex(ValueError, "already exists"):
            demo.approve_demo_case(self.output, candidate, "reviewer", approve=True)

    def test_changed_correlator_output_cannot_be_approved(self):
        demo.prepare(self.output)
        path = self.output / "correlation.json"
        report = json.loads(path.read_text())
        candidate = report["incident_candidates"][0]["candidate_id"]
        report["incident_candidates"][0]["highest_severity"] = "critical"
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "changed after"):
            demo.approve_demo_case(self.output, candidate, "reviewer", approve=True)
        self.assertFalse((self.output / "cases.db").exists())

    def test_unknown_candidate_cannot_be_approved(self):
        demo.prepare(self.output)
        with self.assertRaisesRegex(ValueError, "candidate ID"):
            demo.approve_demo_case(self.output, "candidate-forged", "reviewer", approve=True)
        self.assertFalse((self.output / "cases.db").exists())

    def test_partial_or_missing_manifest_rejected(self):
        demo.prepare(self.output)
        (self.output / "manifest.json").unlink()
        with self.assertRaises(FileNotFoundError):
            demo.approve_demo_case(self.output, "candidate-forged", "reviewer", approve=True)
        self.assertFalse((self.output / "cases.db").exists())


if __name__ == "__main__":
    unittest.main()
