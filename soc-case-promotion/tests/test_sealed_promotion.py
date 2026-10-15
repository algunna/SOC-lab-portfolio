"""Sealed batch verification must precede analyst case promotion and DB mutation."""
import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sealed_promotion_health", ROOT / "soc-event-ingestion/src/batch_health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
SAMPLE = json.loads((ROOT / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


class SealedPromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "synthetic.json"
        self.source.write_text(json.dumps(SAMPLE), encoding="utf-8")
        self.folder = self.root / "batch"
        self.assertEqual(health.process([self.source], self.folder)["status"], "passed")
        c = json.loads((self.folder / "correlation.json").read_text())
        self.candidate = c["incident_candidates"][0]["candidate_id"]
        self.db = self.root / "cases.db"

    def promote(self, *extra):
        args = [sys.executable, str(ROOT / "soc-case-promotion/src/promote.py"),
                "--batch-dir", str(self.folder), "--db", str(self.db),
                "--candidate-id", self.candidate, "--analyst", "synthetic-reviewer", *extra]
        return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=15)

    def test_forged_correlator_severity_and_updated_manifest_refused(self):
        import hashlib
        corr = self.folder / "correlation.json"
        doc = json.loads(corr.read_text())
        doc["incident_candidates"][0]["highest_severity"] = "critical"
        corr.write_text(json.dumps(doc))
        marker_path = self.folder / "integrity.json"
        manifest = json.loads(marker_path.read_text())
        raw = corr.read_bytes()
        manifest["files"]["correlation.json"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        marker_path.write_text(json.dumps(manifest))
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_requires_explicit_approval_and_keeps_db_absent(self):
        result = self.promote()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_verified_approved_case_and_audit(self):
        result = self.promote("--approve")
        self.assertEqual(result.returncode, 0, result.stderr)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cases").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM promoted_alerts").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM history").fetchone()[0], 3)

    def test_tampered_correlation_is_refused_before_db_creation(self):
        with (self.folder / "correlation.json").open("a", encoding="utf-8") as file:
            file.write(" ")
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_tampered_ingestion_is_refused_before_db_creation(self):
        (self.folder / "ingestion.json").write_text('{"accepted":[]}', encoding="utf-8")
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_missing_completion_marker_refused_before_db_creation(self):
        (self.folder / "integrity.json").unlink()
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_no_db_inside_sealed_directory(self):
        self.db = self.folder / "cases.db"
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_legacy_report_with_batch_dir_rejected(self):
        result = self.promote(str(self.folder / "correlation.json"), "--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_blocked_batch_refused_before_db_creation(self):
        self.source.write_text("{invalid", encoding="utf-8")
        self.folder = self.root / "quarantined"
        self.assertEqual(health.process([self.source], self.folder)["status"], "blocked")
        result = self.promote("--approve")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.db.exists())

    def test_duplicate_case_refused_without_extra_row(self):
        self.assertEqual(self.promote("--approve").returncode, 0)
        self.assertNotEqual(self.promote("--approve").returncode, 0)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cases").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
