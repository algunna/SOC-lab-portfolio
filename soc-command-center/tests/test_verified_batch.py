"""Sealed SOC batch consumer regression tests (offline only)."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


batch = module("verified_test_batch", ROOT / "soc-event-ingestion/src/batch_health.py")
integrity = module("verified_test_integrity", ROOT / "soc-event-ingestion/src/artifact_integrity.py")
adapter = module("verified_test_adapter", ROOT / "soc-command-center/src/adapter.py")
SAMPLE = json.loads((ROOT / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


class SealedDashboardTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.folder = Path(self.workspace.name)
        self.source = self.folder / "synthetic.json"
        self.source.write_text(json.dumps(SAMPLE), encoding="utf-8")
        self.batch = self.folder / "sealed-batch"
        self.assertEqual(batch.process([self.source], self.batch)["status"], "passed")

    def run_adapter(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "soc-command-center/src/adapter.py"), *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=15)

    def test_verified_reports_work_without_reopening_files(self):
        a, c = integrity.verified_reports(self.batch)
        self.assertEqual(adapter.build(a, c)["alerts"][0]["event_id"], SAMPLE["event_id"])
        self.assertEqual(len(c["incident_candidates"]), 1)

    def test_forged_correlator_severity_and_refreshed_hash_refused(self):
        corr = self.batch / "correlation.json"
        doc = json.loads(corr.read_text())
        doc["incident_candidates"][0]["highest_severity"] = "critical"
        corr.write_text(json.dumps(doc))
        manifest = self.batch / "integrity.json"
        marker = json.loads(manifest.read_text())
        marker["files"] = integrity.fingerprints(self.batch, integrity.FILE_SETS["passed"])
        manifest.write_text(json.dumps(marker))
        dest = self.folder / "forged.json"
        result = self.run_adapter("--batch-dir", self.batch, "--out", dest)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(dest.exists())

    def test_cli_sealed_pipeline_success(self):
        output = self.folder / "dashboard.json"
        result = self.run_adapter("--batch-dir", self.batch, "--out", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual((len(data["alerts"]), len(data["candidates"]), len(data["cases"])), (1, 1, 0))

    def test_tampered_ingestion_rejected_without_output(self):
        (self.batch / "ingestion.json").write_text('{"accepted":[]}', encoding="utf-8")
        output = self.folder / "refused.json"
        result = self.run_adapter("--batch-dir", self.batch, "--out", output)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_tampered_correlation_rejected_without_output(self):
        (self.batch / "correlation.json").write_text('{"incident_candidates":[]}', encoding="utf-8")
        with self.assertRaises(ValueError):
            integrity.verified_reports(self.batch)

    def test_missing_completion_marker_rejected(self):
        (self.batch / "integrity.json").unlink()
        with self.assertRaisesRegex(ValueError, "Missing completion"):
            integrity.verified_reports(self.batch)

    def test_extra_file_rejected(self):
        (self.batch / "secret.log").write_text("ignore")
        with self.assertRaisesRegex(ValueError, "Unexpected or missing"):
            integrity.verified_reports(self.batch)

    def test_symlinked_ingestion_rejected(self):
        original = self.batch / "ingestion.json"
        other = self.folder / "outside.json"
        other.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(other)
        with self.assertRaises(ValueError):
            integrity.verified_reports(self.batch)

    def test_blocked_batch_does_not_feed_dashboard(self):
        denied = self.folder / "bad-batch"
        self.source.write_text("{broken", encoding="utf-8")
        self.assertEqual(batch.process([self.source], denied)["status"], "blocked")
        self.assertEqual(integrity.verify(denied)["status"], "blocked")
        with self.assertRaisesRegex(ValueError, "Blocked batches"):
            integrity.verified_reports(denied)
        out = self.folder / "not-created.json"
        result = self.run_adapter("--batch-dir", denied, "--out", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out.exists())

    def test_output_must_not_modify_sealed_directory(self):
        result = self.run_adapter("--batch-dir", self.batch, "--out", self.batch / "dashboard.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.batch / "dashboard.json").exists())
        self.assertEqual(integrity.verify(self.batch)["status"], "passed")

    def test_cli_rejects_mixed_legacy_and_sealed_arguments(self):
        out = self.folder / "not-created.json"
        result = self.run_adapter("--batch-dir", self.batch, "--ingestion",
                                  self.batch / "ingestion.json", "--out", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(out.exists())

    def test_cli_requires_pair_of_legacy_inputs(self):
        result = self.run_adapter("--ingestion", self.batch / "ingestion.json",
                                  "--out", self.folder / "not-created.json")
        self.assertNotEqual(result.returncode, 0)

    def test_existing_output_refused(self):
        output = self.folder / "original.json"
        output.write_text("preserve", encoding="utf-8")
        result = self.run_adapter("--batch-dir", self.batch, "--out", output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "preserve")

    def test_changed_health_rejected_even_if_metadata_updated(self):
        health = self.batch / "health.json"
        content = json.loads(health.read_text())
        content["counts"]["accepted"] = 100
        health.write_text(json.dumps(content), encoding="utf-8")
        manifest = self.batch / "integrity.json"
        marker = json.loads(manifest.read_text())
        marker["files"] = integrity.fingerprints(self.batch, integrity.FILE_SETS["passed"])
        manifest.write_text(json.dumps(marker), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "counts"):
            integrity.verified_reports(self.batch)

    def test_local_manifest_forgery_not_claimed_as_provenance(self):
        """Hash checks alone cannot attest who wrote the data."""
        data = self.batch / "ingestion.json"
        obj = json.loads(data.read_text())
        obj["accepted"][0]["title"] = "Offline training title changed"
        data.write_text(json.dumps(obj), encoding="utf-8")
        manifest = self.batch / "integrity.json"
        marker = json.loads(manifest.read_text())
        marker["files"] = integrity.fingerprints(self.batch, integrity.FILE_SETS["passed"])
        manifest.write_text(json.dumps(marker), encoding="utf-8")
        result, _ = integrity.verified_reports(self.batch)
        self.assertEqual(result["accepted"][0]["title"], "Offline training title changed")

    def test_report_counters_invalid_type_rejected(self):
        modified = self.batch / "ingestion.json"
        data = json.loads(modified.read_text())
        data["counts"] = "bad"
        modified.write_text(json.dumps(data), encoding="utf-8")
        marker = self.batch / "integrity.json"
        obj = json.loads(marker.read_text())
        obj["files"] = integrity.fingerprints(self.batch, integrity.FILE_SETS["passed"])
        marker.write_text(json.dumps(obj), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Invalid batch report counters"):
            integrity.verified_reports(self.batch)


if __name__ == "__main__":
    unittest.main()
