"""Offline batch completion seals: tamper detection, bounded reads and privacy."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

health = module("integrity_test_health", "batch_health.py")
integrity = module("integrity_test_verifier", "artifact_integrity.py")
SAMPLE = json.loads((ROOT.parent / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


class BatchIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def input(self, name="good.json", content=None):
        file = self.base / name
        file.write_text(json.dumps(SAMPLE) if content is None else content, encoding="utf-8")
        return file

    def successful(self, dirname="good-batch"):
        folder = self.base / dirname
        self.assertEqual(health.process([self.input()], folder)["status"], "passed")
        return folder

    def blocked(self):
        folder = self.base / "failed-batch"
        self.assertEqual(health.process([self.input("bad.jsonl", "{broken PRIVATE-STRING")], folder)["status"], "blocked")
        return folder

    def test_success_creates_and_verifies_seal(self):
        folder = self.successful()
        outcome = integrity.verify(folder)
        self.assertEqual(outcome, {"integrity": "verified_local_hashes", "status": "passed",
                                   "artifact_count": 3, "mode": "offline_training"})
        marker = json.loads((folder / "integrity.json").read_text())
        self.assertEqual(set(marker["files"]), {"health.json", "ingestion.json", "correlation.json"})

    def test_blocked_batch_can_be_verified_without_ingestion(self):
        folder = self.blocked()
        self.assertEqual(integrity.verify(folder)["status"], "blocked")
        self.assertEqual(set(p.name for p in folder.iterdir()),
                         {"health.json", "quarantine.json", "integrity.json"})

    def test_manifest_never_contains_raw_values_or_input_paths(self):
        folder = self.blocked()
        data = (folder / "integrity.json").read_text()
        for text in ("PRIVATE-STRING", "bad.jsonl", str(self.base), "LAB", "Encoded PowerShell"):
            self.assertNotIn(text, data)

    def test_corrupted_alert_report_rejected(self):
        folder = self.successful()
        f = folder / "ingestion.json"
        f.write_text(f.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed"):
            integrity.verify(folder)

    def test_corrupted_quarantine_rejected(self):
        folder = self.blocked()
        (folder / "quarantine.json").write_text('{"version":"0.1","issues":[]}', encoding="utf-8")
        with self.assertRaises(ValueError):
            integrity.verify(folder)

    def test_corrupted_health_rejected(self):
        folder = self.successful()
        data = json.loads((folder / "health.json").read_text())
        data["counts"]["accepted"] = 30
        (folder / "health.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            integrity.verify(folder)

    def test_missing_file_rejected(self):
        folder = self.successful()
        (folder / "correlation.json").unlink()
        with self.assertRaisesRegex(ValueError, "Unexpected or missing"):
            integrity.verify(folder)

    def test_incomplete_interrupted_batch_has_no_seal(self):
        folder = self.base / "interrupted"
        folder.mkdir()
        (folder / "health.json").write_text('{"version":"0.1"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Missing completion"):
            integrity.verify(folder)

    def test_unexpected_file_rejected(self):
        folder = self.successful()
        (folder / "secret.log").write_text("do not publish", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unexpected or missing"):
            integrity.verify(folder)

    def test_directory_symlink_rejected(self):
        folder = self.successful()
        shortcut = self.base / "shortcut"
        shortcut.symlink_to(folder, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not be a symlink"):
            integrity.verify(shortcut)

    def test_artifact_symlink_rejected(self):
        folder = self.successful()
        f = folder / "ingestion.json"
        other = self.base / "other.json"
        other.write_bytes(f.read_bytes())
        f.unlink()
        f.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "Symbolic link"):
            integrity.verify(folder)

    def test_malformed_completion_marker_rejected(self):
        folder = self.successful()
        f = folder / "integrity.json"
        value = json.loads(f.read_text())
        value["files"]["ingestion.json"]["sha256"] = "wrong"
        f.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ValueError):
            integrity.verify(folder)

    def test_manifest_extra_key_rejected(self):
        folder = self.successful()
        f = folder / "integrity.json"
        value = json.loads(f.read_text())
        value["input_name"] = "private path"
        f.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Malformed completion"):
            integrity.verify(folder)

    def test_invalid_health_stage_rejected_even_if_hashes_match(self):
        folder = self.successful()
        health_file = folder / "health.json"
        data = json.loads(health_file.read_text())
        data["stage"] = "preflight"
        health_file.write_text(json.dumps(data), encoding="utf-8")
        marker = folder / "integrity.json"
        value = json.loads(marker.read_text())
        value["files"] = integrity.fingerprints(folder, integrity.FILE_SETS["passed"])
        marker.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            integrity.verify(folder)

    def test_duplicate_json_keys_fail_closed(self):
        folder = self.successful()
        (folder / "integrity.json").write_text('{"version":"0.1","version":"0.1"}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            integrity.verify(folder)

    def test_manifest_and_files_have_size_limits(self):
        folder = self.successful()
        (folder / "integrity.json").write_bytes(b"x" * (integrity.MAX_SIZE["integrity.json"] + 1))
        with self.assertRaises(ValueError):
            integrity.verify(folder)

    def test_seal_missing_artifacts_refuses_completion(self):
        folder = self.base / "missing"
        folder.mkdir()
        (folder / "health.json").write_text(json.dumps({
            "version":"0.1", "mode":"offline_training", "status":"passed",
            "stage":"complete", "counts":{"accepted":1, "rejected":0, "duplicates":0, "candidates":1}
        }))
        with self.assertRaisesRegex(ValueError, "Incomplete or unexpected"):
            integrity.seal(folder, "passed")
        self.assertFalse((folder / "integrity.json").exists())

    def test_failed_seal_keeps_batch_unverified(self):
        folder = self.base / "forced-incomplete"
        with patch.object(health.integrity, "seal", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                health.process([self.input()], folder)
        self.assertFalse((folder / "integrity.json").exists())
        with self.assertRaisesRegex(ValueError, "Missing completion"):
            integrity.verify(folder)


if __name__ == "__main__":
    unittest.main()
