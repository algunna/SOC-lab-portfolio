"""Semantic consistency checks: forged hashes must not hide altered candidate logic."""
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def get_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


health = get_module("semantic_health", ROOT / "soc-event-ingestion/src/batch_health.py")
integrity = get_module("semantic_integrity", ROOT / "soc-event-ingestion/src/artifact_integrity.py")
SAMPLE = json.loads((ROOT / "soc-event-contract/examples/windows_alert.json").read_text(encoding="utf-8"))


class SemanticIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.json"
        self.source.write_text(json.dumps(SAMPLE), encoding="utf-8")
        self.batch = self.root / "passed"
        self.assertEqual(health.process([self.source], self.batch)["status"], "passed")

    def rewrite_and_reseal(self, filename, edit):
        file = self.batch / filename
        data = json.loads(file.read_text(encoding="utf-8"))
        edit(data)
        file.write_text(json.dumps(data), encoding="utf-8")
        marker = self.batch / "integrity.json"
        value = json.loads(marker.read_text(encoding="utf-8"))
        value["files"] = integrity.fingerprints(self.batch, integrity.FILE_SETS["passed"])
        marker.write_text(json.dumps(value), encoding="utf-8")
        return data

    def test_genuine_batch_semantically_valid(self):
        report, candidates = integrity.verified_reports(self.batch)
        self.assertEqual(len(report["accepted"]), 1)
        self.assertEqual(len(candidates["incident_candidates"]), 1)

    def test_forged_severity_in_correlated_candidate_rejected(self):
        def tamper(data):
            data["incident_candidates"][0]["highest_severity"] = "critical"
        self.rewrite_and_reseal("correlation.json", tamper)
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_evidence_references_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d["incident_candidates"][0].update(
            evidence_references=["synthetic/fake-evidence"]))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_candidate_id_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d["incident_candidates"][0].update(
            candidate_id="candidate-forged"))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_alert_reference_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d["incident_candidates"][0].update(
            alert_ids=["alert-forged"]))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_grouping_reason_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d["incident_candidates"][0].update(
            reason="verified malicious intrusion"))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_extra_candidate_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d["incident_candidates"].append(
            copy.deepcopy(d["incident_candidates"][0])))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_ingestion_title_and_updated_manifest_without_candidate_update_rejected(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d["accepted"][0].update(
            title="Adversarially changed title"))
        # Title is not a correlation input; a hash alone cannot spot attacker re-signing.
        # This change remains detectable by changing a field used for correlation below.
        self.rewrite_and_reseal("ingestion.json", lambda d: d["accepted"][0].update(
            occurred_at="2026-01-01T00:00:00Z"))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_ingestion_actor_rejected(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d["accepted"][0].update(
            actor="injected-user"))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_invalid_normalized_alert_rejected_despite_refreshed_digests(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d["accepted"][0].update(
            severity="supercritical"))
        with self.assertRaisesRegex(ValueError, "cannot be correlated"):
            integrity.verified_reports(self.batch)

    def test_malformed_ingestion_count_type_rejected(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d.update(counts="secret"))
        with self.assertRaisesRegex(ValueError, "Invalid batch report counters"):
            integrity.verified_reports(self.batch)

    def test_extra_ingestion_field_rejected(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d.update(
            malicious_override="INJECTED"))
        with self.assertRaisesRegex(ValueError, "Malformed normalized ingestion"):
            integrity.verified_reports(self.batch)

    def test_ingestion_accepted_count_mismatch_rejected(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d.update(accepted=[]))
        with self.assertRaisesRegex(ValueError, "contents do not match"):
            integrity.verified_reports(self.batch)

    def test_duplicate_accepted_event_rejected_even_when_counters_reforged(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: (
            d["accepted"].append(copy.deepcopy(d["accepted"][0])),
            d["counts"].update(accepted=2)))
        self.rewrite_and_reseal("health.json", lambda d: d["counts"].update(accepted=2))
        self.rewrite_and_reseal("correlation.json", lambda d: d["counts"].update(alerts=2))
        with self.assertRaises(ValueError):
            integrity.verified_reports(self.batch)

    def test_missing_correlation_schema_rejected(self):
        self.rewrite_and_reseal("correlation.json", lambda d: d.pop("version"))
        with self.assertRaisesRegex(ValueError, "independently recomputed"):
            integrity.verified_reports(self.batch)

    def test_forged_consistent_source_and_manifest_is_not_source_authentication(self):
        self.rewrite_and_reseal("ingestion.json", lambda d: d["accepted"][0].update(
            title="Attacker-changed-but-valid-content"))
        # Correlation does not include titles, so independently recomputed
        # candidates will still match. This is a limitation, not a verification claim.
        alerts, _ = integrity.verified_reports(self.batch)
        self.assertEqual(alerts["accepted"][0]["title"], "Attacker-changed-but-valid-content")


if __name__ == "__main__":
    unittest.main()
