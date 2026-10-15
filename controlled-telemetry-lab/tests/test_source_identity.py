"""Controlled synthetic source identity, UTC and collision regression tests."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "controlled_source_identity", ROOT / "controlled-telemetry-lab/src/source_identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
vspec = importlib.util.spec_from_file_location(
    "source_contract_verifier", ROOT / "soc-event-contract/src/validate.py")
validator = importlib.util.module_from_spec(vspec)
vspec.loader.exec_module(validator)
FIXTURE = ROOT / "controlled-telemetry-lab/fixtures/synthetic_sources.json"
EXAMPLE = ROOT / "soc-event-contract/examples/windows_alert.json"


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.rows = self.original["records"]

    def encode(self):
        return json.dumps(self.original).encode("utf-8")

    def test_scoped_records_distinct(self):
        result = identity.evaluate(FIXTURE.read_bytes())
        self.assertEqual(len(result["records"]), 6)
        self.assertFalse(result["live_provenance_verified"])
        self.assertEqual(result["scope"], "unauthenticated_synthetic_only")
        ids = [(r["source"]["system"], r["source"]["record_id"]) for r in result["records"]]
        self.assertEqual(len(set(ids)), 6)
        self.assertTrue(all(r["evidence_reference"].startswith("synthetic-source:")
                            and r["provenance"] == "unauthenticated_synthetic_fixture"
                            for r in result["records"]))

    def test_windows_epoch_or_host_changes_namespace(self):
        records = identity.evaluate(self.encode())["records"]
        self.assertEqual({r["source"]["system"] for r in records[:3]}, {"windows"})
        self.assertEqual(len({r["source"]["record_id"] for r in records[:3]}), 3)

    def test_cloudtrail_account_changes_namespace(self):
        records = identity.evaluate(self.encode())["records"]
        self.assertEqual(records[3]["source"]["system"], "aws_cloudtrail")
        self.assertNotEqual(records[3]["source"]["record_id"], records[4]["source"]["record_id"])

    def test_utc_normalization_and_offset_equivalence(self):
        records = identity.evaluate(self.encode())["records"]
        self.assertEqual(records[0]["occurred_at"], "2026-10-14T12:00:00.000000Z")
        self.assertEqual(records[4]["occurred_at"], "2026-10-14T12:00:00.000000Z")
        self.assertEqual(records[5]["occurred_at"], "2026-10-14T12:00:00.000000Z")
        self.rows[0]["occurred_at"] = "2026-10-14T08:00:00-04:00"
        before = identity.evaluate(FIXTURE.read_bytes())["records"][0]
        after = identity.evaluate(self.encode())["records"][0]
        self.assertEqual(before, after)

    def test_clock_review_not_attack_verdict(self):
        result = identity.evaluate(self.encode())
        self.assertEqual(result["clock_counts"],
                         {"within_lab_window": 4, "delayed_arrival": 1, "future_event_time": 1})
        self.assertEqual(result["records"][3]["clock_review"], "delayed_arrival")
        self.assertEqual(result["records"][5]["clock_review"], "future_event_time")

    def test_unknown_namespace_fields_rejected(self):
        for key, value in [("host", ""), ("channel", "../Security"), ("log_epoch", "not-a-uuid"),
                           ("record_id", "1007\n")]:
            with self.subTest(field=key):
                row = copy.deepcopy(self.rows[0])
                row["namespace"][key] = value
                with self.assertRaises(ValueError):
                    identity.project(row)
        row = copy.deepcopy(self.rows[0])
        row["namespace"]["claim_verified"] = True
        with self.assertRaises(ValueError):
            identity.project(row)

    def test_cloudtrail_account_and_event_id_rejected(self):
        for key, value in [("account_id", "123"), ("account_id", 123456789012),
                           ("region", "us_east_1"), ("event_id", "not-a-uuid")]:
            with self.subTest(field=key):
                row = copy.deepcopy(self.rows[3])
                row["namespace"][key] = value
                with self.assertRaises(ValueError):
                    identity.project(row)

    def test_missing_or_extra_outer_fields_rejected(self):
        for key in ("kind", "namespace", "occurred_at", "received_at"):
            with self.subTest(field=key):
                row = copy.deepcopy(self.rows[0])
                del row[key]
                with self.assertRaises(ValueError):
                    identity.project(row)
        row = copy.deepcopy(self.rows[0])
        row["_raw"] = "SYNTHETIC-SECRET"
        with self.assertRaises(ValueError):
            identity.project(row)

    def test_invalid_timestamp_and_missing_timezone_rejected(self):
        for value in ("2026-10-14T12:00:00", "2026-02-30T12:00:00Z",
                      "2026-10-14T12:60:00Z", "2026-10-14 12:00:00Z",
                      "2026-10-14T12:00:00+25:00", "now", True):
            with self.subTest(value=value):
                row = copy.deepcopy(self.rows[0])
                row["occurred_at"] = value
                with self.assertRaises(ValueError):
                    identity.project(row)

    def test_duplicate_record_identity_rejected(self):
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaisesRegex(ValueError, "Duplicate scoped"):
            identity.evaluate(self.encode())

    def test_duplicate_identity_even_if_event_time_changes(self):
        record = copy.deepcopy(self.rows[0])
        record["occurred_at"] = "2026-10-14T12:30:00Z"
        self.rows.append(record)
        with self.assertRaisesRegex(ValueError, "Duplicate scoped"):
            identity.evaluate(self.encode())

    def test_case_insensitive_windows_host(self):
        row = copy.deepcopy(self.rows[0])
        row["namespace"]["host"] = "lab-ws01"
        self.assertEqual(identity.project(row)["source"], identity.project(self.rows[0])["source"])

    def test_controlled_projection_can_be_copied_to_existing_contract(self):
        project = identity.project(self.rows[0])
        alert = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        alert["source"] = project["source"]
        alert["occurred_at"] = project["occurred_at"]
        alert["evidence"][0]["reference"] = project["evidence_reference"]
        self.assertEqual(validator.validate(alert), [])
        self.assertNotIn("log_epoch", json.dumps(alert))
        # This checks compatibility only. It does NOT make the sample alert a
        # real observed detection or attach independently verified provenance.

    def test_duplicate_keys_and_oversized_input_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            identity.evaluate(b'{"schema_version":"1.0","schema_version":"1.0"}')
        with self.assertRaises(ValueError):
            identity.evaluate(b"x" * (identity.MAX_BYTES + 1))

    def test_invalid_fixture_scope_rejected(self):
        self.original["scope"] = "authenticated"
        with self.assertRaises(ValueError):
            identity.evaluate(self.encode())

    def test_cli_summary_opaque_and_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "summary.json"
            cmd = [sys.executable, str(ROOT / "controlled-telemetry-lab/src/source_identity.py"),
                   "--out", str(dest)]
            first = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=20)
            self.assertEqual(first.returncode, 0, first.stderr)
            raw = dest.read_text()
            report = json.loads(raw)
            self.assertEqual(len(report["records"]), 6)
            for restricted in ["LAB-WS01", "123456789012", "33333333-3333", "log_epoch",
                               "event_id", "account_id", "_raw"]:
                self.assertNotIn(restricted, raw)
            second = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(dest.read_text(), raw)


if __name__ == "__main__":
    unittest.main()
