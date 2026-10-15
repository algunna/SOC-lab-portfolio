"""Pipeline 16 synthetic source-to-alert fail-closed handoff regression tests."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


handoff = load("synthetic_source_handoff_tests", "controlled-telemetry-lab/src/to_soc_alerts.py")
FIXTURE = ROOT / "controlled-telemetry-lab/fixtures/synthetic_sources.json"


class ControlledHandoffTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def raw(self):
        return json.dumps(self.data).encode("utf-8")

    def test_handoff_produces_six_contract_valid_observations(self):
        alerts = handoff.build(FIXTURE.read_bytes())
        self.assertEqual(len(alerts), 6)
        self.assertTrue(all(handoff.contract.validate(a) == [] for a in alerts))
        self.assertEqual([a["severity"] for a in alerts], ["informational"] * 6)
        self.assertEqual({a["rule_id"] for a in alerts}, {handoff.RULE})
        self.assertEqual({a["source"]["system"] for a in alerts}, {"windows", "aws_cloudtrail"})

    def test_never_asserts_attack_identity_or_provenance(self):
        alerts = handoff.build(FIXTURE.read_bytes())
        for alert in alerts:
            self.assertNotIn("actor", alert)
            self.assertNotIn("asset", alert)
            self.assertNotIn("attack_techniques", alert)
            self.assertNotIn("provenance", alert)
            self.assertNotIn("authenticated", alert)
            self.assertIn("no detection", alert["title"])
            self.assertIn("unauthenticated", alert["evidence"][0]["description"])
            self.assertTrue(alert["evidence"][0]["reference"].startswith("synthetic-source:"))

    def test_repeated_run_is_deterministic(self):
        self.assertEqual(handoff.build(FIXTURE.read_bytes()), handoff.build(FIXTURE.read_bytes()))

    def test_windows_record_reuse_and_cloudtrail_account_scoped(self):
        alerts = handoff.build(FIXTURE.read_bytes())
        self.assertEqual(len({x["event_id"] for x in alerts}), 6)
        self.assertEqual(len({x["source"]["record_id"] for x in alerts}), 6)
        self.assertEqual(len({x["source"]["record_id"] for x in alerts[:3]}), 3)
        self.assertNotEqual(alerts[3]["source"]["record_id"], alerts[4]["source"]["record_id"])

    def test_equivalent_timezone_offsets_produce_same_alert(self):
        before = handoff.build(self.raw())
        self.data["records"][0]["occurred_at"] = "2026-10-14T08:00:00-04:00"
        after = handoff.build(self.raw())
        self.assertEqual(before, after)

    def test_changed_timestamp_same_source_keeps_id_but_changes_content(self):
        before = handoff.build(self.raw())
        self.data["records"][0]["occurred_at"] = "2026-10-14T12:08:00Z"
        after = handoff.build(self.raw())
        self.assertEqual(before[0]["event_id"], after[0]["event_id"])
        self.assertNotEqual(before[0]["occurred_at"], after[0]["occurred_at"])

    def test_duplicate_source_record_blocks_all(self):
        self.data["records"].append(copy.deepcopy(self.data["records"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate scoped"):
            handoff.build(self.raw())

    def test_missing_host_blocks_all(self):
        del self.data["records"][0]["namespace"]["host"]
        with self.assertRaises(ValueError):
            handoff.build(self.raw())

    def test_missing_log_epoch_blocks_all(self):
        del self.data["records"][0]["namespace"]["log_epoch"]
        with self.assertRaises(ValueError):
            handoff.build(self.raw())

    def test_extra_claims_block_all(self):
        for key in ("verified", "severity", "rule_id", "_raw"):
            with self.subTest(extra_field=key):
                modified = copy.deepcopy(self.data)
                modified["records"][0][key] = "forged"
                with self.assertRaises(ValueError):
                    handoff.build(json.dumps(modified).encode())

    def test_invalid_aws_identity_blocks_all(self):
        self.data["records"][3]["namespace"]["account_id"] = "invalid"
        with self.assertRaises(ValueError):
            handoff.build(self.raw())

    def test_malformed_timestamps_block_all(self):
        for value in ("2026-10-14T12:00:00", "2026-02-30T12:00:00Z", "tomorrow"):
            with self.subTest(value=value):
                modified = copy.deepcopy(self.data)
                modified["records"][0]["occurred_at"] = value
                with self.assertRaises(ValueError):
                    handoff.build(json.dumps(modified).encode())

    def test_mismatched_reference_cannot_be_attached(self):
        projection = handoff.source_identity.project(self.data["records"][0])
        projection["evidence_reference"] = "synthetic-source:" + "0" * 48
        with self.assertRaisesRegex(ValueError, "mismatch"):
            handoff.observation_alert(projection)

    def test_unknown_provenance_or_clock_claim_refused(self):
        projection = handoff.source_identity.project(self.data["records"][0])
        for key, value in (("provenance", "verified_splunk"), ("clock_review", "attack_confirmed")):
            with self.subTest(key=key):
                record = dict(projection)
                record[key] = value
                with self.assertRaises(ValueError):
                    handoff.observation_alert(record)

    def test_malformed_projected_record_rejected(self):
        projection = handoff.source_identity.project(self.data["records"][0])
        projection["source"]["record_id"] = "lab-src-bad"
        with self.assertRaises(ValueError):
            handoff.observation_alert(projection)

    def test_duplicate_json_keys_fail_before_alert_output(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            handoff.build(b'{"schema_version":"1.0","schema_version":"1.0"}')

    def test_cli_new_output_only_and_no_raw_source_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "observations.jsonl"
            command = [sys.executable, str(ROOT / "controlled-telemetry-lab/src/to_soc_alerts.py"),
                       "--out", str(output)]
            first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            raw = output.read_text()
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual(len(rows), 6)
            self.assertTrue(all(handoff.contract.validate(a) == [] for a in rows))
            for forbidden in ("LAB-WS01", "123456789012", "log_epoch", "received_at", "_raw"):
                self.assertNotIn(forbidden, raw)
            again = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(output.read_text(), raw)


if __name__ == "__main__":
    unittest.main()
