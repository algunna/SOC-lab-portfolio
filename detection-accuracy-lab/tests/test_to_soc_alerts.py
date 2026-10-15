"""Offline detection-to-alert bridge: stable IDs, provenance honesty and fail-closed tests."""
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
spec = importlib.util.spec_from_file_location("synthetic_detector_bridge", ROOT / "detection-accuracy-lab/src/to_soc_alerts.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
FIXTURE = ROOT / "detection-accuracy-lab/fixtures/labeled_scenarios.json"


class SyntheticBridgeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def bytes(self):
        return json.dumps(self.fixture, ensure_ascii=True).encode("utf-8")

    def test_fixture_generates_contract_valid_alerts(self):
        alerts = m.bridge(FIXTURE.read_bytes())
        self.assertEqual(len(alerts), 15)
        self.assertTrue(all(m.contract.validate(a) == [] for a in alerts))
        self.assertEqual({a["source"]["system"] for a in alerts}, {"windows", "aws_cloudtrail"})
        self.assertEqual(len({a["event_id"] for a in alerts}), len(alerts))
        self.assertEqual(len({(a["source"]["system"], a["source"]["record_id"], a["rule_id"]) for a in alerts}), len(alerts))

    def test_every_evidence_reference_is_synthetic(self):
        alerts = m.bridge(FIXTURE.read_bytes())
        self.assertTrue(all(a["evidence"][0]["reference"].startswith("synthetic-fixture:") for a in alerts))
        self.assertTrue(all("Synthetic offline" in a["evidence"][0]["description"] for a in alerts))
        self.assertTrue(all(a["event_id"].startswith("lab-") for a in alerts))

    def test_all_eight_detection_rules_preserve_local_metadata(self):
        alerts = m.bridge(FIXTURE.read_bytes())
        self.assertEqual({a["rule_id"] for a in alerts}, {entry[1] for entry in m.MAPPINGS.values()})
        self.assertEqual({a["severity"] for a in alerts}, {"low", "medium", "high"})
        self.assertTrue(all("critical" != a["severity"] for a in alerts))

    def test_repeated_runs_deterministic(self):
        self.assertEqual(m.bridge(FIXTURE.read_bytes()), m.bridge(FIXTURE.read_bytes()))

    def test_lab_ids_are_not_raw_original_event_ids(self):
        alerts = m.bridge(FIXTURE.read_bytes())
        data = json.dumps(alerts)
        self.assertNotIn("LAB-WS01\\Windows\\Security", data)
        self.assertNotIn("SYNTHETIC_DONT_EXPORT", data)
        self.assertNotIn("command_line", data)
        self.assertNotIn("sourceIPAddress", data)
        self.assertNotIn("eventTime", data)

    def test_benign_fixture_unexpected_detector_output_blocks_entire_batch(self):
        target = next(x for x in self.fixture["scenarios"] if x["id"] == "win-benign-powershell")
        target["events"][0]["command_line"] = "powershell.exe -EncodedCommand QUJD"
        with self.assertRaisesRegex(ValueError, "contradicts"):
            m.bridge(self.bytes())

    def test_expected_detection_missing_blocks_batch(self):
        target = next(x for x in self.fixture["scenarios"] if x["id"] == "win-encoded-command")
        target["events"][0]["command_line"] = "powershell.exe -NoProfile"
        with self.assertRaisesRegex(ValueError, "contradicts"):
            m.bridge(self.bytes())

    def test_unknown_rule_output_refused(self):
        with patch.object(m.matrix.DETECTORS["windows"], "hunt",
                          return_value=[{"rule": "not_reviewed", "severity": "high"}]):
            with self.assertRaises(ValueError):
                m.bridge(FIXTURE.read_bytes())

    def test_source_severity_override_refused(self):
        one = m.matrix.DETECTORS["windows"].hunt(self.fixture["scenarios"][0]["events"])[0]
        one["severity"] = "critical"
        with self.assertRaisesRegex(ValueError, "metadata disagrees"):
            m.alert_for(one, "windows", "win-encoded-command", 0)

    def test_source_mitre_override_refused(self):
        one = m.matrix.DETECTORS["windows"].hunt(self.fixture["scenarios"][0]["events"])[0]
        one["attack"] = "T9999"
        with self.assertRaisesRegex(ValueError, "metadata disagrees"):
            m.alert_for(one, "windows", "win-encoded-command", 0)

    def test_missing_actor_or_asset_refused(self):
        original = m.matrix.DETECTORS["windows"].hunt(self.fixture["scenarios"][0]["events"])[0]
        for key in ("user", "host"):
            with self.subTest(field=key):
                finding = copy.deepcopy(original)
                finding[key] = ""
                with self.assertRaisesRegex(ValueError, "actor or asset"):
                    m.alert_for(finding, "windows", "win-encoded-command", 0)

    def test_bad_detector_timestamp_refused_by_contract(self):
        original = m.matrix.DETECTORS["windows"].hunt(self.fixture["scenarios"][0]["events"])[0]
        original["timestamp"] = "2026-10-14 12:00"
        with self.assertRaisesRegex(ValueError, "SOC Event Contract"):
            m.alert_for(original, "windows", "win-encoded-command", 0)

    def test_duplicate_fixture_id_refused(self):
        self.fixture["scenarios"][1]["id"] = self.fixture["scenarios"][0]["id"]
        with self.assertRaises(ValueError):
            m.bridge(self.bytes())

    def test_bad_fixture_mode_refused(self):
        self.fixture["scope"] = "production"
        with self.assertRaises(ValueError):
            m.bridge(self.bytes())

    def test_empty_or_oversized_fixture_refused(self):
        with self.assertRaises(ValueError):
            m.bridge(b"")
        with self.assertRaises(ValueError):
            m.bridge(b"X" * (m.MAX_BYTES + 1))

    def test_cli_creates_only_new_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "alerts.jsonl"
            command = [sys.executable, str(ROOT / "detection-accuracy-lab/src/to_soc_alerts.py"),
                       "--out", str(dest)]
            first = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=20)
            self.assertEqual(first.returncode, 0, first.stderr)
            alerts = [json.loads(x) for x in dest.read_text().splitlines()]
            self.assertEqual(len(alerts), 15)
            later = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(later.returncode, 0)
            self.assertEqual(len(dest.read_text().splitlines()), 15)


if __name__ == "__main__":
    unittest.main()
