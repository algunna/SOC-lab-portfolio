"""Offline Splunk readiness matrix safeguards and deterministic acceptance."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_splunk_readiness", ROOT / "src/readiness_matrix.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
FIXTURE = ROOT / "fixtures/live_readiness_scenarios.json"


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def data(self):
        return json.dumps(self.fixture).encode()

    def test_full_offline_matrix(self):
        results = m.rehearse(FIXTURE.read_bytes())
        self.assertEqual(results["mode"], "synthetic_offline_only")
        self.assertIs(results["live_splunk_verified"], False)
        self.assertEqual(results["passed_scenarios"], 12)
        self.assertEqual(sum(r["result"] == "passed" for r in results["results"]), 4)
        self.assertEqual(sum(r["result"] == "expected_rejection" for r in results["results"]), 8)
        for result in results["results"]:
            self.assertIn(result["id"], {r["id"] for r in self.fixture["scenarios"]})

    def test_run_is_deterministic(self):
        self.assertEqual(m.rehearse(FIXTURE.read_bytes()), m.rehearse(FIXTURE.read_bytes()))

    def test_positive_counts_are_stable(self):
        got = {r["id"]: r for r in m.rehearse(FIXTURE.read_bytes())["results"]}
        self.assertEqual((got["baseline-three-allowlisted-detections"]["alerts"],
                          got["baseline-three-allowlisted-detections"]["candidates"]), (3, 3))
        self.assertEqual(got["same-host-two-windows-alerts-group"]["candidates"], 1)
        self.assertEqual(got["events-beyond-fixed-window-separate"]["candidates"], 2)
        self.assertEqual(got["absent-actor-never-grouped"]["candidates"], 2)

    def test_rejection_does_not_leak_raw_secret(self):
        report = json.dumps(m.rehearse(FIXTURE.read_bytes()))
        for leaked in ("SYNTHETIC_UNTRUSTED", "SYNTHETIC_DONT_EXPORT",
                       "LAB-WS01", "123456789012", '"_raw":', '"password":',
                       '"actor":', '"asset":'):
            self.assertNotIn(leaked, report)

    def test_wrong_expected_positive_count_fails_rehearsal(self):
        scenario = copy.deepcopy(self.fixture["scenarios"][0])
        scenario["candidates"] += 1
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(AssertionError):
                m.run_scenario(scenario, Path(folder))

    def test_wrong_expected_rejection_fails_rehearsal(self):
        scenario = copy.deepcopy(self.fixture["scenarios"][0])
        scenario.pop("alerts")
        scenario.pop("candidates")
        scenario["expect"] = "reject"
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(AssertionError):
                m.run_scenario(scenario, Path(folder))

    def test_duplicate_fixture_ids_rejected(self):
        self.fixture["scenarios"][1]["id"] = self.fixture["scenarios"][0]["id"]
        with self.assertRaises(ValueError):
            m.parse_matrix(self.data())

    def test_invalid_fixture_mode_rejected(self):
        self.fixture["dataset"] = "live_splunk"
        with self.assertRaises(ValueError):
            m.parse_matrix(self.data())

    def test_malformed_fixture_and_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            m.parse_matrix(b"{bad")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            m.parse_matrix(b'{"version":"0.1","version":"0.1"}')

    def test_more_than_allowed_scenarios_rejected(self):
        self.fixture["scenarios"] *= 4
        with self.assertRaises(ValueError):
            m.parse_matrix(self.data())

    def test_missing_or_wrong_positive_expectations_rejected(self):
        for wrong in (True, "3", -1, 0):
            case = copy.deepcopy(self.fixture)
            case["scenarios"][0]["alerts"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                m.parse_matrix(json.dumps(case).encode())

    def test_rejected_case_cannot_supply_positive_counts(self):
        self.fixture["scenarios"][-1]["alerts"] = 1
        with self.assertRaises(ValueError):
            m.parse_matrix(self.data())

    def test_no_network_calls_from_fixed_rehearsal(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("Network call forbidden")):
            self.assertEqual(m.rehearse(FIXTURE.read_bytes())["passed_scenarios"], 12)

    def test_cli_summary_only_and_exclusive_file(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "summary.json"
            command = [sys.executable, str(ROOT / "src/readiness_matrix.py"), "--out", str(output)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["passed_scenarios"], 12)
            self.assertIs(data["live_splunk_verified"], False)
            self.assertNotIn("SYNTHETIC_DONT_EXPORT", output.read_text())
            later = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(later.returncode, 0)
            self.assertEqual(json.loads(output.read_text()), data)


if __name__ == "__main__":
    unittest.main()
