"""Offline health observability: strict schema, privacy, bounds and HTTP controls."""
import copy
import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_observability_test", ROOT / "src" / "health_dashboard.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
server_spec = importlib.util.spec_from_file_location("soc_dashboard_test_server", ROOT / "src" / "dashboard.py")
dashboard = importlib.util.module_from_spec(server_spec)
server_spec.loader.exec_module(dashboard)

GOOD = {"version": "0.1", "mode": "offline_training", "status": "passed", "stage": "complete",
        "counts": {"accepted": 3, "rejected": 0, "duplicates": 2, "candidates": 2}}
BAD = {"version": "0.1", "mode": "offline_training", "status": "blocked", "stage": "ingestion",
       "counts": {"accepted": 1, "rejected": 1, "duplicates": 0, "candidates": 0}}


class HealthDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, folder, data=GOOD):
        target = self.root / folder
        target.mkdir()
        (target / "health.json").write_text(json.dumps(data), encoding="utf-8")
        return target

    def test_aggregate_verified_counters(self):
        reports = mod.load_reports([self.write("run1"), self.write("run2", BAD)])
        result = mod.summarize(reports)
        self.assertEqual((result["runs"], result["passed"], result["blocked"]), (2, 1, 1))
        self.assertEqual(result["counts"], {"accepted": 4, "rejected": 1, "duplicates": 2, "candidates": 2})
        page = mod.render(reports)
        for text in ("Offline Batch Health", "Batch History (supplied order)", "Static snapshot", "Run", "Blocked"):
            self.assertIn(text, page)
        self.assertNotIn("<script", page)
        self.assertNotIn("<form", page)

    def test_only_health_file_read_and_no_raw_text_disclosure(self):
        one = self.write("private-path-SECRET")
        (one / "quarantine.json").write_text('{"raw":"PATIENT-SECRET"}')
        (one / "ingestion.json").write_text('{"actor":"LAB-SECRET"}')
        (one / "history.txt").write_text("EVIDENCE-SECRET")
        page = mod.render(mod.load_reports([one]))
        for private in ("private-path-SECRET", "PATIENT-SECRET", "LAB-SECRET", "EVIDENCE-SECRET", str(self.root)):
            self.assertNotIn(private, page)

    def test_malformed_json_and_duplicate_keys_refused(self):
        one = self.write("bad")
        (one / "health.json").write_text('{"version":"0.1","version":"0.1"}')
        with self.assertRaises(ValueError):
            mod.load_reports([one])
        (one / "health.json").write_text("{not-json")
        with self.assertRaises(ValueError):
            mod.load_reports([one])

    def test_unknown_fields_rejected(self):
        bad = copy.deepcopy(GOOD)
        bad["private_path"] = "SECRET-NAME"
        with self.assertRaises(ValueError):
            mod.validate_health(bad)
        bad = copy.deepcopy(GOOD)
        bad["counts"]["raw"] = "SECRET-DATA"
        with self.assertRaises(ValueError):
            mod.validate_health(bad)

    def test_wrong_status_stage_and_counts_rejected(self):
        for status, stage in (("passed", "ingestion"), ("blocked", "complete"), ("unknown", "preflight")):
            value = copy.deepcopy(GOOD)
            value["status"], value["stage"] = status, stage
            with self.subTest(status=status, stage=stage), self.assertRaises(ValueError):
                mod.validate_health(value)
        other = copy.deepcopy(GOOD)
        other["counts"]["rejected"] = 1
        with self.assertRaises(ValueError):
            mod.validate_health(other)
        other = copy.deepcopy(BAD)
        other["counts"]["candidates"] = 1
        with self.assertRaises(ValueError):
            mod.validate_health(other)

    def test_invalid_numeric_types_refused(self):
        for bad_value in (True, 1.2, "5", None, -1, mod.MAX_COUNTER + 1):
            other = copy.deepcopy(GOOD)
            other["counts"]["accepted"] = bad_value
            with self.subTest(value=bad_value), self.assertRaises(ValueError):
                mod.validate_health(other)

    def test_not_enough_alerts_for_candidates_refused(self):
        other = copy.deepcopy(GOOD)
        other["counts"]["accepted"] = 1
        with self.assertRaises(ValueError):
            mod.validate_health(other)

    def test_non_finite_json_rejected(self):
        one = self.write("nan")
        (one / "health.json").write_text(json.dumps(GOOD).replace('"accepted": 3', '"accepted": NaN'))
        with self.assertRaises(ValueError):
            mod.load_reports([one])

    def test_too_large_and_missing_health_rejected(self):
        one = self.write("oversize")
        (one / "health.json").write_bytes(b"x" * (mod.MAX_HEALTH_BYTES + 1))
        with self.assertRaises(ValueError):
            mod.load_reports([one])
        (one / "health.json").unlink()
        with self.assertRaises(ValueError):
            mod.load_reports([one])

    def test_health_symlinks_and_directory_symlinks_rejected(self):
        one = self.write("actual")
        second = self.root / "aliased"
        second.symlink_to(one, target_is_directory=True)
        with self.assertRaises(ValueError):
            mod.load_reports([second])
        other = self.root / "badlink"
        other.mkdir()
        (other / "health.json").symlink_to(one / "health.json")
        with self.assertRaises(ValueError):
            mod.load_reports([other])

    def test_repeated_directory_and_limit_rejected(self):
        one = self.write("run")
        with self.assertRaises(ValueError):
            mod.load_reports([one, one])
        with self.assertRaises(ValueError):
            mod.load_reports([])
        with self.assertRaises(ValueError):
            mod.load_reports([one] * (mod.MAX_RUNS + 1))

    def test_no_false_recovery_claim(self):
        page = mod.render(mod.load_reports([self.write("failed", BAD), self.write("passed", GOOD)]))
        self.assertIn("does not establish recovery", page)
        self.assertNotIn("Successfully recovered", page)

    def test_existing_dashboard_loopback_security_headers(self):
        page = mod.render(mod.load_reports([self.write("run")])).encode("utf-8")
        with dashboard.make_server(page, port=0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                client.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
                response = client.getresponse()
                text = response.read()
                self.assertEqual(response.status, 200)
                self.assertIn(b"Offline Batch Health", text)
                self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
                client.close()
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                client.request("GET", "/", headers={"Host": f"malicious.invalid:{port}"})
                response = client.getresponse()
                response.read()
                self.assertEqual(response.status, 421)
                client.close()
            finally:
                server.shutdown()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
