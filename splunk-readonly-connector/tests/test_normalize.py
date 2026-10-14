"""Offline Splunk alert normalization: contract, provenance, privacy and failure paths."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("splunk_normalize_test", ROOT / "src" / "normalize.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
F = ROOT / "fixtures" / "synthetic_saved_search_alerts.jsonl"


def encoded(rows):
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode("utf-8")


class SyntheticAlertsTests(unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(line) for line in F.read_text(encoding="utf-8").splitlines()]

    def test_synthetic_fixture_maps_three_rules(self):
        alerts = m.transform_jsonl(F.read_bytes())
        self.assertEqual(len(alerts), 3)
        self.assertEqual([x["source"]["system"] for x in alerts],
                         ["windows", "authentication", "aws_cloudtrail"])
        self.assertEqual([x["severity"] for x in alerts], ["medium", "high", "high"])
        for alert in alerts:
            self.assertEqual(m.contract.validate(alert), [])

    def test_same_input_stable_id(self):
        self.assertEqual(m.transform_jsonl(F.read_bytes()), m.transform_jsonl(F.read_bytes()))

    def test_unique_ids_and_evidence(self):
        alerts = m.transform_jsonl(F.read_bytes())
        self.assertEqual(len({a["event_id"] for a in alerts}), 3)
        self.assertTrue(all(a["evidence"][0]["reference"].startswith("splunk-synthetic:") for a in alerts))
        self.assertTrue(all(a["evidence"][0]["description"].startswith("Synthetic ") for a in alerts))

    def test_unknown_search_rejected(self):
        self.rows[0]["search_name"] = "unreviewed_detector"
        with self.assertRaisesRegex(ValueError, "Unknown search"):
            m.transform_jsonl(encoded(self.rows))

    def test_source_row_cannot_choose_severity_or_rule(self):
        self.rows[0]["severity"] = "critical"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))
        del self.rows[0]["severity"]
        self.rows[0]["rule_id"] = "admin_override"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))

    def test_raw_data_rejected_not_leaked(self):
        self.rows[0]["_raw"] = "API-KEY-SECRET"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))
        del self.rows[0]["_raw"]
        self.rows[0]["password"] = "not-allowed"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))

    def test_identity_control_characters_rejected(self):
        self.rows[0]["actor"] = "x\nINJECT"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))

    def test_invalid_date_rejected(self):
        self.rows[0]["occurred_at"] = "today"
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded(self.rows))

    def test_record_id_validation(self):
        for value in ("", "../secret", "x" * 129, 1):
            with self.subTest(value=value):
                self.rows[0]["record_id"] = value
                with self.assertRaises(ValueError):
                    m.transform_jsonl(encoded(self.rows))

    def test_duplicate_rows_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "Duplicate saved-search"):
            m.transform_jsonl(encoded(self.rows + self.rows[:1]))

    def test_duplicate_json_object_keys_fail(self):
        line = '{"search_name":"windows_encoded_powershell","search_name":"auth_failed_login_burst","record_id":"x","occurred_at":"2026-10-14T12:00:00Z"}\n'
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            m.transform_jsonl(line.encode())

    def test_malformed_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid JSONL"):
            m.transform_jsonl(b"{bad json\n")

    def test_oversize_and_empty_fail(self):
        with self.assertRaises(ValueError):
            m.transform_jsonl(b"X" * (m.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            m.transform_jsonl(b" \n")
        with self.assertRaises(ValueError):
            m.transform_jsonl(encoded([self.rows[0]] * (m.MAX_ROWS + 1)))

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            m.transform_jsonl(b"\xff")

    def test_whitelisted_actor_and_asset(self):
        alerts = m.transform_jsonl(F.read_bytes())
        self.assertEqual(alerts[0]["actor"], "LAB\\analyst")
        self.assertEqual(alerts[2]["asset"], "123456789012")
        self.assertTrue(all("_raw" not in x for x in alerts))

    def test_alerts_are_not_confirmed_incidents(self):
        alerts = m.transform_jsonl(F.read_bytes())
        self.assertTrue(all("incident_id" not in x and "confirmed" not in json.dumps(x) for x in alerts))


if __name__ == "__main__":
    unittest.main()
