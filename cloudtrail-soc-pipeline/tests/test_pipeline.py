import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parse = load("parse_cloudtrail")
detect = load("detect_cloudtrail_risks")
correlate = load("correlate_cloudtrail_incidents")


def run_fixture():
    timeline = parse.extract_events(ROOT / "fixtures")
    alerts = detect.detect_cloudtrail_risks(timeline)
    return timeline, alerts, correlate.correlate_incidents(alerts)


class SourceIpTests(unittest.TestCase):
    def test_classification(self):
        cases = {
            "AWS Internal": "aws_internal",
            "resource-explorer-2.amazonaws.com": "aws_service",
            "10.20.30.40": "internal_ip",
            "192.168.1.5": "internal_ip",
            "fd00::1": "internal_ip",
            "::ffff:10.1.2.3": "internal_ip",
            "::ffff:203.0.113.9": "public_ip",
            "203.0.113.50": "public_ip",
            "2001:db8::50": "public_ip",
            "not-an-ip": "unknown",
            "": "unknown",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(detect.classify_source_ip(source), expected)


class FixtureTests(unittest.TestCase):
    def test_timeline_is_chronological(self):
        timeline, _, _ = run_fixture()
        self.assertEqual(len(timeline), 10)
        times = [detect.parse_timeline_line(line)["Time"] for line in timeline]
        self.assertEqual(times, sorted(times))

    def test_alerts(self):
        _, alerts, _ = run_fixture()
        summary = [(a.split("]")[0][1:], detect.parse_timeline_line(a.split(" | ", 2)[2])["Event"]) for a in alerts]
        self.assertEqual(summary, [
            ("HIGH", "ListBuckets"),
            ("HIGH", "ConsoleLogin"),
            ("CRITICAL", "ConsoleLogin"),
            ("CRITICAL", "ConsoleLogin"),
            ("HIGH", "CreateAccessKey"),
            ("HIGH", "AttachUserPolicy"),
            ("HIGH", "StopLogging"),
            ("MEDIUM", "CreateServiceLinkedRole"),
            ("MEDIUM", "AssumeRole"),
        ])

    def test_benign_event_not_alerted(self):
        _, alerts, _ = run_fixture()
        self.assertFalse(any("DescribeInstances" in alert for alert in alerts))

    def test_root_alerts_form_one_incident(self):
        _, _, incidents = run_fixture()
        self.assertEqual(list(incidents), ["ROOT_ACTIVITY", "IAM_CHANGE", "LOGGING_TAMPER", "ASSUME_ROLE"])
        root = incidents["ROOT_ACTIVITY"]
        self.assertEqual(len(root["alerts"]), 4)
        self.assertEqual(root["severity"], "CRITICAL")
        self.assertEqual(incidents["IAM_CHANGE"]["severity"], "HIGH")

    def test_every_alert_has_guidance(self):
        _, alerts, _ = run_fixture()
        self.assertTrue(all("| AnalystAction: " in alert for alert in alerts))

    def test_incident_time_window(self):
        _, _, incidents = run_fixture()
        report = correlate.format_incidents(incidents)
        self.assertIn("Time Window: 2026-01-05T09:00:00+00:00 -> 2026-01-05T09:06:00+00:00", report)

    def test_additional_event_names(self):
        for name, category in (("StopEventDataStoreIngestion", "LOGGING_TAMPER"), ("DeleteRolePermissionsBoundary", "IAM_CHANGE"),
                               ("DeactivateMFADevice", "IAM_CHANGE"), ("AssumeRoot", "ASSUME_ROLE")):
            with self.subTest(name=name):
                line = f"Time: 2026-01-05T09:00:00Z | Event: {name} | UserType: IAMUser | SourceIP: 198.51.100.7 | Region: us-east-1"
                alerts = detect.detect_cloudtrail_risks([line])
                self.assertEqual([correlate.parse_alert(a)[1] for a in alerts], [category])


class TimezoneTests(unittest.TestCase):
    def test_mixed_offsets_sort_and_correlate(self):
        records = [
            {"eventTime": "2026-01-05T10:05:00+02:00", "eventName": "DeleteTrail", "userIdentity": {"type": "IAMUser"}},
            {"eventTime": "2026-01-05T09:00:00Z", "eventName": "StopLogging", "userIdentity": {"type": "IAMUser"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "mixed.json").write_text(json.dumps({"Records": records}), encoding="utf-8")
            timeline = parse.extract_events(Path(tmp))
        self.assertEqual([detect.parse_timeline_line(line)["Event"] for line in timeline], ["DeleteTrail", "StopLogging"])
        incidents = correlate.correlate_incidents(detect.detect_cloudtrail_risks(timeline))
        self.assertIn("Time Window: 2026-01-05T08:05:00+00:00 -> 2026-01-05T09:00:00+00:00", correlate.format_incidents(incidents))


class MalformedInputTests(unittest.TestCase):
    def test_bad_files_and_records_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "a_invalid.json").write_text("{not json", encoding="utf-8")
            (tmp / "b_no_records.json").write_text('{"foo": 1}', encoding="utf-8")
            (tmp / "c_list.json").write_text("[1, 2]", encoding="utf-8")
            (tmp / "d_partial.json").write_text(
                json.dumps({"Records": ["junk", {"eventName": "StopLogging", "userIdentity": "junk"}]}),
                encoding="utf-8",
            )
            timeline = parse.extract_events(tmp)
        self.assertEqual(len(timeline), 1)
        self.assertIn("Event: StopLogging | UserType: Unknown", timeline[0])

    def test_field_values_cannot_inject_fields(self):
        record = {
            "eventTime": "2026-01-05T09:00:00Z",
            "eventName": "ListBuckets | UserType: Root",
            "userIdentity": {"type": "IAMUser"},
            "sourceIPAddress": "203.0.113.9\nTime: x",
        }
        line = parse.format_event(record)
        self.assertNotIn("\n", line)
        self.assertEqual(detect.parse_timeline_line(line)["UserType"], "IAMUser")
        self.assertEqual(detect.detect_cloudtrail_risks([line]), [])

    def test_correlation_ignores_non_alert_lines(self):
        self.assertEqual(correlate.correlate_incidents(["", "garbage", "[HIGH"]), {})


if __name__ == "__main__":
    unittest.main()
