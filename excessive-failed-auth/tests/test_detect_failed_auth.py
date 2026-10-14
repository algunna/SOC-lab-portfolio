import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("failed_auth", ROOT / "scripts" / "detect_failed_auth.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def line(result, ip="203.0.113.5", second=0, user="admin"):
    return f"Time: 2026-01-21T20:01:{second:02d}Z | Event: ConsoleLogin | Result: {result} | User: {user} | SourceIP: {ip}"


class FailedAuthTests(unittest.TestCase):
    def test_sample(self):
        alerts = mod.detect_failed_auth((ROOT / "sample-logs" / "auth_timeline.txt").read_text(encoding="utf-8").splitlines())
        self.assertEqual([a.split("]")[0] + "]" for a in alerts], ["[HIGH]", "[CRITICAL]", "[HIGH]"])

    def test_below_threshold(self):
        self.assertEqual(mod.detect_failed_auth([line("Failure", second=i) for i in range(4)] + [line("Success", second=9)]), [])

    def test_success_after_failures(self):
        alerts = mod.detect_failed_auth([line("Failure", second=i) for i in range(5)] + [line("Success", second=9)])
        self.assertTrue(alerts[1].startswith("[CRITICAL] Successful login after 5 failures"))
        self.assertIn("First: 2026-01-21T20:01:00Z | Last: 2026-01-21T20:01:04Z", alerts[0])

    def test_sources_counted_separately(self):
        rows = [line("Failure", ip=f"203.0.113.{i}") for i in range(5)]
        self.assertEqual(mod.detect_failed_auth(rows), [])

    def test_malformed_lines_skipped(self):
        self.assertEqual(mod.detect_failed_auth(["Time: x | Result: Failure", "", "garbage"]), [])


if __name__ == "__main__":
    unittest.main()
