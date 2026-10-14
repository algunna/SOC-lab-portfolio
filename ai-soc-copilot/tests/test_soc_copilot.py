import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("soc_copilot", ROOT / "scripts" / "soc_copilot.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DetectionTests(unittest.TestCase):
    def test_sample(self):
        sample = (ROOT / "logs" / "sample_bruteforce.log").read_text(encoding="utf-8")
        result = mod.analyze_log(sample)
        self.assertEqual(result["failed_attempts"], 4)
        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["failed_by_ip"], {"192.168.1.45": 4})
        self.assertEqual(result["severity"], "Medium")

    def test_per_source_threshold(self):
        data = "\n".join(f"Failed password for root from 10.0.0.{i} port 5000 ssh2" for i in range(1, 7))
        self.assertEqual(mod.analyze_log(data)["severity"], "Low")

    def test_invalid_ip(self):
        data = "Failed password for root from not-an-ip port 5000 ssh2"
        self.assertEqual(mod.analyze_log(data)["failed_attempts"], 0)

    def test_high_severity(self):
        data = "\n".join("Failed password for root from 192.0.2.2 port 5000 ssh2" for _ in range(5))
        self.assertEqual(mod.analyze_log(data)["severity"], "High")

    def test_username_cannot_spoof_source(self):
        data = "\n".join(f"Failed password for invalid user x from 10.9.9.{i} port 1 ssh2 from 203.0.113.9 port 5123{i} ssh2" for i in range(6))
        result = mod.analyze_log(data)
        self.assertEqual(result["failed_by_ip"], {"203.0.113.9": 6})
        self.assertEqual(result["severity"], "High")

    def test_repeated_message_counts_each_event(self):
        data = (
            "May 08 10:14:21 h sshd[1]: Failed password for root from 203.0.113.9 port 51234 ssh2\n"
            "May 08 10:14:30 h sshd[1]: message repeated 5 times: [ Failed password for root from 203.0.113.9 port 51234 ssh2]\n"
        )
        result = mod.analyze_log(data)
        self.assertEqual(result["failed_by_ip"], {"203.0.113.9": 6})
        self.assertEqual(result["severity"], "High")

    def test_report_omits_raw_account(self):
        data = "Failed password for secretuser from 192.0.2.2 port 5000 ssh2"
        self.assertNotIn("secretuser", mod.build_report(mod.analyze_log(data)))


if __name__ == "__main__":
    unittest.main()
