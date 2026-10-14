import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ip_obfuscation", ROOT / "scripts" / "detect_ip_obfuscation.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ExternalIpTests(unittest.TestCase):
    def test_classification(self):
        cases = {
            "172.31.5.5": False,   # private (172.16.0.0/12), was missed
            "172.2.3.4": True,     # public, was treated as private
            "172.250.1.1": True,   # public, was treated as private
            "10.0.0.1": False,
            "8.34.117.92": True,
            "2606:4700::1111": True,
            "AWS Internal": False,
            "resource-explorer-2.amazonaws.com": False,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(mod.is_external_ip(value), expected)

    def test_sample(self):
        lines = (ROOT / "sample-logs" / "cloudtrail_timeline.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(mod.detect_ip_obfuscation(lines)), 2)


if __name__ == "__main__":
    unittest.main()
