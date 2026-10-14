import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "threat_intel_enrichment.py"
spec = importlib.util.spec_from_file_location("ioc_classification", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class IOCClassificationTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(module.classify_ioc("8.8.8.8")["type"], "IP address")

    def test_ipv6(self):
        self.assertEqual(module.classify_ioc("2001:db8::1")["type"], "IP address")

    def test_domain(self):
        self.assertEqual(module.classify_ioc("example.org")["type"], "Domain")

    def test_sha256(self):
        self.assertEqual(module.classify_ioc("a" * 64)["type"], "File hash")

    def test_unrecognized(self):
        self.assertEqual(module.classify_ioc("not a valid IOC")["type"], "Unrecognized")

    def test_no_assumed_reputation(self):
        for value in ("8.8.8.8", "bad.example", "a" * 64):
            result = module.classify_ioc(value)
            self.assertEqual(result["reputation"], "Not assessed")
            self.assertEqual(result["risk"], "Unknown")


if __name__ == "__main__":
    unittest.main()
