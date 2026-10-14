import importlib.util
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_docs", ROOT / "scripts" / "verify_docs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DocsTests(unittest.TestCase):
    def test_relative_links(self):
        count, broken = module.check()
        self.assertGreater(count, 5)
        self.assertEqual(broken, [])

if __name__ == "__main__":
    unittest.main()
