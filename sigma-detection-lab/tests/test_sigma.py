import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("validate_sigma",ROOT/"scripts"/"validate_rules.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class SigmaTests(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(module.validate(),15)
    def test_unknown_operator_rejected(self):
        with self.assertRaises(ValueError):
            module.selector_matches({"Image|startswith":"cmd"}, {"Image":"cmd.exe"})
    def test_unknown_condition_rejected(self):
        with self.assertRaises(ValueError):
            module.matches({"detection":{"selection":{},"condition":"selection or something_else"}}, {})
if __name__=="__main__":
    unittest.main()
