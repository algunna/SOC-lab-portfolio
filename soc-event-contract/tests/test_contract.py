import copy
import importlib.util
import json
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validator", ROOT / "src" / "validate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class ContractTests(unittest.TestCase):
    def setUp(self):
        self.alert = json.loads((ROOT / "examples" / "windows_alert.json").read_text(encoding="utf-8"))
    def test_valid(self):
        self.assertEqual(m.validate(self.alert), [])
    def test_missing_evidence(self):
        a=copy.deepcopy(self.alert);a["evidence"]=[]
        self.assertTrue(m.validate(a))
    def test_invalid_time(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="yesterday"
        self.assertTrue(m.validate(a))
    def test_missing_timezone(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="2026-10-14T12:00:00"
        self.assertTrue(m.validate(a))
    def test_timezone_offset_allowed(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="2026-10-14T12:00:00-04:00"
        self.assertEqual(m.validate(a), [])
    def test_unknown_fields(self):
        a=copy.deepcopy(self.alert);a["api_key"]="should-not-be-accepted"
        self.assertTrue(m.validate(a))
    def test_invalid_severity(self):
        a=copy.deepcopy(self.alert);a["severity"]="urgent"
        self.assertTrue(m.validate(a))
    def test_stable_dedup_key(self):
        a=copy.deepcopy(self.alert);a["event_id"]="another-run"
        self.assertEqual(m.deduplication_key(self.alert),m.deduplication_key(a))
if __name__=="__main__":
    unittest.main()
