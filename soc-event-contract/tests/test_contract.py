import copy
import importlib.util
import json
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validator", ROOT / "src" / "validate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def fields(errors):
    return {e.split(":", 1)[0].split(".", 1)[0] for e in errors}
class ContractTests(unittest.TestCase):
    def setUp(self):
        self.alert = json.loads((ROOT / "examples" / "windows_alert.json").read_text(encoding="utf-8"))
    def test_valid(self):
        self.assertEqual(m.validate(self.alert), [])
    def test_missing_evidence(self):
        a=copy.deepcopy(self.alert);a["evidence"]=[]
        self.assertEqual(fields(m.validate(a)), {"evidence"})
    def test_invalid_time(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="yesterday"
        self.assertEqual(fields(m.validate(a)), {"occurred_at"})
    def test_missing_timezone(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="2026-10-14T12:00:00"
        self.assertEqual(fields(m.validate(a)), {"occurred_at"})
    def test_timezone_offset_allowed(self):
        a=copy.deepcopy(self.alert);a["occurred_at"]="2026-10-14T12:00:00-04:00"
        self.assertEqual(m.validate(a), [])
    def test_unknown_fields(self):
        a=copy.deepcopy(self.alert);a["api_key"]="should-not-be-accepted"
        self.assertTrue(any("api_key" in e for e in m.validate(a)))
    def test_invalid_severity(self):
        a=copy.deepcopy(self.alert);a["severity"]="urgent"
        self.assertEqual(fields(m.validate(a)), {"severity"})
    def test_non_rfc3339_times(self):
        for value in ("2026-10-14 12:00:00+00:00", "20261014T120000Z", "2026-10-14T12+00:00", "2026-W42-3T12:00+00:00"):
            with self.subTest(value=value):
                a=copy.deepcopy(self.alert);a["occurred_at"]=value
                self.assertEqual(fields(m.validate(a)), {"occurred_at"})
    def test_control_characters(self):
        for field, value in (("event_id", "evt-1\n"), ("title", "x\n# INJECTED"), ("attack_techniques", ["T1059\n"])):
            with self.subTest(field=field):
                a=copy.deepcopy(self.alert);a[field]=value
                self.assertEqual(fields(m.validate(a)), {field})
    def test_technique_id_format(self):
        a=copy.deepcopy(self.alert);a["attack_techniques"]=["T1"]
        self.assertEqual(fields(m.validate(a)), {"attack_techniques"})
    def test_evidence_limit(self):
        a=copy.deepcopy(self.alert);a["evidence"]=a["evidence"]*31
        self.assertEqual(fields(m.validate(a)), {"evidence"})
    def test_stable_dedup_key(self):
        a=copy.deepcopy(self.alert);a["event_id"]="another-run"
        self.assertEqual(m.deduplication_key(self.alert),m.deduplication_key(a))
if __name__=="__main__":
    unittest.main()
