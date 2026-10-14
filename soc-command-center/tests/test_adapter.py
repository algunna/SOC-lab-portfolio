import importlib.util,json,unittest,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("adapter",ROOT/"src"/"adapter.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
A=json.loads((ROOT.parent/"soc-event-contract"/"examples"/"windows_alert.json").read_text())
C={"version":"0.2","incident_candidates":[{"candidate_id":"candidate-demo","classification":"unverified","alert_ids":[A["event_id"]],"event_count":1}]}
class AdapterTests(unittest.TestCase):
 def test_valid(self):
  x=m.build({"accepted":[A],"rejected":[]},C)
  self.assertEqual(len(x["alerts"]),1)
 def test_rejected_input(self):
  with self.assertRaises(ValueError):m.build({"accepted":[A],"rejected":[{"error":"bad"}]},C)
 def test_bad_event(self):
  a=copy.deepcopy(A);a["severity"]="extreme"
  with self.assertRaises(ValueError):m.build({"accepted":[a],"rejected":[]},C)
 def test_unknown_alert_reference(self):
  c=copy.deepcopy(C);c["incident_candidates"][0]["alert_ids"]=["unknown"]
  with self.assertRaises(ValueError):m.build({"accepted":[A],"rejected":[]},c)
 def test_duplicate_event(self):
  with self.assertRaises(ValueError):m.build({"accepted":[A,A],"rejected":[]},C)
 def test_unverified_only(self):
  c=copy.deepcopy(C);c["incident_candidates"][0]["classification"]="confirmed"
  with self.assertRaises(ValueError):m.build({"accepted":[A],"rejected":[]},c)
if __name__=="__main__":unittest.main()
