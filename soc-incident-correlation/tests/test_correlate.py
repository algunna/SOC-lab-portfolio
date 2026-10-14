import copy
import importlib.util
import json
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("correlate", ROOT/"src"/"correlate.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SAMPLE=json.loads((ROOT.parent/"soc-event-contract"/"examples"/"windows_alert.json").read_text(encoding="utf-8"))
def report(*events):return {"accepted":list(events),"rejected":[]}
class CorrelationTests(unittest.TestCase):
    def test_single_candidate(self):
        r=m.group_alerts(report(SAMPLE))
        self.assertEqual((r["counts"]["candidates"],r["counts"]["alerts"]),(1,1))
    def test_same_actor_asset_group(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["rule_id"]="other.rule"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],1)
    def test_different_asset_separate(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["asset"]="OTHER"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],2)
    def test_different_source_separate(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="aws-002";e["source"]["system"]="aws_cloudtrail"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],2)
    def test_missing_actor_isolated(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e.pop("actor")
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],2)
    def test_evidence_reference_preserved(self):
        c=m.group_alerts(report(SAMPLE))["incident_candidates"][0]
        self.assertEqual(c["evidence_references"],["fixtures/windows-event-001"])
    def test_stable_candidate_id(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002"
        a=m.group_alerts(report(SAMPLE,e))["incident_candidates"][0]["candidate_id"]
        b=m.group_alerts(report(e,SAMPLE))["incident_candidates"][0]["candidate_id"]
        self.assertEqual(a,b)
    def test_refuse_rejected(self):
        with self.assertRaises(ValueError):m.group_alerts({"accepted":[SAMPLE],"rejected":[{"errors":["bad"]}]})
    def test_empty(self):
        self.assertEqual(m.group_alerts(report())["counts"],{"candidates":0,"alerts":0})
if __name__=="__main__":unittest.main()
