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
    def test_candidate_triage_fields(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["occurred_at"]="2026-10-14T12:10:00Z";e["severity"]="high";e["rule_id"]="windows.other"
        c=m.group_alerts(report(SAMPLE,e))["incident_candidates"][0]
        self.assertEqual((c["source_system"],c["actor"],c["asset"]),("windows","LAB\\analyst","LAB-WS01"))
        self.assertEqual((c["first_seen"],c["last_seen"]),("2026-10-14T12:00:00+00:00","2026-10-14T12:10:00+00:00"))
        self.assertEqual(c["highest_severity"],"high")
        self.assertEqual(c["rule_ids"],["windows.other","windows.powershell.encoded"])
    def test_cli_reports_bad_input_without_traceback(self):
        import subprocess,sys,tempfile
        with tempfile.TemporaryDirectory() as d:
            bad=Path(d)/"bad.json";bad.write_text("{",encoding="utf-8")
            r=subprocess.run([sys.executable,str(ROOT/"src"/"correlate.py"),str(bad),"--out",str(Path(d)/"o.json")],capture_output=True,text=True)
        self.assertEqual(r.returncode,2)
        self.assertNotIn("Traceback",r.stderr)
    def test_refuse_rejected(self):
        with self.assertRaises(ValueError):m.group_alerts({"accepted":[SAMPLE],"rejected":[{"errors":["bad"]}]})
    def test_outside_window_separate(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["occurred_at"]="2026-10-14T12:16:00Z"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],2)
    def test_window_boundary_inclusive(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["occurred_at"]="2026-10-14T12:15:00Z"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],1)
    def test_timezone_equivalence(self):
        e=copy.deepcopy(SAMPLE);e["event_id"]="win-lab-002";e["occurred_at"]="2026-10-14T08:05:00-04:00"
        self.assertEqual(m.group_alerts(report(SAMPLE,e))["counts"]["candidates"],1)
    def test_revalidate_untrusted_accepted_event(self):
        e=copy.deepcopy(SAMPLE);e["occurred_at"]="yesterday"
        with self.assertRaises(ValueError):m.group_alerts(report(e))
    def test_invalid_window(self):
        with self.assertRaises(ValueError):m.group_alerts(report(SAMPLE),0)
    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):m.group_alerts(report(SAMPLE,SAMPLE))
    def test_empty(self):
        self.assertEqual(m.group_alerts(report())["counts"],{"candidates":0,"alerts":0})
if __name__=="__main__":unittest.main()
