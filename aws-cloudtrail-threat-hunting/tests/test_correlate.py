import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("cloud2",ROOT/"src"/"correlate.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
def ev(name,minute=0,identity="arn:aws:iam::123456789012:user/lab"):
    return {"eventName":name,"eventTime":f"2026-10-14T12:{minute:02d}:00Z",
            "userIdentity":{"type":"IAMUser","arn":identity},"sourceIPAddress":"192.0.2.10"}
class CorrelationTests(unittest.TestCase):
    def test_same_actor_correlation(self):
        r=mod.analyze([ev("AttachRolePolicy"),ev("StopLogging",5)])
        self.assertEqual(len(r["incidents"]),1)
    def test_different_actors(self):
        r=mod.analyze([ev("AttachRolePolicy"),ev("StopLogging",5,"other")])
        self.assertEqual(r["incidents"],[])
    def test_outside_window(self):
        r=mod.analyze([ev("AttachRolePolicy"),ev("StopLogging",45)])
        self.assertEqual(r["incidents"],[])
    def test_failed_call_not_counted(self):
        denied=ev("StopLogging",5);denied["errorCode"]="AccessDenied"
        self.assertEqual(mod.analyze([ev("AttachRolePolicy"),denied])["incidents"],[])
    def test_every_episode_reported(self):
        later = lambda name, minute: dict(ev(name, minute), eventTime=f"2026-10-14T14:{minute:02d}:00Z")
        r = mod.analyze([ev("StopLogging"), ev("CreateAccessKey", 5), later("AttachUserPolicy", 0), later("DeleteTrail", 5)])
        self.assertEqual([i["start"][11:16] for i in r["incidents"]], ["12:00", "14:00"])
    def test_window_edge_included(self):
        self.assertEqual(len(mod.analyze([ev("AttachRolePolicy"), ev("StopLogging", 30)])["incidents"]), 1)
    def test_unattributed_events_not_correlated(self):
        a = ev("AttachRolePolicy"); b = ev("UpdateTrail", 5)
        a["userIdentity"] = {"type": "AWSService"}; b["userIdentity"] = {"type": "AWSService"}
        self.assertEqual(mod.analyze([a, b])["incidents"], [])
    def test_policy_version_escalation_correlated(self):
        self.assertEqual(len(mod.analyze([ev("CreatePolicyVersion"), ev("StopLogging", 5)])["incidents"]), 1)
    def test_records_export(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.json"
            p.write_text(json.dumps({"Records":[ev("AttachRolePolicy")]}))
            self.assertEqual(len(mod.load(p)),1)
    def test_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.jsonl"
            p.write_text(json.dumps(ev("AttachRolePolicy"))+"\n"+json.dumps(ev("StopLogging",1)))
            self.assertEqual(len(mod.load(p)),2)
    def test_report(self):
        self.assertIn("Timeline",mod.markdown(mod.analyze([ev("AttachRolePolicy"),ev("StopLogging",1)])))
if __name__=="__main__":unittest.main()
