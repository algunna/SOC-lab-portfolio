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
