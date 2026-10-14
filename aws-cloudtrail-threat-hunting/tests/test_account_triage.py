import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("account_triage", ROOT/"src"/"account_triage.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
def event(action, minute=0, account="111111111111", who="demo"):
    return {"eventName":action,"eventTime":f"2026-10-14T12:{minute:02d}:00Z",
            "recipientAccountId":account,"userIdentity":{"type":"IAMUser","accountId":account,"arn":f"arn:aws:iam::{account}:user/{who}"}}
class AccountTriageTests(unittest.TestCase):
    def test_same_identity(self):
        self.assertEqual(len(mod.correlate([event("AttachRolePolicy"),event("StopLogging",5)])),1)
    def test_different_account(self):
        self.assertEqual(mod.correlate([event("AttachRolePolicy"),event("StopLogging",5,"222222222222")]),[])
    def test_different_identity(self):
        self.assertEqual(mod.correlate([event("AttachRolePolicy"),event("StopLogging",5,who="other")]),[])
    def test_window_boundary(self):
        self.assertEqual(mod.correlate([event("AttachRolePolicy"),event("StopLogging",45)]),[])
    def test_failed_action(self):
        blocked=event("StopLogging",5)
        blocked["errorCode"]="AccessDenied"
        self.assertEqual(mod.correlate([event("AttachRolePolicy"),blocked]),[])
    def test_scoring_explained(self):
        result=mod.correlate([event("AttachRolePolicy"),event("StopLogging",5)])[0]
        self.assertEqual(result["risk_score"],60)
        self.assertEqual(result["severity"],"high")
        self.assertTrue(result["reasons"])
    def test_every_episode_scored(self):
        later=[dict(event(n,m),eventTime=f"2026-10-16T12:{m:02d}:00Z") for n,m in (("CreateAccessKey",0),("StopLogging",2),("DeleteTrail",4))]
        cases=mod.correlate([event("AttachRolePolicy"),event("UpdateTrail",5)]+later)
        self.assertEqual([c["risk_score"] for c in cases],[40,60])
    def test_non_object_identity_ignored(self):
        a=event("AttachRolePolicy");a["userIdentity"]="x"
        self.assertEqual(mod.correlate([a,event("StopLogging",5)]),[])
    def test_missing_identity_not_correlated(self):
        a=event("AttachRolePolicy");b=event("StopLogging",5)
        a["userIdentity"]={};b["userIdentity"]={}
        self.assertEqual(mod.correlate([a,b]),[])
if __name__=="__main__": unittest.main()
