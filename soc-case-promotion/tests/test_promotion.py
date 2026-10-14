import copy
import importlib.util
import json
import sqlite3
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("promotion",ROOT/"src"/"promote.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
CANDIDATE={"candidate_id":"candidate-abc123","classification":"unverified","alert_ids":["evt-1"],"evidence_references":["synthetic/1"]}
def report():return {"version":"0.2","incident_candidates":[copy.deepcopy(CANDIDATE)]}
class PromotionTests(unittest.TestCase):
    def setUp(self):self.db=m.cases.connect(":memory:")
    def tearDown(self):self.db.close()
    def test_requires_approval(self):
        with self.assertRaises(ValueError):m.promote(self.db,report(),"candidate-abc123","analyst")
        self.assertEqual(self.db.execute("SELECT count(*) FROM cases").fetchone()[0],0)
    def test_create_with_audit(self):
        key=m.promote(self.db,report(),"candidate-abc123","analyst",approve=True)
        history=m.cases.export_case(self.db,key)["history"]
        self.assertEqual([r["kind"] for r in history],["created","evidence","note"])
        self.assertIn("unverified",history[-1]["detail"])
    def test_duplicate_blocked(self):
        m.promote(self.db,report(),"candidate-abc123","analyst",approve=True)
        with self.assertRaises(ValueError):m.promote(self.db,report(),"candidate-abc123","analyst",approve=True)
        self.assertEqual(self.db.execute("SELECT count(*) FROM cases").fetchone()[0],1)
    def test_severity_from_candidate(self):
        r=report();r["incident_candidates"][0]["highest_severity"]="critical"
        key=m.promote(self.db,r,"candidate-abc123","analyst",approve=True)
        self.assertEqual(self.db.execute("SELECT severity FROM cases WHERE id=?",(key,)).fetchone()[0],"critical")
    def test_informational_maps_to_low_and_override_wins(self):
        r=report();r["incident_candidates"][0]["highest_severity"]="informational"
        key=m.promote(self.db,r,"candidate-abc123","analyst",approve=True)
        self.assertEqual(self.db.execute("SELECT severity FROM cases WHERE id=?",(key,)).fetchone()[0],"low")
        r2=report();r2["incident_candidates"][0].update(candidate_id="candidate-other",alert_ids=["evt-9"],highest_severity="critical")
        key2=m.promote(self.db,r2,"candidate-other","analyst",severity="medium",approve=True)
        self.assertEqual(self.db.execute("SELECT severity FROM cases WHERE id=?",(key2,)).fetchone()[0],"medium")
    def test_same_alerts_under_new_candidate_id_blocked(self):
        m.promote(self.db,report(),"candidate-abc123","analyst",approve=True)
        r=report();r["incident_candidates"][0].update(candidate_id="candidate-rerun",alert_ids=["evt-1","evt-2"])
        with self.assertRaises(ValueError):m.promote(self.db,r,"candidate-rerun","analyst",approve=True)
        self.assertEqual(self.db.execute("SELECT count(*) FROM cases").fetchone()[0],1)
    def test_title_names_actor_and_asset(self):
        r=report();r["incident_candidates"][0].update(actor="LAB\\analyst",asset="LAB-WS01")
        key=m.promote(self.db,r,"candidate-abc123","analyst",approve=True)
        self.assertIn("LAB\\analyst / LAB-WS01",self.db.execute("SELECT title FROM cases WHERE id=?",(key,)).fetchone()[0])
    def test_unknown_candidate(self):
        with self.assertRaises(ValueError):m.promote(self.db,report(),"missing","analyst",approve=True)
    def test_invalid_analyst(self):
        with self.assertRaises(ValueError):m.promote(self.db,report(),"candidate-abc123"," ",approve=True)
    def test_invalid_severity(self):
        with self.assertRaises(ValueError):m.promote(self.db,report(),"candidate-abc123","analyst",severity="extreme",approve=True)
    def test_reject_ambiguous_candidate(self):
        r=report();r["incident_candidates"].append(copy.deepcopy(CANDIDATE))
        with self.assertRaises(ValueError):m.promote(self.db,r,"candidate-abc123","analyst",approve=True)
    def test_rollback_on_evidence_error(self):
        r=report();r["incident_candidates"][0]["evidence_references"]=[None]
        with self.assertRaises(ValueError):m.promote(self.db,r,"candidate-abc123","analyst",approve=True)
        self.assertEqual(self.db.execute("SELECT count(*) FROM cases").fetchone()[0],0)
if __name__=="__main__":unittest.main()
