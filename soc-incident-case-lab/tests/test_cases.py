import importlib.util
import sqlite3
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("cases",ROOT/"src"/"cases.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class CaseTests(unittest.TestCase):
    def setUp(self):
        self.db=m.connect(":memory:")
    def tearDown(self):
        self.db.close()
    def test_create_audit(self):
        key=m.create_case(self.db,"Suspicious PowerShell","high")
        self.assertEqual(m.export_case(self.db,key)["history"][0]["kind"],"created")
    def test_notes_and_evidence(self):
        key=m.create_case(self.db,"SSH alert","medium")
        with self.db:
            m.record(self.db,key,"note","Reviewed source")
            m.record(self.db,key,"evidence","Synthetic fixture 1")
        self.assertEqual(len(m.export_case(self.db,key)["history"]),3)
    def test_valid_transition(self):
        key=m.create_case(self.db,"Review","low")
        m.transition(self.db,key,"investigating")
        m.transition(self.db,key,"closed")
        self.assertEqual(m.export_case(self.db,key)["case"]["status"],"closed")
    def test_closed_cannot_reopen(self):
        key=m.create_case(self.db,"Review","low")
        m.transition(self.db,key,"investigating")
        m.transition(self.db,key,"closed")
        with self.assertRaises(ValueError):m.transition(self.db,key,"open")
    def test_invalid_severity(self):
        with self.assertRaises(ValueError):m.create_case(self.db,"Alert","severe")
    def test_unknown_case(self):
        with self.assertRaises(ValueError):m.record(self.db,999,"note","Missing")
if __name__=="__main__":unittest.main()
