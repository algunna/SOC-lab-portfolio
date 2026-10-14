"""Structural checks only: these do not execute SPL against Splunk."""
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class SplunkLabTests(unittest.TestCase):
    def test_searches(self):
        searches=sorted((ROOT/"searches").glob("*.spl"))
        self.assertEqual(len(searches),3)
        for path in searches:
            text=path.read_text(encoding="utf-8")
            self.assertIn("| table ",text)
            self.assertIn("EventCode=",text)
            self.assertNotIn("| delete",text.lower())
            self.assertNotIn("| outputlookup",text.lower())
    def test_playbooks(self):
        for name in ("POWERSHELL","PRIVILEGED_GROUP","SCHEDULED_TASK"):
            text=(ROOT/"playbooks"/f"{name}.md").read_text(encoding="utf-8")
            self.assertIn("False positives",text)
            self.assertIn("Limitations",text)
    def test_related_docs(self):
        text=(ROOT/"README.md").read_text(encoding="utf-8")
        self.assertIn("not execution against a real Splunk",text)
if __name__=="__main__":unittest.main()
