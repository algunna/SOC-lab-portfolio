import importlib.util
import json
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("dashboard",ROOT/"src"/"dashboard.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
DATA=json.loads((ROOT/"fixtures"/"demo.json").read_text(encoding="utf-8"))
class DashboardTests(unittest.TestCase):
    def test_render_sections(self):
        page=m.render(DATA)
        for expected in ("Alerts (2)", "Unverified candidates (1)", "Investigation cases (1)"):
            self.assertIn(expected,page)
    def test_escapes_untrusted_text(self):
        x=json.loads(json.dumps(DATA));x["alerts"][0]["title"]="<script>alert('X')</script>"
        page=m.render(x)
        self.assertNotIn("<script>",page)
        self.assertIn("&lt;script&gt;",page)
    def test_reject_missing_sections(self):
        with self.assertRaises(ValueError):m.render({"alerts":[]})
    def test_no_forms_or_scripts(self):
        page=m.render(DATA)
        self.assertNotIn("<form",page)
        self.assertNotIn("<script",page)
    def test_valid_html(self):
        self.assertIn("<!doctype html>",m.render(DATA))
if __name__=="__main__":unittest.main()
