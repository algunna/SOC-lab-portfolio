import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("dashboard",ROOT/"src"/"dashboard.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
DATA=json.loads((ROOT/"fixtures"/"demo.json").read_text(encoding="utf-8"))
cspec=importlib.util.spec_from_file_location("contract",ROOT.parent/"soc-event-contract"/"src"/"validate.py")
contract=importlib.util.module_from_spec(cspec);cspec.loader.exec_module(contract)
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
    def test_fixture_alerts_follow_event_contract(self):
        for alert in DATA["alerts"]:
            self.assertEqual(contract.validate(alert),[],alert["event_id"])
    def test_contract_source_and_lists_displayed_as_text(self):
        page=m.render(DATA)
        self.assertIn(">windows</td>",page)
        self.assertNotIn("record_id",page)
        x=json.loads(json.dumps(DATA));x["candidates"][0]["alert_ids"]=["a","b"]
        self.assertIn(">a, b</td>",m.render(x))
    def test_severity_badge_only_for_known_values(self):
        x=json.loads(json.dumps(DATA));x["alerts"][0]["severity"]="x' onmouseover='y"
        page=m.render(x)
        self.assertIn("sev-high",page)
        self.assertNotIn("sev-x",page)
        self.assertNotIn("onmouseover='",page)
    def test_missing_values_shown_as_dash(self):
        x=json.loads(json.dumps(DATA));del x["alerts"][0]["actor"]
        self.assertIn("data-label='Actor'>\u2014</td>",m.render(x))

class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=m.make_server(m.render(DATA).encode("utf-8"),port=0)
        cls.port=cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close()
    def request(self,method="GET",path="/",host=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=5)
        conn.request(method,path,headers={"Host":host or f"127.0.0.1:{self.port}"})
        r=conn.getresponse();body=r.read();conn.close()
        return r,body
    def test_dashboard_served_with_security_headers(self):
        r,body=self.request()
        self.assertEqual(r.status,200)
        self.assertIn(b"SOC Command Center",body)
        self.assertIn("frame-ancestors 'none'",r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"),"DENY")
        self.assertNotIn("Python",r.getheader("Server"))
    def test_error_pages_carry_security_headers(self):
        for method,path,status in (("GET","/x",404),("POST","/",405)):
            r,_=self.request(method,path)
            self.assertEqual(r.status,status)
            self.assertIn("default-src 'none'",r.getheader("Content-Security-Policy"))
    def test_query_string_and_head(self):
        self.assertEqual(self.request(path="/?view=all")[0].status,200)
        r,body=self.request("HEAD")
        self.assertEqual((r.status,body),(200,b""))
    def test_foreign_host_rejected(self):
        self.assertEqual(self.request(host=f"attacker.example:{self.port}")[0].status,421)
        self.assertEqual(self.request(host=f"localhost:{self.port}")[0].status,200)
if __name__=="__main__":unittest.main()
