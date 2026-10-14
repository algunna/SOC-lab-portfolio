import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
sysmon=load(ROOT/"windows-sysmon-ai-detection/scripts/sysmon_ai_detector.py","sysmon")
phish=load(ROOT/"phishing-email-analyzer/scripts/phishing_email_analyzer.py","phish")
class DetectionTests(unittest.TestCase):
    def test_sysmon_detects_encoded(self):
        sample=(ROOT/"windows-sysmon-ai-detection/logs/sample_sysmon.xml").read_text()
        self.assertIn("Encoded command",sysmon.analyze_xml(sample)[0]["indicators"])
    def test_sysmon_clean(self):
        sample=(ROOT/"windows-sysmon-ai-detection/logs/sample_sysmon.xml").read_text()
        self.assertEqual(sysmon.analyze_xml(sample.replace("-EncodedCommand AAAA -ExecutionPolicy Bypass","-NoProfile")),[])
    def test_sysmon_event_type(self):
        sample=(ROOT/"windows-sysmon-ai-detection/logs/sample_sysmon.xml").read_text()
        self.assertEqual(sysmon.analyze_xml(sample.replace("<EventID>1</EventID>","<EventID>3</EventID>")),[])
    def test_phishing_headers(self):
        r=phish.analyze_email("From: me@test.org\nSubject: Hello\n\nSee https://example.org")
        self.assertEqual(r["sender"],"me@test.org")
    def test_phishing_clean(self):
        self.assertEqual(phish.analyze_email("From: a@test.org\nSubject: Hi\n\nHello")["indicators"],[])
    def test_phishing_http(self):
        self.assertIn("Unencrypted HTTP URL",phish.analyze_email("From: a@test.org\nSubject: Urgent\n\nhttp://test.org/verify")["indicators"])
    def test_phishing_no_hardcoded_sender(self):
        self.assertEqual(phish.analyze_email("From: abc@xyz.org\nSubject: OK\n\nHello")["sender"],"abc@xyz.org")
if __name__=="__main__": unittest.main()
