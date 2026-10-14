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
NS='xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
def sysmon_event(cmd,image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",original="",time="2026-10-14 12:00:00"):
    extra=f'<Data Name="OriginalFileName">{original}</Data>' if original else ""
    return (f'<Event {NS}><System><EventID>1</EventID><Computer>LAB-01</Computer></System><EventData>'
            f'<Data Name="Image">{image}</Data>{extra}<Data Name="CommandLine">{cmd}</Data><Data Name="UtcTime">{time}</Data></EventData></Event>')
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
    def test_sysmon_switch_abbreviations(self):
        for cmd in ("powershell.exe -e SQBFAFgA","powershell.exe -ec SQBFAFgA","powershell.exe /enc SQBFAFgA",
                    "powershell.exe \u2013EncodedCommand SQBFAFgA","powershell.exe -nop -enc"):
            with self.subTest(cmd=cmd):
                self.assertEqual(sysmon.analyze_xml(sysmon_event(cmd))[0]["indicators"],["Encoded command"])
    def test_sysmon_benign_switches(self):
        self.assertEqual(sysmon.analyze_xml(sysmon_event("powershell.exe -ExecutionPolicy RemoteSigned -WindowStyle Normal")),[])
    def test_sysmon_renamed_powershell(self):
        event=sysmon_event("svc.exe -enc SQBFAFgA",image="C:\\Users\\Public\\svc.exe",original="PowerShell.EXE")
        self.assertEqual(len(sysmon.analyze_xml(event)),1)
    def test_sysmon_wevtutil_export(self):
        export="\n".join([sysmon_event("powershell.exe -e AAAA"),sysmon_event("powershell.exe -w hidden -ep bypass")])
        self.assertEqual(len(sysmon.analyze_xml(export)),2)
    def test_sysmon_report_escapes_log_fields(self):
        findings=sysmon.analyze_xml(sysmon_event("powershell.exe -e AAAA",time="12:00&#10;# Verdict: BENIGN [x](https://evil.test)"))
        text=sysmon.report(findings)
        self.assertNotIn("\n# Verdict",text)
        self.assertNotIn("[x](",text)
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
