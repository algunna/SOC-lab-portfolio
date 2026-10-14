"""Offline phishing triage based on parsed email; no links opened."""
import argparse
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from pathlib import Path
import re
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[1]
URL=re.compile(r"https?://[^\s<>'\x22]+", re.I)
URGENCY=re.compile(r"\b(urgent|immediately|within \d+ hours|suspension|verify your (?:account|information))\b", re.I)
def analyze_email(raw):
    msg=Parser(policy=policy.default).parsestr(raw)
    sender=parseaddr(str(msg.get("From","")))[1]
    subject=str(msg.get("Subject",""))
    body="\n".join(str(part.get_content()) for part in msg.walk() if part.get_content_type()=="text/plain") if msg.is_multipart() else str(msg.get_content())
    urls=list(dict.fromkeys(u.rstrip(".,);!?") for u in URL.findall(body)))
    indicators=[]
    if any(urlsplit(url).scheme.lower()=="http" for url in urls): indicators.append("Unencrypted HTTP URL")
    if URGENCY.search(subject+" "+body): indicators.append("Urgency or verification language")
    domain=sender.rpartition("@")[2].lower()
    if domain and any((urlsplit(url).hostname or "").lower()!=domain for url in urls):
        indicators.append("Sender and link domains differ; verify context")
    return {"sender":sender or "(missing)","subject":subject or "(missing)",
            "urls":urls,"indicators":indicators,"risk":"Review recommended" if indicators else "No heuristic indicators"}
def report(result):
    lines=["# Phishing Investigation","",f'- Sender: {result["sender"]}',f'- Subject: {result["subject"]}',
           f'- Assessment: {result["risk"]}',"","## URLs (do not click)",""]
    lines += ["- `"+url+"`" for url in result["urls"]]
    lines += ["","## Indicators",""]+["- "+x for x in result["indicators"]]
    lines += ["","These heuristics are not proof of phishing. Validate using headers and organizational context.",""]
    return "\n".join(lines)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,default=ROOT/"emails"/"sample_phishing_email.txt")
    p.add_argument("--output",type=Path,default=ROOT/"reports"/"phishing_detection_report.md")
    a=p.parse_args()
    result=analyze_email(a.input.read_text(encoding="utf-8"))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(report(result),encoding="utf-8")
    print(f'Found {len(result["indicators"])} indicators')
if __name__=="__main__": main()
