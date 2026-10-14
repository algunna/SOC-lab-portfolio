"""Offline Sysmon Event ID 1 XML investigation; binary EVTX not supported."""
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NS={"e":"http://schemas.microsoft.com/win/2004/08/events/event"}
def analyze_xml(xml):
    root=ET.fromstring(xml)
    events=[root] if root.tag.endswith("}Event") else root.findall(".//e:Event",NS)
    findings=[]
    for event in events:
        if event.findtext("e:System/e:EventID",default="",namespaces=NS)!="1": continue
        data={x.get("Name"):(x.text or "") for x in event.findall("e:EventData/e:Data",NS)}
        process=data.get("Image","").replace("/","\\").lower().split("\\")[-1]
        if process not in ("powershell.exe","pwsh.exe"): continue
        cmd=data.get("CommandLine","").lower()
        indicators=[label for label,match in (
            ("Encoded command","-encodedcommand" in cmd or "-enc " in cmd),
            ("Execution policy bypass","-executionpolicy bypass" in cmd or "-ep bypass" in cmd),
            ("Hidden window","-windowstyle hidden" in cmd or "-w hidden" in cmd)) if match]
        if indicators:
            findings.append({"host":event.findtext("e:System/e:Computer",default="",namespaces=NS),
               "image":data.get("Image",""),"time":data.get("UtcTime",""),
               "indicators":indicators,"attack":"T1059.001"})
    return findings
def report(findings):
    lines=["# Sysmon Investigation","",f"Suspicious PowerShell events: {len(findings)}","",
           "Heuristic results are not proof of compromise.",""]
    for f in findings:
        lines += [f'## {f["host"]} {f["time"]}',f'- Process: {f["image"]}',
                  f'- Indicators: {", ".join(f["indicators"])}',
                  '- MITRE ATT&CK hypothesis: T1059.001',""]
    return "\n".join(lines)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,default=ROOT/"logs"/"sample_sysmon.xml")
    p.add_argument("--output",type=Path,default=ROOT/"reports"/"sysmon_detection_report.md")
    a=p.parse_args()
    if a.input.suffix.lower()==".evtx": p.error("Export EVTX to XML first")
    findings=analyze_xml(a.input.read_text(encoding="utf-8"))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(report(findings),encoding="utf-8")
    print(f"Found {len(findings)} events")
if __name__=="__main__": main()
