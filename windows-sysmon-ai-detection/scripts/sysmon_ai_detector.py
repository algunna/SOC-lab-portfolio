"""Offline Sysmon Event ID 1 XML investigation; binary EVTX not supported."""
import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NS={"e":"http://schemas.microsoft.com/win/2004/08/events/event"}
POWERSHELL={"powershell.exe","pwsh.exe","pwsh.dll"}
SWITCH_PREFIXES="-/–—―"  # PowerShell also accepts / and en/em dashes
def powershell_indicators(cmd):
    """Suspicious switches, allowing the abbreviations PowerShell accepts (-e, -ec, -ep, -w)."""
    tokens=cmd.lower().split()
    found=set()
    for i,token in enumerate(tokens):
        if token[0] not in SWITCH_PREFIXES: continue
        name=token[1:]
        following=tokens[i+1] if i+1<len(tokens) else ""
        if name in ("e","ec") or (len(name)>=2 and "encodedcommand".startswith(name)):
            found.add("Encoded command")
        elif (name=="ep" or (len(name)>=2 and "executionpolicy".startswith(name))) and following=="bypass":
            found.add("Execution policy bypass")
        elif name and "windowstyle".startswith(name) and following in ("hidden","1"):
            found.add("Hidden window")
    return [label for label in ("Encoded command","Execution policy bypass","Hidden window") if label in found]
def parse_events(xml):
    xml=xml.strip()
    if not xml.startswith("<Events"):
        # wevtutil qe /f:xml writes bare <Event> elements with no wrapper
        xml=re.sub(r"^<\?xml[^>]*\?>","",xml).strip()
        xml=f'<Events xmlns="{NS["e"]}">{xml}</Events>'
    return ET.fromstring(xml).findall(".//e:Event",NS)
def analyze_xml(xml):
    findings=[]
    for event in parse_events(xml):
        if event.findtext("e:System/e:EventID",default="",namespaces=NS).strip()!="1": continue
        data={x.get("Name"):(x.text or "") for x in event.findall("e:EventData/e:Data",NS)}
        process=data.get("Image","").replace("/","\\").lower().split("\\")[-1]
        # A renamed copy of powershell.exe keeps its OriginalFileName
        if process not in POWERSHELL and data.get("OriginalFileName","").lower() not in POWERSHELL: continue
        indicators=powershell_indicators(data.get("CommandLine",""))
        if indicators:
            findings.append({"host":event.findtext("e:System/e:Computer",default="",namespaces=NS),
               "image":data.get("Image",""),"time":data.get("UtcTime",""),
               "indicators":indicators,"attack":"T1059.001"})
    return findings
def md(value):
    """Keep log-controlled text from adding lines, links or formatting to the report."""
    value=re.sub(r"[\x00-\x1f\x7f]+"," ",str(value))
    return re.sub(r"([\\`*_\[\]<>#|])",r"\\\1",value)
def report(findings):
    lines=["# Sysmon Investigation","",f"Suspicious PowerShell events: {len(findings)}","",
           "Heuristic results are not proof of compromise.",""]
    for f in findings:
        lines += [f'## {md(f["host"])} {md(f["time"])}',f'- Process: {md(f["image"])}',
                  f'- Indicators: {", ".join(f["indicators"])}',
                  '- MITRE ATT&CK hypothesis: T1059.001',""]
    return "\n".join(lines)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",type=Path,default=ROOT/"logs"/"sample_sysmon.xml")
    p.add_argument("--output",type=Path,default=ROOT/"reports"/"sysmon_detection_report.md")
    a=p.parse_args()
    if a.input.suffix.lower()==".evtx": p.error("Export EVTX to XML first")
    try:
        findings=analyze_xml(a.input.read_text(encoding="utf-8"))
    except (OSError,UnicodeDecodeError,ET.ParseError) as exc:
        p.error(f"{a.input}: {exc}")
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(report(findings),encoding="utf-8")
    print(f"Found {len(findings)} events")
if __name__=="__main__": main()
