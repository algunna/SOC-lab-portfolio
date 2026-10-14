"""Offline CloudTrail correlation from JSONL or AWS Records JSON."""
import argparse
import importlib.util
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# One definition of the watched event names, shared with hunt.py
_spec = importlib.util.spec_from_file_location("cloudtrail_hunt", ROOT / "src" / "hunt.py")
_hunt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hunt)
IAM = _hunt.IAM_CHANGES
LOGGING = _hunt.LOGGING_CHANGES

def load(path):
    data = path.read_text(encoding="utf-8").strip()
    if not data:
        return []
    if data[0] in "[{":
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("Records"), list):
            events = parsed["Records"]
        elif isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict):
            events = [parsed]
        else:
            events = [json.loads(line) for line in data.splitlines() if line.strip()]
    else:
        raise ValueError("Expected JSON or JSONL")
    if not all(isinstance(event, dict) for event in events):
        raise ValueError("Every event must be a JSON object")
    return events

def identity(event):
    ident = event.get("userIdentity")
    return ident if isinstance(ident, dict) else {}

def actor(event):
    ident = identity(event)
    return str(ident.get("arn") or ident.get("principalId") or ident.get("userName") or "unknown")

def timestamp(event):
    try:
        t = datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00"))
        return t.astimezone(timezone.utc) if t.tzinfo else None
    except (KeyError, AttributeError, TypeError, ValueError):
        return None

def analyze(events, window_minutes=30):
    findings = []
    event_rows = []
    for event in events:
        name = str(event.get("eventName", ""))
        rules = []
        if identity(event).get("type") == "Root":
            # Any use of root credentials matters, even when the call was denied
            rules.append(("root_account_activity", "high", "T1078.004"))
        if not event.get("errorCode"):  # denied calls are not completed changes
            if name in IAM:
                rules.append(("iam_change", "medium", "T1098"))
            if name in LOGGING:
                rules.append(("logging_change", "high", "T1562.008"))
            if name == "AssumeRole":
                rules.append(("role_assumption", "low", "T1078.004"))
        time = timestamp(event)
        for rule, severity, attack in rules:
            finding = {"rule": rule, "severity": severity, "attack_hypothesis": attack,
                       "actor": actor(event), "event_name": name,
                       "time": event.get("eventTime", "unknown"),
                       "source_ip": event.get("sourceIPAddress", "unknown")}
            findings.append(finding)
            if time:
                event_rows.append((time, finding))
    grouped = defaultdict(list)
    for t, finding in sorted(event_rows, key=lambda row: row[0]):
        grouped[finding["actor"]].append((t, finding))
    incidents = []
    for who, rows in grouped.items():
        if who == "unknown":
            continue  # unattributed events from different services are not one actor
        index = 0
        while index < len(rows):
            start = rows[index][0]
            relevant = [(time, record) for time, record in rows[index:] if timedelta(0) <= time-start <= timedelta(minutes=window_minutes)]
            rules = {record["rule"] for _, record in relevant}
            if "iam_change" in rules and "logging_change" in rules:
                incidents.append({"actor": who, "start": start.isoformat(),
                                  "severity": "high", "related_events": [record for _, record in relevant],
                                  "reason": "IAM changes and CloudTrail logging changes within correlation window"})
                index += len(relevant)  # look for later episodes after this one
            else:
                index += 1
    return {"count": len(findings), "findings": findings, "incidents": incidents}

def markdown(result):
    lines = ["# AWS CloudTrail Analyst Report", "",
             f'Investigation leads: {result["count"]}', f'Correlated cases: {len(result["incidents"])}', "",
             "These are investigation hypotheses, not confirmed attacks.", ""]
    for case in result["incidents"]:
        lines += [f'## Correlated case — {case["actor"]}',f'- First event: {case["start"]}',
                  f'- Assessment: {case["reason"]}', "- Timeline:"]
        for event in case["related_events"]:
            lines.append(f'  - {event["time"]}: {event["event_name"]} ({event["rule"]})')
        lines.append("")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=ROOT / "fixtures" / "events.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "findings.json")
    parser.add_argument("--markdown", type=Path, default=ROOT / "reports" / "analyst_report.md")
    args = parser.parse_args()
    result = analyze(load(args.input))
    for path, data in ((args.output, json.dumps(result, indent=2)+"\n"), (args.markdown, markdown(result))):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
    print(f'Generated {result["count"]} findings and {len(result["incidents"])} correlated cases')

if __name__ == "__main__":
    main()
