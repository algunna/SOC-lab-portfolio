"""Account-scoped CloudTrail correlation and explainable triage scoring."""
import argparse
import importlib.util
import json
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloudtrail_base", ROOT / "src" / "correlate.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

def identity_key(event):
    identity = base.identity(event)
    arn = identity.get("arn") or identity.get("principalId") or identity.get("userName")
    account = identity.get("accountId") or event.get("recipientAccountId")
    if not account and isinstance(arn, str) and arn.startswith("arn:"):
        segments = arn.split(":")
        if len(segments) > 4:
            account = segments[4]
    if not account or not arn:
        return None
    return str(account), str(arn)

def correlate(events, minutes=30):
    grouped = defaultdict(list)
    for event in events:
        if event.get("errorCode") or not base.timestamp(event):
            continue
        key = identity_key(event)
        if key:
            grouped[key].append(event)
    cases = []
    for (account, actor), entries in grouped.items():
        entries.sort(key=base.timestamp)
        first = 0
        while first < len(entries):
            anchor = base.timestamp(entries[first])
            segment = [e for e in entries[first:] if timedelta(0) <= base.timestamp(e)-anchor <= timedelta(minutes=minutes)]
            names = {e.get("eventName") for e in segment}
            if names.intersection(base.IAM) and names.intersection(base.LOGGING):
                score = 40
                reasons = ["IAM and logging changes from the same account and identity (+40)"]
                if any(base.identity(e).get("type") == "Root" for e in segment):
                    score += 25
                    reasons.append("Root identity activity (+25)")
                if names.intersection({"StopLogging", "DeleteTrail"}):
                    score += 20
                    reasons.append("Logging stopped or trail deleted (+20)")
                cases.append({"account_id": account, "actor": actor, "start": anchor.isoformat(),
                              "risk_score": score, "severity": "critical" if score >= 80 else "high",
                              "reasons": reasons,
                              "timeline": [{"time": e.get("eventTime"), "action": e.get("eventName")} for e in segment]})
                first += len(segment)  # look for later episodes after this one
            else:
                first += 1
    return cases

def markdown(cases):
    lines = ["# CloudTrail Account-Aware Triage", "", "Scoring is a transparent training heuristic, not a confirmed compromise.", ""]
    for case in cases:
        lines.extend([f'## Account {case["account_id"]}', f'- Identity: {case["actor"]}',
                      f'- Severity: {case["severity"]} ({case["risk_score"]}/100)',
                      f'- Rationale: {"; ".join(case["reasons"])}', "- Timeline:"])
        for event in case["timeline"]:
            lines.append(f'  - {event["time"]}: {event["action"]}')
        lines.append("")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=ROOT / "fixtures" / "records_export.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "account_cases.json")
    parser.add_argument("--markdown", type=Path, default=ROOT / "reports" / "account_cases.md")
    args = parser.parse_args()
    cases = correlate(base.load(args.input))
    for path, payload in ((args.output, json.dumps(cases, indent=2) + "\n"), (args.markdown, markdown(cases))):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    print(f"Correlated {len(cases)} account-scoped cases")

if __name__ == "__main__":
    main()
