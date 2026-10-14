"""Offline AWS CloudTrail JSONL threat hunting, no AWS access required."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IAM_CHANGES = {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
               "CreateAccessKey", "UpdateAssumeRolePolicy", "AddUserToGroup"}
LOGGING_CHANGES = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}

def hunt(events):
    findings = []
    for e in events:
        name = str(e.get("eventName", ""))
        identity = e.get("userIdentity") or {}
        kind = identity.get("type", "")
        source = str(e.get("sourceIPAddress", "unknown"))
        time = str(e.get("eventTime", "unknown"))
        if e.get("errorCode"):
            continue  # denied calls are not completed administrative changes
        observations = []
        if kind == "Root":
            observations.append(("root_account_activity", "high", "T1078.004"))
        if name in IAM_CHANGES:
            observations.append(("iam_permission_or_identity_change", "medium", "T1098"))
        if name in LOGGING_CHANGES:
            observations.append(("logging_configuration_change", "high", "T1562.008"))
        if name == "AssumeRole":
            observations.append(("role_assumption_review", "low", "T1078.004"))
        for rule, severity, attack in observations:
            findings.append({"rule": rule, "severity": severity, "event_name": name,
                             "time": time, "source_ip": source, "identity_type": kind,
                             "attack_hypothesis": attack})
    return findings

def load(path):
    result = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"JSONL line {number} must be an object")
        result.append(value)
    return result

def main():
    p = argparse.ArgumentParser(description="Offline CloudTrail hunting lab")
    p.add_argument("--input", type=Path, default=ROOT / "fixtures" / "events.jsonl")
    p.add_argument("--output", type=Path, default=ROOT / "reports" / "findings.json")
    a = p.parse_args()
    findings = hunt(load(a.input))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps({"count": len(findings), "findings": findings}, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(findings)} investigation leads")

if __name__ == "__main__":
    main()
