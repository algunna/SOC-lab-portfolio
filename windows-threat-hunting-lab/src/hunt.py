"""Offline Windows threat hunting with normalized JSONL events."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ("-encodedcommand", "-enc ", "-executionpolicy bypass", "-windowstyle hidden")

def hunt(events):
    findings = []
    failures = defaultdict(list)
    for e in sorted(events, key=lambda x: x.get("timestamp", "")):
        eid = e.get("event_id")
        host, user, ts = (str(e.get(k, "unknown")) for k in ("host", "user", "timestamp"))
        if eid == 4688:
            image = str(e.get("image", "")).replace("/", "\\").lower().split("\\")[-1]
            cmd = str(e.get("command_line", "")).lower()
            hits = [flag for flag in FLAGS if flag in cmd]
            if image in ("powershell.exe", "pwsh.exe") and hits:
                findings.append(dict(rule="suspicious_powershell", severity="medium", host=host, user=user, timestamp=ts, evidence=hits, attack="T1059.001"))
        elif eid in (4728, 4732):
            group = str(e.get("group", "")).lower()
            if group in ("administrators", "domain admins"):
                findings.append(dict(rule="privileged_group_change", severity="high", host=host, user=user, timestamp=ts, evidence=[group], attack="T1098"))
        elif eid == 4698:
            findings.append(dict(rule="scheduled_task_created", severity="low", host=host, user=user, timestamp=ts, evidence=[str(e.get("task_name", "unnamed"))], attack="T1053.005"))
        elif eid in (4625, 4624):
            key = (host, user, str(e.get("source_ip", "")))
            try:
                now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if now.tzinfo is None:
                    continue
            except ValueError:
                continue
            failures[key] = [t for t in failures[key] if timedelta(0) <= now - t <= timedelta(minutes=5)]
            if eid == 4625:
                failures[key].append(now)
            elif len(failures[key]) >= 5:
                findings.append(dict(rule="success_after_failures", severity="high", host=host, user=user, timestamp=ts, evidence=[f"{len(failures[key])} failures in 5 minutes"], attack="T1110"))
                failures[key].clear()
    return findings

def load(path):
    rows = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"line {n} must be an object")
            rows.append(value)
    return rows

def main():
    parser = argparse.ArgumentParser(description="Offline Windows JSONL event hunting")
    parser.add_argument("--input", type=Path, default=ROOT / "fixtures" / "sample_events.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "findings.json")
    args = parser.parse_args()
    findings = hunt(load(args.input))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"count": len(findings), "findings": findings}, indent=2) + "\n", encoding="utf-8")
    print(f"Found {len(findings)} investigation leads")

if __name__ == "__main__":
    main()
