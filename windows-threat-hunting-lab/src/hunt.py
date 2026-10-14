"""Offline Windows threat hunting with normalized JSONL events."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWITCH_PREFIXES = "-/\u2013\u2014\u2015"  # PowerShell also accepts / and en/em dashes
PRIVILEGED_GROUPS = ("administrators", "domain admins", "enterprise admins", "schema admins")

def powershell_indicators(command_line):
    """Suspicious switches, allowing the abbreviations PowerShell accepts (-e, -ec, -ep, -w)."""
    tokens = str(command_line).lower().split()
    hits = []
    for index, token in enumerate(tokens):
        if token[0] not in SWITCH_PREFIXES:
            continue
        name = token[1:]
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if name in ("e", "ec") or (len(name) >= 2 and "encodedcommand".startswith(name)):
            hits.append("encoded command")
        elif (name == "ep" or (len(name) >= 2 and "executionpolicy".startswith(name))) and following == "bypass":
            hits.append("execution policy bypass")
        elif name and "windowstyle".startswith(name) and following in ("hidden", "1"):
            hits.append("hidden window")
    return sorted(set(hits))

def parse_time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None

def hunt(events):
    findings = []
    failures = defaultdict(list)
    # Sort on parsed UTC time so mixed offsets stay in order; unparseable times go last.
    latest = datetime.max.replace(tzinfo=timezone.utc)
    for e in sorted(events, key=lambda x: parse_time(x.get("timestamp")) or latest):
        try:
            eid = int(e.get("event_id"))
        except (TypeError, ValueError):
            continue
        host, user, ts = (str(e.get(k, "unknown")) for k in ("host", "user", "timestamp"))
        if eid == 4688:
            image = str(e.get("image", "")).replace("/", "\\").lower().split("\\")[-1]
            hits = powershell_indicators(e.get("command_line", ""))
            if image in ("powershell.exe", "pwsh.exe") and hits:
                findings.append(dict(rule="suspicious_powershell", severity="medium", host=host, user=user, timestamp=ts, evidence=hits, attack="T1059.001"))
        elif eid in (4728, 4732, 4756):
            group = str(e.get("group", "")).lower()
            if group in PRIVILEGED_GROUPS:
                findings.append(dict(rule="privileged_group_change", severity="high", host=host, user=user, timestamp=ts, evidence=[group], attack="T1098"))
        elif eid == 4698:
            findings.append(dict(rule="scheduled_task_created", severity="low", host=host, user=user, timestamp=ts, evidence=[str(e.get("task_name", "unnamed"))], attack="T1053.005"))
        elif eid in (4625, 4624):
            source_ip = str(e.get("source_ip", ""))
            key = (host.lower(), user.lower(), source_ip)  # Windows account names are case-insensitive
            now = parse_time(ts)
            if now is None:
                continue
            failures[key] = [t for t in failures[key] if timedelta(0) <= now - t <= timedelta(minutes=5)]
            if eid == 4625:
                failures[key].append(now)
            elif len(failures[key]) >= 5:
                findings.append(dict(rule="success_after_failures", severity="high", host=host, user=user, source_ip=source_ip, timestamp=ts, evidence=[f"{len(failures[key])} failures in 5 minutes"], attack="T1110"))
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
