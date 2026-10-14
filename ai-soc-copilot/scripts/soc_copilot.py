"""Offline SSH authentication triage demo. No network or API key required."""
import argparse
import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
LOG_FILE = BASE / "logs" / "sample_bruteforce.log"
REPORT_FILE = BASE / "reports" / "incident_report.md"
# The username is attacker-controlled and may contain " from <ip> port N ssh2", so the
# source is taken from the end of the line. rsyslog folds identical lines into
# "message repeated N times: [ ... ]", which stands for N events.
EVENT = re.compile(
    r"(?:message repeated (?P<repeat>\d+) times: \[\s*)?"
    r"(?P<outcome>Failed|Accepted) password for .+ from (?P<ip>\S+) port \d+ ssh2\]?\s*$"
)


def analyze_log(log_data):
    failures, successes = Counter(), Counter()
    for line in log_data.splitlines():
        match = EVENT.search(line)
        if not match:
            continue
        try:
            ip = str(ipaddress.ip_address(match.group("ip")))
        except ValueError:
            continue
        count = int(match.group("repeat") or 1)
        if match.group("outcome") == "Failed":
            failures[ip] += count
        else:
            successes[ip] += count
    maximum = max(failures.values(), default=0)
    return {
        "failed_attempts": sum(failures.values()),
        "successful_logins": sum(successes.values()),
        "unique_ips": sorted(set(failures) | set(successes)),
        "failed_by_ip": dict(sorted(failures.items())),
        "severity": "High" if maximum >= 5 else "Medium" if maximum >= 3 else "Low",
    }


def build_report(results):
    return (
        f'# SSH Authentication Investigation\n\nGenerated (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}\n\n'
        f'## Findings\n\n- Failed attempts: {results["failed_attempts"]}\n'
        f'- Successful logins: {results["successful_logins"]}\n'
        f'- Severity (demo threshold): {results["severity"]}\n'
        f'- Failed attempts by source: {results["failed_by_ip"]}\n\n'
        '## MITRE ATT&CK\n\nT1110 Brute Force is an investigation hypothesis, not proof of compromise.\n\n'
        '## Analyst next steps\n\nCheck source ownership, account context, timestamps, and successful logins. Escalate according to policy.\n\n'
        '## Privacy\n\nThis script does not transmit raw logs to any external service. Only use authorized or synthetic input.\n'
    )


def main():
    parser = argparse.ArgumentParser(description="Offline SSH authentication triage")
    parser.add_argument("--input", type=Path, default=LOG_FILE)
    parser.add_argument("--output", type=Path, default=REPORT_FILE)
    args = parser.parse_args()
    try:
        results = analyze_log(args.input.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(results), encoding="utf-8")
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
