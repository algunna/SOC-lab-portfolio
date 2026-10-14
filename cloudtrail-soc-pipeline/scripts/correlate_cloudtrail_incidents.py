"""Group CloudTrail alerts into one incident per alert category."""
import argparse
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_FILE = BASE / "output" / "cloudtrail_alerts.txt"
DEFAULT_OUTPUT_FILE = BASE / "output" / "cloudtrail_incidents.txt"

SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def parse_time(line):
    try:
        time_part = line.split("Time:")[1].split("|")[0].strip()
        parsed = datetime.fromisoformat(time_part.replace("Z", "+00:00"))
    except (IndexError, ValueError):
        return None
    # Normalize so Z, +00:00 and other offsets compare correctly
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_alert(line):
    """Return (severity, category) from '[SEVERITY] CATEGORY title | ...'."""
    severity, sep, rest = line[1:].partition("] ")
    if not line.startswith("[") or not sep:
        return None
    return severity, rest.split(" ", 1)[0] or "OTHER"


def correlate_incidents(lines):
    incidents = {}

    for line in lines:
        line = line.strip()
        parsed = parse_alert(line)
        if parsed is None:
            continue
        severity, category = parsed

        if category not in incidents:
            incidents[category] = {
                "id": f"INC-{len(incidents) + 1:03}",
                "category": category,
                "severity": severity,
                "alerts": [],
                "times": [],
            }
        incident = incidents[category]

        # An incident is as severe as its most severe alert.
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(incident["severity"], 0):
            incident["severity"] = severity

        incident["alerts"].append(line)

        event_time = parse_time(line)
        if event_time:
            incident["times"].append(event_time)

    return incidents


def format_incidents(incidents):
    lines = []
    for incident in incidents.values():
        start = min(incident["times"]).isoformat() if incident["times"] else "N/A"
        end = max(incident["times"]).isoformat() if incident["times"] else "N/A"

        lines.append(f"{incident['id']} | {incident['category']} | Severity: {incident['severity']}")
        lines.append(f"Time Window: {start} -> {end}")
        lines.append("Related Alerts:")
        lines.extend(f"  - {alert}" for alert in incident["alerts"])
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Group CloudTrail alerts into incidents")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE)
    args = parser.parse_args()

    try:
        incidents = correlate_incidents(args.input.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(format_incidents(incidents), encoding="utf-8")

    print(f"Generated {len(incidents)} incidents")


if __name__ == "__main__":
    main()
