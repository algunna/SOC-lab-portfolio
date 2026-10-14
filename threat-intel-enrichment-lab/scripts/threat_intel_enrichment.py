"""Offline IOC type classification. No reputation verdicts without external evidence."""
import argparse
import ipaddress
import re
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
IOC_FILE = ROOT / "iocs" / "sample_iocs.txt"
REPORT_FILE = ROOT / "reports" / "threat_intel_report.md"
HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def classify_ioc(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        kind = "IP address"
    except ValueError:
        if HASH.fullmatch(value):
            kind = "File hash"
        elif DOMAIN.fullmatch(value):
            kind = "Domain"
        else:
            kind = "Unrecognized"
    return {"ioc": value, "type": kind, "reputation": "Not assessed", "risk": "Unknown"}


def load_iocs(path=IOC_FILE):
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def create_report(records):
    lines = ["# IOC Classification Report", "",
             f"Generated (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "Local format classification only. No threat-feed lookups or reputation judgments were performed.", "",
             "| Indicator | Type | Reputation | Risk |", "| --- | --- | --- | --- |"]
    for item in records:
        safe = item["ioc"].replace("|", "\\|").replace("`", "")
        lines.append(f'| {safe} | {item["type"]} | {item["reputation"]} | {item["risk"]} |')
    lines += ["", "## Analyst next steps", "", "Verify source, context, provenance, and current threat intelligence before deciding whether an indicator is malicious.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Offline IOC format classification")
    parser.add_argument("--input", type=Path, default=IOC_FILE)
    parser.add_argument("--output", type=Path, default=REPORT_FILE)
    args = parser.parse_args()
    try:
        records = [classify_ioc(value) for value in load_iocs(args.input)]
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(create_report(records), encoding="utf-8")
    print(f"Classified {len(records)} IOCs. Report: {args.output}")


if __name__ == "__main__":
    main()
