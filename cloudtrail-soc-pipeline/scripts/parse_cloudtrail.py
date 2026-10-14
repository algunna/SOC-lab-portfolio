"""Parse CloudTrail JSON exports into a chronological, one-line-per-event timeline."""
import argparse
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_DIR = BASE / "fixtures"
DEFAULT_OUTPUT_FILE = BASE / "output" / "cloudtrail_timeline.txt"


def clean(value):
    """Keep attacker-controlled field values from breaking the ' | ' line format."""
    return str(value).replace("|", "/").replace("\r", " ").replace("\n", " ").strip() or "N/A"


def format_event(record):
    identity = record.get("userIdentity")
    if not isinstance(identity, dict):
        identity = {}
    return (
        f"Time: {clean(record.get('eventTime', 'N/A'))} | "
        f"Event: {clean(record.get('eventName', 'N/A'))} | "
        f"UserType: {clean(identity.get('type', 'Unknown'))} | "
        f"SourceIP: {clean(record.get('sourceIPAddress', 'N/A'))} | "
        f"Region: {clean(record.get('awsRegion', 'N/A'))}"
    )


def extract_events(input_dir):
    events = []

    for file in sorted(Path(input_dir).glob("*.json")):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"Skipping {file.name}: {exc}", file=sys.stderr)
            continue

        records = data.get("Records", []) if isinstance(data, dict) else []
        if not isinstance(records, list):
            records = []
        records = [record for record in records if isinstance(record, dict)]

        print(f"Found {len(records)} records in {file.name}")

        for record in records:
            events.append((str(record.get("eventTime", "")), format_event(record)))

    # ISO 8601 UTC timestamps sort correctly as strings.
    return [line for _, line in sorted(events, key=lambda event: event[0])]


def main():
    parser = argparse.ArgumentParser(description="Parse CloudTrail JSON exports into a timeline")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE)
    args = parser.parse_args()

    timeline = extract_events(args.input_dir)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(entry + "\n" for entry in timeline), encoding="utf-8")

    print(f"Extracted {len(timeline)} events to {args.output}")


if __name__ == "__main__":
    main()
