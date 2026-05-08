import json
from pathlib import Path

INPUT_DIR = Path("sample-logs")
OUTPUT_FILE = Path("output/cloudtrail_timeline.txt")


def extract_events():
    events = []

    for file in INPUT_DIR.glob("*.json"):
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        records = data.get("Records", [])

        print(f"Found {len(records)} records in {file.name}")

        for record in records:
            event_time = record.get("eventTime", "N/A")
            event_name = record.get("eventName", "N/A")
            user_type = record.get("userIdentity", {}).get("type", "Unknown")
            source_ip = record.get("sourceIPAddress", "N/A")
            region = record.get("awsRegion", "N/A")

            line = (
                f"Time: {event_time} | "
                f"Event: {event_name} | "
                f"UserType: {user_type} | "
                f"SourceIP: {source_ip} | "
                f"Region: {region}"
            )

            events.append(line)

    return events

def main():
    timeline = extract_events()

    OUTPUT_FILE.parent.mkdir(exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for entry in timeline:
            f.write(entry + "\n")

    print(f"Extracted {len(timeline)} events to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
