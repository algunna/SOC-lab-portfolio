from pathlib import Path
from datetime import datetime

INPUT_FILE = Path("output/cloudtrail_alerts.txt")
OUTPUT_FILE = Path("output/cloudtrail_incidents.txt")

def parse_time(line):
    try:
        time_part = line.split("Time:")[1].split("|")[0].strip()
        return datetime.fromisoformat(time_part.replace("Z", ""))
    except Exception:
        return None

def correlate_incidents():
    incidents = {}
    incident_id = 1

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            severity = line.split("]")[0].replace("[", "")

            if "Root activity" in line:
                key = "ROOT_ACTIVITY"
            elif "IAM configuration change" in line:
                key = "IAM_CHANGE"
            elif "Role assumption" in line:
                key = "ASSUME_ROLE"
            else:
                key = "OTHER"

            if key not in incidents:
                incidents[key] = {
                    "id": f"INC-{incident_id:03}",
                    "severity": severity,
                    "alerts": [],
                    "times": []
                }
                incident_id += 1

            incidents[key]["alerts"].append(line)

            event_time = parse_time(line)
            if event_time:
                incidents[key]["times"].append(event_time)

    return incidents

def write_incidents(incidents):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for incident in incidents.values():
            start = min(incident["times"]) if incident["times"] else "N/A"
            end = max(incident["times"]) if incident["times"] else "N/A"

            f.write(f"{incident['id']} | Severity: {incident['severity']}\n")
            f.write(f"Time Window: {start} -> {end}\n")
            f.write("Related Alerts:\n")

            for alert in incident["alerts"]:
                f.write(f"  - {alert}\n")

            f.write("\n")

def main():
    incidents = correlate_incidents()
    write_incidents(incidents)
    print(f"Generated {len(incidents)} incidents")

if __name__ == "__main__":
    main()
