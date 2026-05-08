INPUT_FILE = "sample-logs/auth_timeline.txt"
OUTPUT_FILE = "output/failed_auth_alerts.txt"

FAIL_THRESHOLD = 5

def detect_failed_auth():
    failures = {}
    alerts = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if "Result: Failure" not in line:
                continue

            ip = line.split("SourceIP:")[1].strip()
            failures[ip] = failures.get(ip, 0) + 1

            if failures[ip] == FAIL_THRESHOLD:
                alerts.append(
                    f"[HIGH] Excessive failed authentication attempts | SourceIP: {ip}"
                )

    return alerts

def main():
    alerts = detect_failed_auth()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(alert + "\n")

    print(f"Generated {len(alerts)} alerts")

if __name__ == "__main__":
    main()
