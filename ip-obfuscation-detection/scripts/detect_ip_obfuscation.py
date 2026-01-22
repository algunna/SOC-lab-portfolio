INPUT_FILE = "sample-logs/cloudtrail_timeline.txt"
OUTPUT_FILE = "output/ip_obfuscation_alerts.txt"


def extract_source_ip(line):
    if "SourceIP:" not in line:
        return None

    return line.split("SourceIP:")[1].split("|")[0].strip()


def is_private_ip(ip):
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
    )


def detect_ip_obfuscation():
    alerts = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            ip = extract_source_ip(line)

            if not ip:
                continue

            if ip.count(".") == 3 and not is_private_ip(ip):
                alerts.append(
                    "[MEDIUM] Suspicious public IP source | "
                    + line
                )

    return alerts


def main():
    alerts = detect_ip_obfuscation()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(alert + "\n")

    print(f"Generated {len(alerts)} IP obfuscation alerts")


if __name__ == "__main__":
    main()
