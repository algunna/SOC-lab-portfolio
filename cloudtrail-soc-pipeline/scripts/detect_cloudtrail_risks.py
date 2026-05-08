INPUT_FILE = "output/cloudtrail_timeline.txt"
OUTPUT_FILE = "output/cloudtrail_alerts.txt"

MITRE_MAP = {
    "ROOT_ACTIVITY": {
        "severity": "HIGH",
        "technique": "T1078",
        "name": "Valid Accounts"
    },
    "IAM_CHANGE": {
        "severity": "HIGH",
        "technique": "T1098",
        "name": "Account Manipulation"
    },
    "ASSUME_ROLE": {
        "severity": "MEDIUM",
        "technique": "T1078.004",
        "name": "Cloud Accounts"
    }
}

ANALYST_GUIDANCE = {
    "CRITICAL": (
        "Immediate response required. "
        "Verify MFA on root, rotate credentials if applicable, "
        "review recent CloudTrail activity, and restrict root usage to break-glass only."
    ),
    "HIGH": (
        "Review activity context. "
        "Validate change approval, confirm actor legitimacy, "
        "and check for related IAM or privilege changes."
    ),
    "MEDIUM": (
        "Monitor and validate. "
        "Ensure role trust policy is expected and usage aligns with known services."
    )
}


def classify_source_ip(line):
    if "AWS Internal" in line:
        return "aws_internal"

    if ".amazonaws.com" in line:
        return "aws_service"

    if "SourceIP:" in line:
        ip = line.split("SourceIP:")[1].split("|")[0].strip()
        if ip.count(".") == 3:
            return "public_ip"

    return "unknown"


def detect_cloudtrail_risks():
    alerts = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if "UserType: Root" in line:
                meta = MITRE_MAP["ROOT_ACTIVITY"]
                alerts.append(
                    f"[{meta['severity']}] Root account activity | "
                    f"MITRE {meta['technique']} {meta['name']} | {line}"
                )

            if "CreateServiceLinkedRole" in line:
                meta = MITRE_MAP["IAM_CHANGE"]
                alerts.append(
                    f"[{meta['severity']}] IAM configuration change | "
                    f"MITRE {meta['technique']} {meta['name']} | {line}"
                )

            if "AssumeRole" in line:
                meta = MITRE_MAP["ASSUME_ROLE"]
                alerts.append(
                    f"[{meta['severity']}] Role assumption detected | "
                    f"MITRE {meta['technique']} {meta['name']} | {line}"
                )

    return alerts


def detect_root_from_public_ip():
    alerts = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if "UserType: Root" in line:
                source_type = classify_source_ip(line)

                if source_type == "public_ip":
                    alerts.append(
                        "[CRITICAL] Root activity from public IP | "
                        "MITRE T1078 Valid Accounts | "
                        + line
                    )

    return alerts


def suppress_duplicate_root_alerts(alerts):
    critical_events = set()

    for alert in alerts:
        if alert.startswith("[CRITICAL]"):
            critical_events.add(alert.split("| Time:")[1].strip())

    deduped_alerts = []

    for alert in alerts:
        if alert.startswith("[HIGH] Root"):
            event_key = alert.split("| Time:")[1].strip()
            if event_key in critical_events:
                continue
        deduped_alerts.append(alert)

    return deduped_alerts


def enrich_alerts_with_guidance(alerts):
    enriched_alerts = []

    for alert in alerts:
        if alert.startswith("[CRITICAL]"):
            guidance = ANALYST_GUIDANCE["CRITICAL"]
        elif alert.startswith("[HIGH]"):
            guidance = ANALYST_GUIDANCE["HIGH"]
        elif alert.startswith("[MEDIUM]"):
            guidance = ANALYST_GUIDANCE["MEDIUM"]
        else:
            guidance = "Review event context."

        enriched_alerts.append(f"{alert} | AnalystAction: {guidance}")

    return enriched_alerts


def main():
    alerts = []

    alerts.extend(detect_cloudtrail_risks())
    alerts.extend(detect_root_from_public_ip())

    alerts = suppress_duplicate_root_alerts(alerts)
    alerts = enrich_alerts_with_guidance(alerts)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(alert + "\n")

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()


