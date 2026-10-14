"""Rule-based detections over the parsed CloudTrail timeline."""
import argparse
import ipaddress
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_FILE = BASE / "output" / "cloudtrail_timeline.txt"
DEFAULT_OUTPUT_FILE = BASE / "output" / "cloudtrail_alerts.txt"

# rule id: (severity, incident category, title, MITRE ATT&CK hypothesis)
RULES = {
    "ROOT_PUBLIC_IP": ("CRITICAL", "ROOT_ACTIVITY", "Root activity from public IP", "T1078.004 Valid Accounts: Cloud Accounts"),
    "ROOT_ACTIVITY": ("HIGH", "ROOT_ACTIVITY", "Root account activity", "T1078.004 Valid Accounts: Cloud Accounts"),
    "IAM_CHANGE": ("HIGH", "IAM_CHANGE", "IAM permission or credential change", "T1098 Account Manipulation"),
    "SERVICE_LINKED_ROLE": ("MEDIUM", "IAM_CHANGE", "Service-linked role created", "T1098 Account Manipulation"),
    "LOGGING_TAMPER": ("HIGH", "LOGGING_TAMPER", "CloudTrail logging changed", "T1562.008 Impair Defenses: Disable or Modify Cloud Logs"),
    "ASSUME_ROLE": ("MEDIUM", "ASSUME_ROLE", "Role assumption", "T1078.004 Valid Accounts: Cloud Accounts"),
}

IAM_CHANGE_EVENTS = {
    "CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "CreateAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "CreateRole", "UpdateAssumeRolePolicy", "AddUserToGroup",
    "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary", "DeleteRolePermissionsBoundary",
    "DeactivateMFADevice",
}
LOGGING_TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                         "StopEventDataStoreIngestion", "DeleteEventDataStore"}
ROLE_ASSUMPTION_EVENTS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
                          "AssumeRoot", "GetFederationToken"}

# Addresses treated as non-public. Everything else that parses as an IP is public.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]

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
    ),
}


def parse_timeline_line(line):
    """Split 'Key: value | Key: value' into a dict."""
    fields = {}
    for part in line.split(" | "):
        key, sep, value = part.partition(": ")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def classify_source_ip(source):
    if source == "AWS Internal":
        return "aws_internal"

    if source.endswith(".amazonaws.com"):
        return "aws_service"

    try:
        ip = ipaddress.ip_address(source)
    except ValueError:
        return "unknown"
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:10.1.2.3 is the IPv4 address 10.1.2.3

    if any(ip in network for network in INTERNAL_NETWORKS):
        return "internal_ip"

    return "public_ip"


def match_rules(event):
    """Return the rule ids triggered by one parsed timeline event."""
    rule_ids = []
    event_name = event.get("Event", "")

    if event.get("UserType") == "Root":
        if classify_source_ip(event.get("SourceIP", "")) == "public_ip":
            rule_ids.append("ROOT_PUBLIC_IP")
        else:
            rule_ids.append("ROOT_ACTIVITY")

    if event_name == "CreateServiceLinkedRole":
        rule_ids.append("SERVICE_LINKED_ROLE")
    elif event_name in IAM_CHANGE_EVENTS:
        rule_ids.append("IAM_CHANGE")

    if event_name in LOGGING_TAMPER_EVENTS:
        rule_ids.append("LOGGING_TAMPER")

    if event_name in ROLE_ASSUMPTION_EVENTS:
        rule_ids.append("ASSUME_ROLE")

    return rule_ids


def format_alert(rule_id, line):
    severity, category, title, technique = RULES[rule_id]
    return (
        f"[{severity}] {category} {title} | MITRE {technique} | {line} | "
        f"AnalystAction: {ANALYST_GUIDANCE[severity]}"
    )


def detect_cloudtrail_risks(lines):
    alerts = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        for rule_id in match_rules(parse_timeline_line(line)):
            alerts.append(format_alert(rule_id, line))

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Detect risky CloudTrail activity in a parsed timeline")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE)
    args = parser.parse_args()

    try:
        alerts = detect_cloudtrail_risks(args.input.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(alert + "\n" for alert in alerts), encoding="utf-8")

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
