"""Flag events whose source is an external (public) IP address, for analyst review."""
import argparse
import ipaddress
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_FILE = BASE / "sample-logs" / "cloudtrail_timeline.txt"
DEFAULT_OUTPUT_FILE = BASE / "output" / "ip_obfuscation_alerts.txt"


def extract_source_ip(line):
    if "SourceIP:" not in line:
        return None

    return line.split("SourceIP:")[1].split("|")[0].strip()


def is_external_ip(value):
    """True for a public IPv4/IPv6 address; False for private, reserved or non-IP sources."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False  # e.g. "AWS Internal" or a service hostname
    return ip.is_global


def detect_ip_obfuscation(lines):
    alerts = []

    for line in lines:
        line = line.strip()
        ip = extract_source_ip(line)

        if ip and is_external_ip(ip):
            alerts.append(
                "[MEDIUM] Suspicious public IP source | "
                + line
            )

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Flag external source IPs in a CloudTrail timeline")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE)
    args = parser.parse_args()

    try:
        alerts = detect_ip_obfuscation(args.input.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(alert + "\n" for alert in alerts), encoding="utf-8")

    print(f"Generated {len(alerts)} IP obfuscation alerts")


if __name__ == "__main__":
    main()
