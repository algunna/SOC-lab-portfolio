"""Flag sources with repeated failed logins, and any success that follows them."""
import argparse
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_FILE = BASE / "sample-logs" / "auth_timeline.txt"
DEFAULT_OUTPUT_FILE = BASE / "output" / "failed_auth_alerts.txt"

FAIL_THRESHOLD = 5


def parse_line(line):
    """Split 'Key: value | Key: value' into a dict."""
    fields = {}
    for part in line.split(" | "):
        key, sep, value = part.partition(": ")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def detect_failed_auth(lines, threshold=FAIL_THRESHOLD):
    failures = {}
    alerts = []

    for line in lines:
        event = parse_line(line.strip())
        ip = event.get("SourceIP")
        result = event.get("Result")
        if not ip or result not in ("Failure", "Success"):
            continue

        seen = failures.setdefault(ip, [])
        if result == "Failure":
            seen.append((event.get("Time", "N/A"), event.get("User", "N/A")))
            if len(seen) == threshold:
                users = ", ".join(sorted({user for _, user in seen}))
                alerts.append(
                    f"[HIGH] Excessive failed authentication attempts | SourceIP: {ip} | "
                    f"Failures: {len(seen)} | First: {seen[0][0]} | Last: {seen[-1][0]} | Users: {users}"
                )
        elif len(seen) >= threshold:
            # The event that matters most: the guessing may have worked
            alerts.append(
                f"[CRITICAL] Successful login after {len(seen)} failures | SourceIP: {ip} | "
                f"Time: {event.get('Time', 'N/A')} | User: {event.get('User', 'N/A')}"
            )

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Detect excessive failed authentication")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_FILE)
    args = parser.parse_args()

    try:
        alerts = detect_failed_auth(args.input.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"{args.input}: {exc}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(alert + "\n" for alert in alerts), encoding="utf-8")

    print(f"Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
