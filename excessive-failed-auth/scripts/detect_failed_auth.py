"""Flag sources with repeated failed logins, and any success that follows them."""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_FILE = BASE / "sample-logs" / "auth_timeline.txt"
DEFAULT_OUTPUT_FILE = BASE / "output" / "failed_auth_alerts.txt"

FAIL_THRESHOLD = 5
WINDOW_SECONDS = 300


def parse_line(line):
    """Split 'Key: value | Key: value' into a dict."""
    fields = {}
    for part in line.split(" | "):
        key, sep, value = part.partition(": ")
        if sep:
            if key.strip() in fields:
                return {}  # Ambiguous duplicate fields cannot establish identity.
            fields[key.strip()] = value.strip()
    return fields


def normalized_event(line):
    event = parse_line(line.strip())
    if event.get('Result') not in ('Failure', 'Success'):
        return None
    for field in ('SourceIP', 'User', 'Event', 'Time'):
        value = event.get(field)
        if not value or value.lower() in ('unknown', 'n/a', '-') or any(ord(c) < 32 for c in value):
            return None
    try:
        occurred = datetime.fromisoformat(event['Time'].replace('Z', '+00:00'))
        if occurred.utcoffset() is None:
            return None
        occurred = occurred.astimezone(timezone.utc)
        source = str(ipaddress.ip_address(event['SourceIP']))
    except (ValueError, OverflowError):
        return None
    # Account and event names are case-sensitive in this generic format; Windows
    # account normalization remains the responsibility of the Windows-specific lab.
    key = (source, event['User'], event['Event'])
    return occurred, key, event


def detect_failed_auth(lines, threshold=FAIL_THRESHOLD, window_seconds=WINDOW_SECONDS):
    if type(threshold) is not int or not 1 <= threshold <= 10000:
        raise ValueError('Threshold must be an integer from 1 to 10000')
    if type(window_seconds) is not int or not 1 <= window_seconds <= 3600:
        raise ValueError('Window must be an integer from 1 to 3600 seconds')
    failures, alerts = {}, []
    events = [event for line in lines if (event := normalized_event(line)) is not None]
    # Stable ordering retains input order for equal timestamps; no invented order.
    for now, key, event in sorted(events, key=lambda item: item[0]):
        ip, user, _ = key
        seen = failures.setdefault(key, [])
        seen[:] = [(time, raw) for time, raw in seen
                   if timedelta(0) <= now - time <= timedelta(seconds=window_seconds)]
        if event['Result'] == 'Failure':
            seen.append((now, event['Time']))
            if len(seen) == threshold:
                alerts.append(
                    f"[HIGH] Excessive failed authentication attempts | SourceIP: {ip} | "
                    f"Failures: {len(seen)} | First: {seen[0][1]} | Last: {seen[-1][1]} | Users: {user}"
                )
        else:
            if len(seen) >= threshold:
                alerts.append(
                    f"[CRITICAL] Successful login after {len(seen)} failures | SourceIP: {ip} | "
                    f"Time: {event['Time']} | User: {user}"
                )
            # Any matching success ends the failure sequence, including one below
            # threshold. It is not evidence that an account was compromised.
            seen.clear()
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
