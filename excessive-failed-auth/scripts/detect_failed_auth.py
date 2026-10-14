"""Offline authentication correlation using an event-time sliding window."""
import argparse
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / 'sample-logs' / 'auth_timeline.txt'
OUTPUT = ROOT / 'output' / 'failed_auth_alerts.txt'

def parse_events(data):
    events = []
    for line in data.splitlines():
        fields = dict(part.strip().split(': ', 1) for part in line.split(' | ') if ': ' in part)
        if not all(k in fields for k in ('Time', 'Result', 'SourceIP', 'User')):
            continue
        try:
            ts = datetime.fromisoformat(fields['Time'].replace('Z', '+00:00'))
            ip = str(ipaddress.ip_address(fields['SourceIP']))
        except (ValueError, TypeError):
            continue
        if ts.tzinfo is None or fields['Result'] not in ('Failure', 'Success'):
            continue
        events.append((ts, ip, fields['User'], fields['Result']))
    return sorted(events)

def detect(data, threshold=5, window_minutes=5):
    recent = defaultdict(deque)
    triggered = set()
    alerts = []
    window = timedelta(minutes=window_minutes)
    for time, ip, user, result in parse_events(data):
        key = (ip, user)
        failures = recent[key]
        while failures and time - failures[0] > window:
            failures.popleft()
        if result == 'Failure':
            failures.append(time)
            if len(failures) >= threshold and key not in triggered:
                alerts.append(f'[HIGH] {threshold}+ failed logins within {window_minutes}m | SourceIP: {ip} | User: {user}')
                triggered.add(key)
        elif len(failures) >= threshold:
            alerts.append(f'[HIGH] Success following repeated failures | SourceIP: {ip} | User: {user}')
            failures.clear()
    return alerts

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, default=SAMPLE)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    alerts = detect(args.input.read_text(encoding='utf-8'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(alerts) + ('\n' if alerts else ''), encoding='utf-8')
    print(f'Generated {len(alerts)} alerts')

if __name__ == '__main__':
    main()
