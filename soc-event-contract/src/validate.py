"""Offline validation for the v1 normalized alert contract."""
import argparse
import json
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "event.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

def validate(alert):
    errors = sorted(VALIDATOR.iter_errors(alert), key=lambda e: str(e.path))
    messages = [f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors]
    if isinstance(alert, dict) and isinstance(alert.get("occurred_at"), str):
        try:
            parsed = datetime.fromisoformat(alert["occurred_at"].replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                messages.append("occurred_at: timezone offset required")
        except ValueError:
            messages.append("occurred_at: invalid ISO 8601 datetime")
    return messages

def deduplication_key(alert):
    """Stable source-event identifier scoped by source and rule."""
    source = alert["source"]
    return (source["system"], source["record_id"], alert["rule_id"])

def main():
    p = argparse.ArgumentParser(description="Validate a normalized SOC alert JSON")
    p.add_argument("path", type=Path)
    args = p.parse_args()
    alert = json.loads(args.path.read_text(encoding="utf-8"))
    problems = validate(alert)
    if problems:
        raise SystemExit("\n".join(problems))
    print("Valid SOC alert v1")

if __name__ == "__main__":
    main()
