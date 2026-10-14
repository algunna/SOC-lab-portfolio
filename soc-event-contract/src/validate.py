"""Offline validation for the v1 normalized alert contract."""
import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "event.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
# RFC 3339 date-time; jsonschema only enforces "format" when optional packages are installed
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

def control_characters(value, path=""):
    """Paths of string fields holding control characters. Schema patterns cannot catch a
    trailing newline, because Python's "$" also matches just before one."""
    if isinstance(value, str):
        return [path or "<root>"] if CONTROL.search(value) else []
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, list):
        items = enumerate(value)
    else:
        return []
    return [hit for key, item in items for hit in control_characters(item, f"{path}.{key}" if path else str(key))]

def validate(alert):
    errors = sorted(VALIDATOR.iter_errors(alert), key=lambda e: str(e.path))
    messages = [f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors]
    messages += [f"{path}: control characters are not allowed" for path in control_characters(alert)]
    if isinstance(alert, dict) and isinstance(alert.get("occurred_at"), str):
        value = alert["occurred_at"]
        try:
            if not RFC3339.fullmatch(value):
                raise ValueError
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            messages.append("occurred_at: must be an RFC 3339 date-time with a timezone, e.g. 2026-10-14T12:00:00Z")
    return messages

def deduplication_key(alert):
    """Stable source-event identifier scoped by source and rule."""
    source = alert["source"]
    return (source["system"], source["record_id"], alert["rule_id"])

def main():
    p = argparse.ArgumentParser(description="Validate a normalized SOC alert JSON")
    p.add_argument("path", type=Path)
    args = p.parse_args()
    try:
        alert = json.loads(args.path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        p.error(f"{args.path}: {exc}")
    problems = validate(alert)
    if problems:
        raise SystemExit("\n".join(problems))
    print("Valid SOC alert v1")

if __name__ == "__main__":
    main()
