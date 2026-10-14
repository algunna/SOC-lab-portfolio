"""Offline mapping of *pre-classified synthetic* Splunk alert rows to SOC Event Contract v1.

This is deliberately NOT a raw Splunk event detector, search client, or live feed.
The input has a tiny, explicitly allowlisted field set; any raw or unexpected
columns cause a fail-closed error. Nothing is written until the whole batch validates.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("splunk_soc_contract", ROOT / "soc-event-contract" / "src" / "validate.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

# Detector claims and severities are determined locally, NEVER by untrusted source rows.
RULES = {
    "windows_encoded_powershell": ("windows", "windows.powershell.encoded", "medium",
                                   "Encoded PowerShell command observed", ["T1059.001"]),
    "auth_failed_login_burst": ("authentication", "authentication.failed.login.burst", "high",
                                "Repeated authentication failures observed", ["T1110"]),
    "aws_cloudtrail_logging_change": ("aws_cloudtrail", "aws.logging.change", "high",
                                      "CloudTrail logging configuration change", ["T1562.008"]),
}
REQUIRED = {"search_name", "record_id", "occurred_at"}
ALLOWED = REQUIRED | {"actor", "asset"}
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9_.:@/\\\\-]{1,256}\Z")
MAX_ROWS = 200
MAX_BYTES = 1_000_000
MAX_LINE_BYTES = 4096


def no_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON field")
        obj[key] = value
    return obj


def to_alert(row):
    if not isinstance(row, dict) or set(row) - ALLOWED or not REQUIRED.issubset(row):
        raise ValueError("Expected only allowlisted synthetic saved-search alert fields")
    rule = RULES.get(row["search_name"]) if isinstance(row["search_name"], str) else None
    if rule is None:
        raise ValueError("Unknown search name: no detection claim can be inferred")
    record_id = row["record_id"]
    if not isinstance(record_id, str) or not IDENTIFIER.fullmatch(record_id):
        raise ValueError("Invalid record ID")
    for key in ("actor", "asset"):
        if key in row and (not isinstance(row[key], str) or not IDENTITY.fullmatch(row[key])):
            raise ValueError("Invalid analyst-visible identity field")
    system, rule_id, severity, title, techniques = rule
    fingerprint = hashlib.sha256(
        json.dumps([system, record_id, rule_id], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    alert = {
        "schema_version": "1.0",
        "event_id": "splunk-" + fingerprint[:24],
        "occurred_at": row["occurred_at"],
        "source": {"system": system, "record_id": record_id},
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "attack_techniques": techniques,
        "evidence": [{
            "reference": "splunk-synthetic:" + fingerprint[:32],
            "description": "Synthetic saved-search alert; origin and detection need analyst verification",
        }],
    }
    for key in ("actor", "asset"):
        if key in row:
            alert[key] = row[key]
    if contract.validate(alert):
        raise ValueError("Generated alert does not satisfy SOC Event Contract v1")
    return alert


def transform_jsonl(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Input must be bounded UTF-8 JSONL bytes")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Input is not UTF-8") from exc
    alerts, seen = [], set()
    for line in lines:
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_LINE_BYTES or len(alerts) >= MAX_ROWS:
            raise ValueError("Input has too many rows or overly long rows")
        try:
            row = json.loads(line, object_pairs_hook=no_duplicate_json_keys)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSONL row") from exc
        alert = to_alert(row)
        identity = (alert["source"]["system"], alert["event_id"])
        if identity in seen:
            raise ValueError("Duplicate saved-search alert identity")
        seen.add(identity)
        alerts.append(alert)
    if not alerts:
        raise ValueError("No synthetic alert rows provided")
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic Splunk saved-search alert normalizer")
    parser.add_argument("input", type=Path, help="Trusted synthetic allowlisted JSONL; NOT raw Splunk events")
    parser.add_argument("--out", required=True, type=Path, help="New normalized JSONL output; refuses overwrite")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Refusing to overwrite existing output")
    try:
        raw = args.input.read_bytes()
        alerts = transform_jsonl(raw)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        # Output contains only fields validated by SOC Event Contract.
        with args.out.open("x", encoding="utf-8") as destination:
            for alert in alerts:
                destination.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=True) + "\n")
    except (OSError, ValueError) as exc:
        parser.error(f"Normalization failed ({type(exc).__name__}); inspect synthetic input and schema")
    print(f"Normalized {len(alerts)} synthetic saved-search alerts; no live SIEM queried")


if __name__ == "__main__":
    main()
