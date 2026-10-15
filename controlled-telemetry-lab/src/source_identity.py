"""Controlled synthetic telemetry source identity projections for future SIEM mapping.

This module never authenticates a source, queries a SIEM, or asserts detections.
Only fixed lab-fixture structure is accepted; output references are opaque hashes.
"""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "controlled-telemetry-lab/fixtures/synthetic_sources.json"
MAX_BYTES = 100_000
MAX_ROWS = 40
TEXT = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-\d\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})\Z")
FIELDS = {"kind", "namespace", "occurred_at", "received_at"}
NAMESPACES = {
    "windows": {"host", "channel", "log_epoch", "record_id"},
    "cloudtrail": {"account_id", "region", "event_id"},
}
# Times are diagnostic metadata, never proof of clock accuracy.
FUTURE_TOLERANCE_SECONDS = 300
LATE_THRESHOLD_SECONDS = 900


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def no_constant(_):
    raise ValueError("Non-finite JSON number")


def timestamp(text):
    if not isinstance(text, str) or not RFC3339.fullmatch(text):
        raise ValueError("Timestamp must be RFC3339 with an explicit timezone")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Impossible timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError("Naive timestamp")
    return parsed.astimezone(timezone.utc)


def strict_string(value, pattern):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError("Invalid source namespace identifier")
    return value


def namespace_parts(row):
    if not isinstance(row, dict) or set(row) != FIELDS:
        raise ValueError("Unknown or missing synthetic source fields")
    kind = row.get("kind")
    if type(kind) is not str or kind not in NAMESPACES:
        raise ValueError("Unsupported synthetic source kind")
    ns = row.get("namespace")
    if not isinstance(ns, dict) or set(ns) != NAMESPACES[kind]:
        raise ValueError("Ambiguous source namespace")
    if kind == "windows":
        host = strict_string(ns["host"], TEXT).lower()
        channel = strict_string(ns["channel"], TEXT).lower()
        epoch = strict_string(ns["log_epoch"], UUID)
        record = strict_string(ns["record_id"], TEXT)
        # A log_epoch is a lab-defined generation ID, not a real Windows field.
        parts = ["windows", host, channel, epoch, record]
        system = "windows"
    else:
        account = ns["account_id"]
        if type(account) is not str or not re.fullmatch(r"[0-9]{12}", account):
            raise ValueError("Invalid AWS sandbox account ID")
        region = strict_string(ns["region"], REGION)
        event = strict_string(ns["event_id"], UUID)
        parts = ["aws_cloudtrail", account, region, event]
        system = "aws_cloudtrail"
    return system, parts


def project(row):
    system, parts = namespace_parts(row)
    occurred = timestamp(row["occurred_at"])
    received = timestamp(row["received_at"])
    age_seconds = (received - occurred).total_seconds()
    clock_classification = ("future_event_time" if age_seconds < -FUTURE_TOLERANCE_SECONDS
                            else "delayed_arrival" if age_seconds > LATE_THRESHOLD_SECONDS
                            else "within_lab_window")
    # Opaque hash only: it still does not anonymize guessable input identifiers.
    digest = hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "source": {"system": system, "record_id": "lab-src-" + digest[:48]},
        "occurred_at": occurred.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "evidence_reference": "synthetic-source:" + digest[:48],
        "clock_review": clock_classification,
        "provenance": "unauthenticated_synthetic_fixture",
    }


def evaluate(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError("Invalid fixture byte length")
    source = json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys,
                        parse_constant=no_constant)
    if (not isinstance(source, dict) or set(source) != {"schema_version", "scope", "records"} or
        source["schema_version"] != "1.0" or source["scope"] != "synthetic_only" or
        not isinstance(source["records"], list) or
        not 1 <= len(source["records"]) <= MAX_ROWS):
        raise ValueError("Invalid controlled source fixture")
    items, seen, clocks = [], set(), {"within_lab_window": 0, "delayed_arrival": 0, "future_event_time": 0}
    for row in source["records"]:
        item = project(row)
        key = (item["source"]["system"], item["source"]["record_id"])
        if key in seen:
            raise ValueError("Duplicate scoped source observation")
        seen.add(key)
        clocks[item["clock_review"]] += 1
        items.append(item)
    return {"schema_version": "1.0", "scope": "unauthenticated_synthetic_only",
            "live_provenance_verified": False, "records": items, "clock_counts": clocks}


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic source namespace and clock preflight")
    parser.add_argument("--out", required=True, type=Path, help="New summary report; no overwrite")
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        parser.error("Refusing to overwrite existing output")
    try:
        report = evaluate(FIXTURE.read_bytes())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        parser.error("Synthetic source preflight refused (" + type(exc).__name__ + ")")
    print("Validated {} synthetic scoped records; live provenance NOT verified".format(len(report["records"])))


if __name__ == "__main__":
    main()
