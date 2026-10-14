"""Offline bounded grouping of validated SOC alerts into unverified candidates."""
import argparse
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("soc_contract", ROOT / "soc-event-contract" / "src" / "validate.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
DEFAULT_WINDOW_MINUTES = 15

def group_alerts(report, window_minutes=DEFAULT_WINDOW_MINUTES):
    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or not (1 <= window_minutes <= 1440):
        raise ValueError("Window must be an integer between 1 and 1440 minutes")
    if not isinstance(report, dict) or not isinstance(report.get("accepted"), list):
        raise ValueError("Expected ingestion report with accepted array")
    if report.get("rejected"):
        raise ValueError("Refusing report containing rejected records")
    observations = []
    identities = set()
    for event in report["accepted"]:
        errors = contract.validate(event)
        if errors:
            raise ValueError("Invalid accepted alert: schema validation failed")
        identifier = (event["source"]["system"], event["event_id"])
        if identifier in identities:
            raise ValueError("Duplicate source/event ID in accepted input")
        identities.add(identifier)
        instant = datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        actor, asset = event.get("actor"), event.get("asset")
        if not actor or not actor.strip() or not asset or not asset.strip():
            key = None
        else:
            key = (event["source"]["system"], actor, asset)
        observations.append((instant, event["event_id"], identifier, key, event))
    observations.sort(key=lambda item: (item[0], item[2]))
    buckets = []
    active = {}
    window = timedelta(minutes=window_minutes)
    for instant, _, identity, key, event in observations:
        if key is None:
            bucket = {"key": ["isolated", *identity], "start": instant, "events": [],
                      "reason": "isolated: actor or asset missing"}
            buckets.append(bucket)
        else:
            bucket = active.get(key)
            if bucket is None or instant - bucket["start"] > window:
                bucket = {"key": list(key), "start": instant, "events": [],
                          "reason": f"same source, actor and asset within {window_minutes}-minute fixed window; no causal link established"}
                buckets.append(bucket)
                active[key] = bucket
        bucket["events"].append(event)
    candidates = []
    for bucket in buckets:
        events = bucket["events"]
        basis = json.dumps([bucket["key"], [(e["source"]["record_id"], e["event_id"]) for e in events]],
                           separators=(",", ":"), ensure_ascii=True)
        identifier = "candidate-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
        candidates.append({
            "candidate_id": identifier, "classification": "unverified",
            "reason": bucket["reason"], "alert_ids": [e["event_id"] for e in events],
            "event_count": len(events),
            "evidence_references": sorted({item["reference"] for e in events for item in e["evidence"]})
        })
    return {"version": "0.2", "window_minutes": window_minutes,
            "incident_candidates": candidates, "counts": {"candidates": len(candidates), "alerts": len(observations)}}

def main():
    parser = argparse.ArgumentParser(description="Offline bounded candidate correlation")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Refusing to overwrite existing output")
    result = group_alerts(json.loads(args.input.read_text(encoding="utf-8")), args.window_minutes)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(f"Grouped {result['counts']['alerts']} alerts into {result['counts']['candidates']} unverified candidates")

if __name__ == "__main__":
    main()
