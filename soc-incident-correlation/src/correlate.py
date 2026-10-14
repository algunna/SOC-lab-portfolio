"""Offline conservative correlation of already-validated normalized SOC alerts."""
import argparse
import hashlib
import json
from pathlib import Path

def group_alerts(report):
    if not isinstance(report, dict) or not isinstance(report.get("accepted"), list):
        raise ValueError("Expected ingestion report with accepted array")
    if report.get("rejected"):
        raise ValueError("Refusing to correlate report with rejected records")
    groups = {}
    for event in report["accepted"]:
        if not isinstance(event, dict):
            raise ValueError("Malformed accepted event")
        source = event.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("system"), str):
            raise ValueError("Malformed source")
        # Deliberately conservative: group only exact actor AND asset within one source.
        actor, asset = event.get("actor"), event.get("asset")
        if not isinstance(actor, str) or not actor.strip() or not isinstance(asset, str) or not asset.strip():
            key = ("isolated", str(event["event_id"]))
            reason = "isolated: actor or asset missing"
        else:
            key = (source["system"], actor, asset)
            reason = "same source system, actor and asset; no temporal or causal link established"
        groups.setdefault(key, {"reason": reason, "alerts": []})["alerts"].append(event)
    incidents = []
    for key, value in sorted(groups.items(), key=lambda pair: pair[0]):
        events = sorted(value["alerts"], key=lambda e: (e["occurred_at"], e["event_id"]))
        # Stable incident candidate ID based on exact grouping key and alert identifiers.
        basis = json.dumps([key, sorted(e["event_id"] for e in events)], separators=(",", ":"))
        identifier = "candidate-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
        incidents.append({"candidate_id": identifier, "classification": "unverified",
                          "reason": value["reason"], "alert_ids": [e["event_id"] for e in events],
                          "event_count": len(events),
                          "evidence_references": sorted(set(item["reference"] for e in events for item in e["evidence"]))})
    return {"version": "0.1", "incident_candidates": incidents, "counts": {"candidates": len(incidents), "alerts": len(report["accepted"])}}

def main():
    parser = argparse.ArgumentParser(description="Offline candidate incident grouping")
    parser.add_argument("input", type=Path, help="Validated ingestion report")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Refusing to overwrite existing output")
    result = group_alerts(json.loads(args.input.read_text(encoding="utf-8")))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(f"Grouped {result['counts']['alerts']} alerts into {result['counts']['candidates']} unverified candidates")

if __name__ == "__main__":
    main()
