"""Source-identity-preflight → contract-valid informational SOC alert handoff.

Strictly synthetic and offline. A scoped source identifier is NOT authenticated
provenance or a detector verdict. The fixed rule describes an observation only.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "controlled-telemetry-lab/fixtures/synthetic_sources.json"
MAX_ALERTS = 40
HASH = re.compile(r"[0-9a-f]{48}\Z")
RULE = "lab.synthetic.source_observation"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


source_identity = load("controlled_source_handoff_identity",
                       ROOT / "controlled-telemetry-lab/src/source_identity.py")
contract = load("controlled_source_handoff_contract",
                ROOT / "soc-event-contract/src/validate.py")


def observation_alert(projected):
    """Consume only data returned by strict source preflight, not raw source rows."""
    if (not isinstance(projected, dict) or
        set(projected) != {"source", "occurred_at", "evidence_reference",
                           "clock_review", "provenance"} or
        projected["provenance"] != "unauthenticated_synthetic_fixture" or
        projected["clock_review"] not in {"within_lab_window",
                                          "delayed_arrival", "future_event_time"}):
        raise ValueError("Invalid synthetic source projection")
    src = projected["source"]
    if (not isinstance(src, dict) or set(src) != {"system", "record_id"} or
        type(src["system"]) is not str or
        src["system"] not in {"windows", "aws_cloudtrail"} or
        type(src["record_id"]) is not str or
        not src["record_id"].startswith("lab-src-") or
        not HASH.fullmatch(src["record_id"][8:]) or
        projected["evidence_reference"] != "synthetic-source:" + src["record_id"][8:]):
        raise ValueError("Source identity and synthetic evidence mismatch")

    basis = json.dumps([src["system"], src["record_id"]], separators=(",", ":"))
    event_id = "labobs-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]
    alert = {
        "schema_version": "1.0",
        "event_id": event_id,
        "occurred_at": projected["occurred_at"],
        "source": dict(src),
        "rule_id": RULE,
        "severity": "informational",
        "title": "Synthetic source observation; no detection asserted",
        "evidence": [{
            "reference": projected["evidence_reference"],
            "description": "Synthetic source namespace preflight only; unauthenticated and not a detection",
        }],
    }
    if contract.validate(alert):
        raise ValueError("Synthetic observation failed SOC Event Contract v1")
    return alert


def build(raw):
    """Reject the entire fixture before writing any output if one row is invalid."""
    preflight = source_identity.evaluate(raw)
    if (preflight["scope"] != "unauthenticated_synthetic_only" or
        preflight["live_provenance_verified"] is not False or
        not 1 <= len(preflight["records"]) <= MAX_ALERTS):
        raise ValueError("No authenticated live source accepted by this offline bridge")
    alerts = [observation_alert(row) for row in preflight["records"]]
    event_ids = {(a["source"]["system"], a["event_id"]) for a in alerts}
    if len(event_ids) != len(alerts):
        raise ValueError("Conflicting event identity")
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Synthetic source identity to informational SOC alerts")
    parser.add_argument("--out", required=True, type=Path,
                        help="New private JSONL; refusing overwrite")
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        parser.error("Output already exists")
    try:
        alerts = build(FIXTURE.read_bytes())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            for alert in alerts:
                stream.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=True) + "\n")
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        parser.error("Synthetic source handoff refused (" + type(exc).__name__ + ")")
    print("Wrote {} synthetic informational observations; zero live sources verified".format(len(alerts)))


if __name__ == "__main__":
    main()
