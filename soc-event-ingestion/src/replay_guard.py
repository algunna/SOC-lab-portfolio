"""Offline, opt-in SQLite replay guard for previously validated SOC ingestion reports.

This demonstrates cross-invocation replay filtering in a controlled lab. It is
NOT an exactly-once message transport, authenticated provenance service or SIEM.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "replay_soc_contract", ROOT / "soc-event-contract" / "src" / "validate.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

SCHEMA = """
CREATE TABLE IF NOT EXISTS observed (
    observation_key TEXT PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL
);
"""
MAX_ALERTS = 10000


def digest(value):
    """Canonical SHA-256; no raw alert bodies or evidence text stored in SQLite."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()


def keys(alert):
    system = alert["source"]["system"]
    observation = digest([system, alert["source"]["record_id"], alert["rule_id"]])
    identity = digest([system, alert["event_id"]])
    # Event ID can change across exports; compare observation content independently.
    payload = {name: value for name, value in alert.items() if name != "event_id"}
    return observation, identity, digest(payload)


def validate_report(report):
    if not isinstance(report, dict) or report.get("schema_version") != "1.0":
        raise ValueError("Expected ingestion schema v1.0 report")
    alerts = report.get("accepted")
    if not isinstance(alerts, list) or len(alerts) > MAX_ALERTS:
        raise ValueError("Accepted alerts missing or exceed batch limit")
    if not isinstance(report.get("rejected"), list) or report["rejected"]:
        raise ValueError("Rejected input cannot be replay-committed")
    previous_duplicates = report.get("duplicates", [])
    if not isinstance(previous_duplicates, list):
        raise ValueError("Malformed input duplicates")
    counts = report.get("counts")
    if not isinstance(counts, dict) or counts.get("accepted") != len(alerts) or counts.get("rejected") != 0:
        raise ValueError("Ingestion counts do not match input")
    if counts.get("duplicates", 0) != len(previous_duplicates):
        raise ValueError("Input duplicates count mismatch")
    own_observations, own_events = {}, {}
    for alert in alerts:
        if contract.validate(alert):
            raise ValueError("Accepted alert failed event-contract validation")
        obs, event, fingerprint = keys(alert)
        if obs in own_observations or event in own_events:
            raise ValueError("Ambiguous repeated observation or event ID within batch")
        own_observations[obs] = (event, fingerprint)
        own_events[event] = (obs, fingerprint)
    return alerts, previous_duplicates


def process(report, db, *, write_output):
    """Atomic database changes on successful file write, not guaranteed crash-safe delivery.

    write_output(report) must atomically create an exclusive output file and return
    cleanup function. If processing fails before database commit, cleanup is called.
    """
    alerts, prev_duplicates = validate_report(report)
    db.execute("BEGIN IMMEDIATE")
    cleanup = None
    try:
        added, replayed = [], []
        staged = []
        for alert in alerts:
            obs, event, fingerprint = keys(alert)
            previous_event = db.execute(
                "SELECT observation_key, payload_hash FROM observed WHERE event_key=?", (event,)
            ).fetchone()
            previous_obs = db.execute(
                "SELECT event_key, payload_hash FROM observed WHERE observation_key=?", (obs,)
            ).fetchone()
            if previous_event and previous_event != (obs, fingerprint):
                raise ValueError("Conflicting reused source/event identity")
            if previous_obs and previous_obs[1] != fingerprint:
                raise ValueError("Conflicting previously observed record and rule")
            if previous_event or previous_obs:
                replayed.append({"event_id": alert["event_id"], "reason": "persistent_replay"})
                continue
            staged.append((obs, event, fingerprint))
            added.append(alert)
        for entry in staged:
            db.execute("INSERT INTO observed(observation_key,event_key,payload_hash) VALUES (?,?,?)", entry)
        out = {
            "schema_version": "1.0", "accepted": added, "rejected": [],
            "duplicates": prev_duplicates + replayed,
            "counts": {"accepted": len(added), "rejected": 0,
                       "duplicates": len(prev_duplicates) + len(replayed)},
            "replay_guard": {"new": len(added), "skipped": len(replayed)},
        }
        cleanup = write_output(out)
        db.commit()
        return out
    except Exception:
        db.rollback()
        if cleanup is not None:
            cleanup()
        raise


def run(report, state_path, output_path):
    validate_report(report)
    state_path = Path(state_path)
    output_path = Path(output_path)
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("Refusing to overwrite output")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    def write_output(result):
        nonlocal created
        with output_path.open("x", encoding="utf-8") as handle:
            created = True
            json.dump(result, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return lambda: output_path.unlink(missing_ok=True)
    try:
        with closing(sqlite3.connect(state_path, timeout=5, isolation_level=None)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.executescript(SCHEMA)
            db.commit()
            return process(report, db, write_output=write_output)
    except Exception:
        if created:
            output_path.unlink(missing_ok=True)
        raise


def main():
    p = argparse.ArgumentParser(description="Offline persistent replay guard for normalized SOC alerts")
    p.add_argument("--ingestion", type=Path, required=True)
    p.add_argument("--state-db", type=Path, required=True, help="Local private SQLite replay state")
    p.add_argument("--out", type=Path, required=True, help="New JSON ingestion report")
    args = p.parse_args()
    if args.ingestion.resolve() in (args.state_db.resolve(), args.out.resolve()) or args.state_db.resolve() == args.out.resolve():
        p.error("Input, state and output must be distinct files")
    try:
        report = json.loads(args.ingestion.read_text(encoding="utf-8"))
        result = run(report, args.state_db, args.out)
    except (OSError, sqlite3.DatabaseError, ValueError, UnicodeError) as exc:
        p.error(f"Replay guard failed ({type(exc).__name__}); inspect trusted local inputs")
    print("New: {}; persistent replays skipped: {}".format(
        result["replay_guard"]["new"], result["replay_guard"]["skipped"]))


if __name__ == "__main__":
    main()
