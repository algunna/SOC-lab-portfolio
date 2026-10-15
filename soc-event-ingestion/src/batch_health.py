"""Offline SOC batch health gate with metadata-only quarantine.

Inputs must be trusted/sanitized training alerts. No network, no retry scheduler,
no replay-state writes and no automatic case promotion.
"""
import argparse
import importlib.util
import json
import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAX_SOURCES = 8
MAX_FILE_BYTES = 1_000_000
MAX_ALERTS = 2_000

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

ingestion = load("health_ingestion", ROOT / "soc-event-ingestion/src/ingest.py")
correlation = load("health_correlation", ROOT / "soc-incident-correlation/src/correlate.py")


def issue(source_index, line, reason):
    """Never expose paths, raw logs, schema validation messages or identities."""
    return {"source_index": source_index, "line": line, "reason": reason}


def preflight(paths):
    problems = []
    for index, path in enumerate(paths, 1):
        path = Path(path)
        if path.suffix not in {".json", ".jsonl"}:
            problems.append(issue(index, 0, "unsupported_extension"))
            continue
        try:
            if path.is_symlink():
                problems.append(issue(index, 0, "symlink_refused"))
                continue
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                problems.append(issue(index, 0, "not_regular_file"))
            elif info.st_size > MAX_FILE_BYTES:
                problems.append(issue(index, 0, "input_too_large"))
        except OSError:
            problems.append(issue(index, 0, "input_unavailable"))
    return problems


def categorize(error):
    """Map ingestion errors to stable, non-sensitive reason codes only."""
    messages = error.get("errors", [])
    if not isinstance(messages, list):
        return "invalid_alert"
    if "Invalid JSON" in messages:
        return "invalid_json"
    if any(isinstance(message, str) and message.startswith("Unable to read input:") for message in messages):
        return "input_unavailable"
    if any(isinstance(message, str) and "already used by a different alert" in message for message in messages):
        return "conflicting_event_id"
    return "invalid_alert"


def write_new(path, payload):
    """Exclusive creation; do not overwrite existing reports."""
    with path.open("x", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=True)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())


def process(paths, out_dir):
    """Return a sanitized health summary and optionally validated pipeline artifacts.

    Each invocation requires a new directory. Corrected inputs must be supplied
    explicitly in a *different* directory; nothing is retried automatically.
    """
    if not 1 <= len(paths) <= MAX_SOURCES:
        raise ValueError("Provide 1 to 8 input files")
    dest = Path(out_dir)
    if not dest.parent.is_dir() or dest.is_symlink():
        raise ValueError("Output parent must exist and be a normal directory")
    dest.mkdir(mode=0o700, exist_ok=False)
    problems = preflight(paths)
    counts = {"accepted": 0, "rejected": len(problems), "duplicates": 0, "candidates": 0}
    health = {"version": "0.1", "mode": "offline_training",
              "status": "blocked", "stage": "preflight", "counts": counts}
    if problems:
        write_new(dest / "quarantine.json", {"version": "0.1", "issues": problems})
        write_new(dest / "health.json", health)
        return health

    report = ingestion.ingest(paths)
    rejected = report["rejected"]
    issues = [issue(index + 1, row.get("line", 0), categorize(row))
              for row in rejected
              for index, path in enumerate(paths) if str(path) == row.get("file")]
    counts.update(accepted=report["counts"]["accepted"],
                  rejected=report["counts"]["rejected"],
                  duplicates=report["counts"]["duplicates"])
    if rejected or counts["accepted"] > MAX_ALERTS:
        if counts["accepted"] > MAX_ALERTS:
            issues.append(issue(0, 0, "too_many_alerts"))
            counts["rejected"] += 1
        health["stage"] = "ingestion"
        write_new(dest / "quarantine.json", {"version": "0.1", "issues": issues})
        write_new(dest / "health.json", health)
        return health

    try:
        candidates = correlation.group_alerts(report)
    except (ValueError, TypeError, KeyError):
        health["stage"] = "correlation"
        write_new(dest / "quarantine.json", {
            "version": "0.1", "issues": [issue(0, 0, "correlation_failed")]})
        write_new(dest / "health.json", health)
        return health

    counts["candidates"] = candidates["counts"]["candidates"]
    health["status"] = "passed"
    health["stage"] = "complete"
    write_new(dest / "ingestion.json", report)
    write_new(dest / "correlation.json", candidates)
    write_new(dest / "health.json", health)
    return health


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic SOC batch health and quarantine")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path, help="New directory; never overwrites")
    args = parser.parse_args()
    if args.out_dir.resolve() in [path.resolve() for path in args.inputs]:
        parser.error("Output directory cannot be an input file")
    try:
        health = process(args.inputs, args.out_dir)
    except (OSError, ValueError) as exc:
        parser.error(f"Batch processing failed ({type(exc).__name__}); output was not reused")
    print("Batch status: {}; stage: {}; accepted: {}; rejected: {}".format(
        health["status"], health["stage"], health["counts"]["accepted"], health["counts"]["rejected"]))
    if health["status"] != "passed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
