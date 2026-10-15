"""Offline SOC batch artifact integrity marker and read-only verifier.

Not authentication: anyone who can rewrite both the outputs and marker can forge
hashes. Completeness marker is written LAST; incomplete/crashed runs fail closed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path

VERSION = "0.1"
MODES = {"offline_training"}
FILE_SETS = {
    "passed": frozenset({"health.json", "ingestion.json", "correlation.json"}),
    "blocked": frozenset({"health.json", "quarantine.json"}),
}
MAX_SIZE = {
    "health.json": 4096,
    "ingestion.json": 32_000_000,
    "correlation.json": 32_000_000,
    "quarantine.json": 32_000_000,
    "integrity.json": 4096,
}
HEX_SHA = re.compile(r"[0-9a-f]{64}\Z")
METRICS = {"accepted", "rejected", "duplicates", "candidates"}
STAGES = {"preflight", "ingestion", "correlation", "complete"}
COUNTER_MAX = 100_000_000


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON number")


def read_json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys,
                      parse_constant=reject_constant)


def validate_health(data):
    if (not isinstance(data, dict) or
        set(data) != {"version", "mode", "status", "stage", "counts"} or
        data["version"] != VERSION or data["mode"] not in MODES or
        type(data["status"]) is not str or data["status"] not in FILE_SETS or
        type(data["stage"]) is not str or data["stage"] not in STAGES or
        ((data["status"] == "passed") != (data["stage"] == "complete"))):
        raise ValueError("Unrecognized health report")
    counts = data["counts"]
    if not isinstance(counts, dict) or set(counts) != METRICS:
        raise ValueError("Invalid health counts")
    if any(type(v) is not int or v < 0 or v > COUNTER_MAX for v in counts.values()):
        raise ValueError("Invalid health counter")
    if data["status"] == "blocked" and counts["candidates"] != 0:
        raise ValueError("Blocked batch has candidates")
    if data["status"] == "passed" and counts["rejected"] != 0:
        raise ValueError("Passed batch has rejected rows")
    if counts["candidates"] > counts["accepted"]:
        raise ValueError("Candidate count exceeds accepted alerts")
    return data["status"]


def read_regular(path, max_size):
    """Read one explicitly named, non-symlinked regular file with size bound."""
    if path.is_symlink():
        raise ValueError("Symbolic link artifact refused")
    with path.open("rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_size:
            raise ValueError("Non-regular or oversized artifact")
        content = file.read(max_size + 1)
    if len(content) > max_size:
        raise ValueError("Artifact exceeds size limit")
    return content


def fingerprints(directory, names):
    rows = {}
    for name in sorted(names):
        raw = read_regular(directory / name, MAX_SIZE[name])
        rows[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return rows


def files_present(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Artifact directory must exist and not be a symlink")
    # Reject unrecognized files, including hidden metadata/SQLite sidecars and symlinks.
    return {item.name for item in directory.iterdir()}


def seal(directory, status):
    """Internal publisher, after health and data files were fully written."""
    directory = Path(directory)
    if status not in FILE_SETS:
        raise ValueError("Unknown artifact status")
    names = files_present(directory)
    if names != FILE_SETS[status]:
        raise ValueError("Incomplete or unexpected batch artifact set")
    health = read_json(read_regular(directory / "health.json", MAX_SIZE["health.json"]))
    if validate_health(health) != status:
        raise ValueError("Batch status inconsistent")
    payload = {"version": VERSION, "mode": "offline_training",
               "status": status, "files": fingerprints(directory, FILE_SETS[status])}
    # Never write the completion marker until every other artifact is readable.
    with (directory / "integrity.json").open("x", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())
    return payload


def verified_payloads(directory):
    """Verify a sealed batch and return the exact verified bytes.

    Caller must consume these returned bytes, NOT reopen the report paths;
    a separate verification then file read would introduce a TOCTOU window.
    """
    directory = Path(directory)
    names = files_present(directory)
    if "integrity.json" not in names:
        raise ValueError("Missing completion marker; batch may be incomplete")
    marker = read_json(read_regular(directory / "integrity.json", MAX_SIZE["integrity.json"]))
    if (not isinstance(marker, dict) or set(marker) != {"version", "mode", "status", "files"} or
        marker["version"] != VERSION or marker["mode"] != "offline_training" or
        type(marker["status"]) is not str or marker["status"] not in FILE_SETS):
        raise ValueError("Malformed completion marker")
    expected = FILE_SETS[marker["status"]]
    if names != expected | {"integrity.json"}:
        raise ValueError("Unexpected or missing artifact")
    files = marker["files"]
    if not isinstance(files, dict) or set(files) != expected:
        raise ValueError("Invalid manifest file list")
    for name in sorted(expected):
        value = files[name]
        if (not isinstance(value, dict) or set(value) != {"sha256", "bytes"} or
            type(value["bytes"]) is not int or not 0 <= value["bytes"] <= MAX_SIZE[name] or
            type(value["sha256"]) is not str or HEX_SHA.fullmatch(value["sha256"]) is None):
            raise ValueError("Invalid file digest metadata")
    payloads = {}
    for name in sorted(expected):
        raw = read_regular(directory / name, MAX_SIZE[name])
        actual = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if actual != files[name]:
            raise ValueError("Batch artifact contents or sizes changed")
        payloads[name] = raw
    health = read_json(payloads["health.json"])
    status = validate_health(health)
    if status != marker["status"]:
        raise ValueError("Health status does not match integrity marker")
    return status, payloads


def verified_reports(directory):
    """Load the exact verified JSON objects for a successful offline batch.

    A blocked batch can have an authenticated-looking local hash marker but is
    deliberately not allowed to feed downstream SOC investigations.
    """
    status, payloads = verified_payloads(directory)
    if status != "passed":
        raise ValueError("Blocked batches are not approved for downstream use")
    ingestion = read_json(payloads["ingestion.json"])
    correlation = read_json(payloads["correlation.json"])
    health = read_json(payloads["health.json"])
    if not isinstance(ingestion, dict) or not isinstance(correlation, dict):
        raise ValueError("Malformed batch reports")
    if not isinstance(ingestion.get("counts"), dict) or not isinstance(correlation.get("counts"), dict):
        raise ValueError("Invalid batch report counters")
    counts = ingestion["counts"]
    if (set(ingestion) != {"schema_version", "accepted", "rejected", "duplicates", "counts"} or
        ingestion["schema_version"] != "1.0" or
        set(counts) != {"accepted", "rejected", "duplicates"} or
        any(type(counts[k]) is not int or not 0 <= counts[k] <= COUNTER_MAX for k in counts) or
        not isinstance(ingestion.get("accepted"), list) or
        not isinstance(ingestion.get("rejected"), list) or
        not isinstance(ingestion.get("duplicates"), list)):
        raise ValueError("Malformed normalized ingestion report")
    if (len(ingestion["accepted"]) > 2000 or
        ingestion["rejected"] or
        len(ingestion["accepted"]) != counts["accepted"] or
        len(ingestion["duplicates"]) != counts["duplicates"] or
        counts["rejected"] != len(ingestion["rejected"]) or
        counts["accepted"] != health["counts"]["accepted"] or
        counts["duplicates"] != health["counts"]["duplicates"]):
        raise ValueError("Sealed ingestion contents do not match health counts")
    # This is a semantic check, not just a digest check. Group again from the
    # already-verified alert bytes with the batch-health default correlation
    # policy, then demand exact agreement, including every candidate field.
    spec = importlib.util.spec_from_file_location(
        "integrity_correlation_recheck",
        Path(__file__).resolve().parents[2] / "soc-incident-correlation/src/correlate.py")
    correlator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(correlator)
    try:
        expected = correlator.group_alerts(ingestion)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        raise ValueError("Sealed alerts cannot be correlated safely") from exc
    if (correlation != expected or
        expected["counts"]["candidates"] != health["counts"]["candidates"] or
        expected["counts"]["alerts"] != health["counts"]["accepted"]):
        raise ValueError("Sealed correlation differs from independently recomputed results")
    return ingestion, correlation


def verify(directory):
    """Read-only verification; returns metadata counts, never raw event contents."""
    status, payloads = verified_payloads(directory)
    return {"integrity": "verified_local_hashes", "status": status,
            "artifact_count": len(payloads), "mode": "offline_training"}

def main():
    parser = argparse.ArgumentParser(description="Read-only verification of offline SOC batch completeness and hashes")
    parser.add_argument("--batch-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.batch_dir)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        # Never print supplied paths or raw payloads.
        parser.error("Local batch verification refused (" + type(exc).__name__ + ")")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
