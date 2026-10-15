"""Synthetic-only Splunk go-live rehearsal: no network, tokens, or PC access.

Runs a reviewed fixed fixture matrix through the allowlisted normalizer and, for
valid scenarios, the sealed offline SOC pipeline and read-only dashboard adapter.
Reports only scenario IDs, expected outcomes and counts; no raw input rows.
"""
import argparse
import importlib.util
import json
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "splunk-readonly-connector/fixtures/live_readiness_scenarios.json"
MAX_SCENARIOS = 32
MAX_BYTES = 80_000
SAFE_ID = re.compile(r"[a-z0-9-]{4,80}\Z")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalizer = load("readiness_normalizer", ROOT / "splunk-readonly-connector/src/normalize.py")
batch = load("readiness_batch", ROOT / "soc-event-ingestion/src/batch_health.py")
integrity = load("readiness_integrity", ROOT / "soc-event-ingestion/src/artifact_integrity.py")
adapter = load("readiness_adapter", ROOT / "soc-command-center/src/adapter.py")


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate fixture JSON key")
        result[key] = value
    return result


def parse_matrix(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Invalid fixture byte size")
    fixture = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json)
    if (not isinstance(fixture, dict) or set(fixture) != {"version", "dataset", "scenarios"} or
        fixture["version"] != "0.1" or fixture["dataset"] != "synthetic_offline_only"):
        raise ValueError("Invalid fixed offline scenario matrix")
    scenarios = fixture["scenarios"]
    if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= MAX_SCENARIOS:
        raise ValueError("Scenario count outside allowed range")
    seen = set()
    for s in scenarios:
        if (not isinstance(s, dict) or not set(s).issubset(
                {"id", "expect", "alerts", "candidates", "rows"}) or
            not {"id", "expect", "rows"}.issubset(s) or
            not isinstance(s["id"], str) or not SAFE_ID.fullmatch(s["id"]) or
            s["id"] in seen or s["expect"] not in {"pass", "reject"} or
            not isinstance(s["rows"], list) or not 1 <= len(s["rows"]) <= 20):
            raise ValueError("Invalid scenario definition")
        seen.add(s["id"])
        if s["expect"] == "pass":
            if (set(s) != {"id", "expect", "alerts", "candidates", "rows"} or
                type(s["alerts"]) is not int or type(s["candidates"]) is not int or
                not 1 <= s["alerts"] <= 20 or not 1 <= s["candidates"] <= s["alerts"]):
                raise ValueError("Invalid positive scenario expectations")
        elif set(s) != {"id", "expect", "rows"}:
            raise ValueError("Unexpected expected counts on negative test")
        if any(not isinstance(row, dict) for row in s["rows"]):
            raise ValueError("Scenario rows must be JSON objects")
    return scenarios


def run_scenario(scenario, workspace):
    raw = ("\n".join(json.dumps(row, separators=(",", ":"), ensure_ascii=True)
                     for row in scenario["rows"]) + "\n").encode("ascii")
    if scenario["expect"] == "reject":
        try:
            normalizer.transform_jsonl(raw)
        except ValueError:
            return {"id": scenario["id"], "result": "expected_rejection"}
        raise AssertionError("Unsafe synthetic scenario was accepted")
    alerts = normalizer.transform_jsonl(raw)
    if len(alerts) != scenario["alerts"]:
        raise AssertionError("Unexpected number of normalized alerts")
    # Never create remote output; all test artifacts live in disposable temp dir.
    source = workspace / "synthetic_normalized.jsonl"
    source.write_text("".join(json.dumps(alert) + "\n" for alert in alerts), encoding="utf-8")
    directory = workspace / "sealed_batch"
    health = batch.process([source], directory)
    if health["status"] != "passed":
        raise AssertionError("Valid synthetic scenario unexpectedly quarantined")
    ingested, correlated = integrity.verified_reports(directory)
    if (len(ingested["accepted"]) != scenario["alerts"] or
        correlated["counts"]["candidates"] != scenario["candidates"]):
        raise AssertionError("Unexpected sealed-pipeline correlation counts")
    view = adapter.build(ingested, correlated)
    if (len(view["alerts"]) != scenario["alerts"] or
        len(view["candidates"]) != scenario["candidates"] or view["cases"]):
        raise AssertionError("Read-only dashboard contained unexpected results or cases")
    if any(not alert["evidence"][0]["reference"].startswith("splunk-synthetic:")
           for alert in view["alerts"]):
        raise AssertionError("Non-synthetic evidence appeared in offline rehearsal")
    if any(c.get("classification") != "unverified" for c in view["candidates"]):
        raise AssertionError("Confirmed incident appeared without analyst review")
    return {"id": scenario["id"], "result": "passed",
            "alerts": len(view["alerts"]), "candidates": len(view["candidates"])}


def rehearse(fixture_bytes):
    results = []
    for scenario in parse_matrix(fixture_bytes):
        with tempfile.TemporaryDirectory(prefix="soc-splunk-readiness-") as root:
            # Fail closed on an assertion, exception or different result. Do not
            # silently continue and claim overall success.
            results.append(run_scenario(scenario, Path(root)))
    return {"version": "0.1", "mode": "synthetic_offline_only",
            "passed_scenarios": len(results),
            "results": results,
            "live_splunk_verified": False}


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic Splunk readiness matrix (no network)")
    parser.add_argument("--out", type=Path, help="Optional new sanitized JSON summary; refuses overwrite")
    args = parser.parse_args()
    if args.out is not None and (args.out.exists() or args.out.is_symlink()):
        parser.error("Refusing to overwrite report")
    try:
        report = rehearse(FIXTURES.read_bytes())
        if args.out is not None:
            with args.out.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
    except (OSError, ValueError, AssertionError, UnicodeError) as exc:
        parser.error("Offline readiness rehearsal failed (" + type(exc).__name__ + ")")
    print("Passed {} synthetic Splunk readiness scenarios; no live SIEM queried".format(
        report["passed_scenarios"]))


if __name__ == "__main__":
    main()
