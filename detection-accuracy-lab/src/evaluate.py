"""Synthetic detector-policy evaluation for offline Windows and AWS hunting labs.

These labels are curated scenario *rule expectations*, NOT ground-truth evidence
that a real event is malicious or that a detector performs well in production.
No network calls, raw telemetry export, automatic case creation or SIEM access.
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/labeled_scenarios.json"
MAX_INPUT_BYTES = 200_000
MAX_SCENARIOS = 80
MAX_EVENTS_PER_SCENARIO = 60
SAFE_ID = re.compile(r"[a-z0-9-]{4,80}\Z")
RULES = {
    "windows": ("suspicious_powershell", "privileged_group_change",
                "scheduled_task_created", "success_after_failures"),
    "cloudtrail": ("root_account_activity", "iam_permission_or_identity_change",
                   "logging_configuration_change", "role_assumption_review"),
}


def import_detector(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DETECTORS = {
    "windows": import_detector("policy_windows_hunt", ROOT / "windows-threat-hunting-lab/src/hunt.py"),
    "cloudtrail": import_detector("policy_aws_hunt", ROOT / "aws-cloudtrail-threat-hunting/src/hunt.py"),
}


def reject_dupes(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate fixture JSON key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("Non-finite numbers not allowed")


def load_matrix(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Oversized or invalid synthetic matrix")
    matrix = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_dupes,
                        parse_constant=reject_constant)
    if (not isinstance(matrix, dict) or
        set(matrix) != {"schema_version", "scope", "scenarios"} or
        matrix["schema_version"] != "1.0" or
        matrix["scope"] != "synthetic_policy_expectations_not_real_world_accuracy" or
        not isinstance(matrix["scenarios"], list) or
        not 1 <= len(matrix["scenarios"]) <= MAX_SCENARIOS):
        raise ValueError("Invalid synthetic test matrix format")
    ids = set()
    for case in matrix["scenarios"]:
        if (not isinstance(case, dict) or
            set(case) != {"id", "detector", "events", "expected_rules", "reason"} or
            not isinstance(case["id"], str) or not SAFE_ID.fullmatch(case["id"]) or
            case["id"] in ids or not isinstance(case["detector"], str) or
            case["detector"] not in RULES or
            not isinstance(case["reason"], str) or not 1 <= len(case["reason"]) <= 250 or
            not isinstance(case["events"], list) or
            not 1 <= len(case["events"]) <= MAX_EVENTS_PER_SCENARIO or
            any(not isinstance(e, dict) for e in case["events"]) or
            not isinstance(case["expected_rules"], list) or
            any(not isinstance(r, str) or r not in RULES[case["detector"]]
                for r in case["expected_rules"]) or
            len(case["expected_rules"]) != len(set(case["expected_rules"]))):
            raise ValueError("Invalid synthetic scenario definition")
        ids.add(case["id"])
    return matrix["scenarios"]


def evaluate(raw):
    cases = load_matrix(raw)
    metrics = {detector: {rule: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
                          for rule in rules} for detector, rules in RULES.items()}
    mismatches = []
    passed = 0
    for case in cases:
        detector = case["detector"]
        findings = DETECTORS[detector].hunt(case["events"])
        if not isinstance(findings, list) or any(not isinstance(f, dict) or
                                                f.get("rule") not in RULES[detector]
                                                for f in findings):
            raise ValueError("Detector returned invalid or unexpected rule")
        actual = {f["rule"] for f in findings}
        expected = set(case["expected_rules"])
        passed += (actual == expected)
        if actual != expected:
            mismatches.append({"scenario_id": case["id"],
                               "missing_rules": sorted(expected - actual),
                               "unexpected_rules": sorted(actual - expected)})
        for rule in RULES[detector]:
            key = ("tp" if rule in expected and rule in actual else
                   "fn" if rule in expected else
                   "fp" if rule in actual else "tn")
            metrics[detector][rule][key] += 1
    return {
        "version": "0.1", "scope": "synthetic_policy_only",
        "scenario_count": len(cases), "matching_scenarios": passed,
        "mismatches": mismatches, "confusion_by_rule": metrics,
        "live_detection_accuracy_measured": False,
        "production_false_positive_rate_measured": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate offline detector-rule expectations only")
    parser.add_argument("--out", type=Path, help="New summary-only JSON report, refuses overwrite")
    args = parser.parse_args()
    if args.out is not None and (args.out.exists() or args.out.is_symlink()):
        parser.error("Refusing to overwrite evaluation report")
    try:
        result = evaluate(FIXTURE.read_bytes())
        if args.out is not None:
            with args.out.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error("Synthetic policy evaluation failed (" + type(exc).__name__ + ")")
    print("Synthetic policy scenarios matching: {}/{}; no live accuracy measured".format(
        result["matching_scenarios"], result["scenario_count"]))
    if result["mismatches"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
