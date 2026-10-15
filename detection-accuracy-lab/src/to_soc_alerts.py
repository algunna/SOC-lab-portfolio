"""Synthetic-only offline detector finding → SOC Event Contract v1 bridge.

Only curated fixture rows are processed. This is NOT a live event/alert connector,
source attestation, validated SIEM SPL detector, or permission to import raw logs.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "detection-accuracy-lab/fixtures/labeled_scenarios.json"
MAX_BYTES = 200_000
MAX_ALERTS = 200
IDENTITY = re.compile(r"[A-Za-z0-9_.:@/\\-]{1,256}\Z")

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

matrix = load("bridge_labeled_matrix", ROOT / "detection-accuracy-lab/src/evaluate.py")
contract = load("bridge_event_contract", ROOT / "soc-event-contract/src/validate.py")

# Fixed, code-reviewed metadata—not fields a detector/source may choose.
# Detector output severity/technique must agree with this local policy.
MAPPINGS = {
    ("windows", "suspicious_powershell"):
        ("windows", "windows.powershell.suspicious", "medium", "PowerShell flags for analyst review", "T1059.001"),
    ("windows", "privileged_group_change"):
        ("windows", "windows.group.privileged_change", "high", "Privileged group membership change", "T1098"),
    ("windows", "scheduled_task_created"):
        ("windows", "windows.task.created", "low", "Scheduled task creation observed", "T1053.005"),
    ("windows", "success_after_failures"):
        ("windows", "windows.authentication.success_after_failures", "high", "Successful login following failures", "T1110"),
    ("cloudtrail", "root_account_activity"):
        ("aws_cloudtrail", "aws.root.activity", "high", "Root account activity observed", "T1078.004"),
    ("cloudtrail", "iam_permission_or_identity_change"):
        ("aws_cloudtrail", "aws.iam.identity_change", "medium", "IAM identity or permission change", "T1098"),
    ("cloudtrail", "logging_configuration_change"):
        ("aws_cloudtrail", "aws.logging.configuration_change", "high", "CloudTrail logging change", "T1562.008"),
    ("cloudtrail", "role_assumption_review"):
        ("aws_cloudtrail", "aws.role.assumption_review", "low", "Role assumption for review", "T1078.004"),
}


def identity(value):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise ValueError("Invalid synthetic actor or asset")
    return value


def alert_for(finding, detector, scenario_id, ordinal):
    if not isinstance(finding, dict):
        raise ValueError("Detector returned nonobject finding")
    rule = finding.get("rule")
    if not isinstance(rule, str) or (detector, rule) not in MAPPINGS:
        raise ValueError("Unreviewed detector rule")
    system, rule_id, severity, title, technique = MAPPINGS[(detector, rule)]
    tech_field = "attack" if detector == "windows" else "attack_hypothesis"
    if finding.get("severity") != severity or finding.get(tech_field) != technique:
        raise ValueError("Detector metadata disagrees with reviewed rule")
    occurred_at = finding.get("timestamp" if detector == "windows" else "time")
    if not isinstance(occurred_at, str):
        raise ValueError("Missing detector timestamp")
    if detector == "windows":
        actor = identity(finding.get("user"))
        asset = identity(finding.get("host"))
    else:
        # identity_type is a coarse label, not an authenticated AWS principal.
        actor = identity(finding.get("identity_type"))
        asset = "SYNTHETIC-AWS-LAB"
    # Stable synthetic ID is scoped to fixture ID, rule and occurrence number.
    # It intentionally makes NO claim about an original EventRecordID/eventID.
    key = json.dumps([scenario_id, system, rule_id, ordinal], separators=(",", ":"))
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    record_id = "fixture-" + digest[:32]
    alert = {
        "schema_version": "1.0",
        "event_id": "lab-" + digest[:24],
        "occurred_at": occurred_at,
        "source": {"system": system, "record_id": record_id},
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "actor": actor,
        "asset": asset,
        "attack_techniques": [technique],
        "evidence": [{
            "reference": "synthetic-fixture:" + digest[:32],
            "description": "Synthetic offline detector finding; no authenticated source event or verdict",
        }],
    }
    if contract.validate(alert):
        raise ValueError("Normalized synthetic alert failed SOC Event Contract v1")
    return alert


def bridge(raw):
    """Validate the whole fixed synthetic matrix and return only alert contract objects.

    Cases that are benign under the curated policy MUST have no findings. Positive
    cases MUST exactly match their independently recorded expected rule sets.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("Unbounded fixture")
    cases = matrix.load_matrix(raw)
    alerts, ids = [], set()
    for scenario in cases:
        detector = scenario["detector"]
        findings = matrix.DETECTORS[detector].hunt(scenario["events"])
        if not isinstance(findings, list):
            raise ValueError("Invalid detector finding list")
        found = {finding.get("rule") for finding in findings if isinstance(finding, dict)}
        if (any(not isinstance(f, dict) for f in findings) or
                found != set(scenario["expected_rules"])):
            raise ValueError("Detector output contradicts synthetic fixture expectations")
        per_rule = defaultdict(int)
        for finding in findings:
            rule = finding["rule"]
            ordinal = per_rule[rule]
            per_rule[rule] += 1
            alert = alert_for(finding, detector, scenario["id"], ordinal)
            event_id = (alert["source"]["system"], alert["event_id"])
            if event_id in ids:
                raise ValueError("Duplicate synthetic alert identity")
            ids.add(event_id)
            alerts.append(alert)
            if len(alerts) > MAX_ALERTS:
                raise ValueError("Too many synthetic alerts")
    if not alerts:
        raise ValueError("Synthetic fixture generated no findings")
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Offline, synthetic-only detector to SOC alert contract")
    parser.add_argument("--out", type=Path, required=True,
                        help="New private JSONL output; never overwrites")
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        parser.error("Refusing to overwrite output")
    try:
        alerts = bridge(FIXTURE.read_bytes())
        # Only open destination after entire input has validated.
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            for alert in alerts:
                stream.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=True) + "\n")
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        parser.error("Synthetic alert bridge refused batch (" + type(exc).__name__ + ")")
    print("Normalized {} synthetic offline detector findings; no live telemetry queried".format(len(alerts)))


if __name__ == "__main__":
    main()
