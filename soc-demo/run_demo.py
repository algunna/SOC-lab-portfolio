"""Reproducible, local-only SOC demonstration using the repository's synthetic fixtures.

No network calls, no credentials, and no case promotion unless explicitly requested.
All outputs are written to a new directory, never an existing workspace.
"""
import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "splunk-readonly-connector" / "fixtures" / "synthetic_saved_search_alerts.jsonl"
COMMAND_CENTER = ROOT / "soc-command-center" / "src" / "dashboard.py"


def command(*args):
    """Run an existing, separately tested component. Never invoke a shell."""
    return subprocess.run([sys.executable, *[str(item) for item in args]],
                          cwd=ROOT, text=True, capture_output=True, check=True)


def load_dashboard():
    spec = importlib.util.spec_from_file_location("demo_dashboard", COMMAND_CENTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(directory, approve_synthetic_case=False):
    """Write output to a fresh directory. Only a synthetic candidate can be approved."""
    destination = Path(directory).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    alerts = destination / "normalized_alerts.jsonl"
    ingestion = destination / "ingestion.json"
    correlation = destination / "correlation.json"
    dashboard = destination / "dashboard.json"
    html = destination / "command_center.html"
    db = destination / "synthetic_cases.db"

    command(ROOT / "splunk-readonly-connector/src/normalize.py", FIXTURE, "--out", alerts)
    command(ROOT / "soc-event-ingestion/src/ingest.py", alerts, "--out", ingestion)
    report = json.loads(ingestion.read_text(encoding="utf-8"))
    if report["counts"]["accepted"] != 3 or report["counts"]["rejected"] != 0:
        raise ValueError("Unexpected synthetic fixture ingestion results")
    command(ROOT / "soc-incident-correlation/src/correlate.py", ingestion, "--out", correlation)
    candidate_report = json.loads(correlation.read_text(encoding="utf-8"))
    candidates = candidate_report["incident_candidates"]
    if len(candidates) != 3 or any(c["classification"] != "unverified" for c in candidates):
        raise ValueError("Unexpected synthetic correlation results")

    case_id = None
    if approve_synthetic_case:
        # This fixture is checked in and synthetic; approval must be explicitly selected.
        matches = [c for c in candidates if c.get("source_system") == "windows"
                   and c.get("rule_ids") == ["windows.powershell.encoded"]]
        if len(matches) != 1:
            raise ValueError("Synthetic approval target must be unique")
        candidate_id = matches[0]["candidate_id"]
        command(ROOT / "soc-case-promotion/src/promote.py", correlation, "--db", db,
                "--candidate-id", candidate_id,
                "--analyst", "SYNTHETIC-DEMO-ANALYST", "--approve")
        case_id = 1

    adapter_args = [ROOT / "soc-command-center/src/adapter.py",
                    "--ingestion", ingestion, "--correlation", correlation, "--out", dashboard]
    if approve_synthetic_case:
        adapter_args.extend(["--cases-db", db])
    command(*adapter_args)
    data = json.loads(dashboard.read_text(encoding="utf-8"))
    expected_cases = 1 if approve_synthetic_case else 0
    if len(data["alerts"]) != 3 or len(data["candidates"]) != 3 or len(data["cases"]) != expected_cases:
        raise ValueError("Dashboard counts do not match synthetic pipeline")
    if case_id is not None and (data["cases"][0]["id"] != case_id or
                                data["cases"][0]["severity"] != "medium"):
        raise ValueError("Unexpected synthetic approved case")
    html.write_text(load_dashboard().render(data), encoding="utf-8")
    summary = {
        "dataset": "SYNTHETIC ONLY — NEVER LIVE SIEM TELEMETRY",
        "alerts": len(data["alerts"]),
        "unverified_candidates": len(data["candidates"]),
        "explicitly_approved_synthetic_cases": len(data["cases"]),
        "no_network_access": True,
        "analyst_approval_required": True,
        "dashboard": str(dashboard),
        "html_preview": str(html),
    }
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Offline end-to-end synthetic SOC portfolio demonstration")
    parser.add_argument("--out-dir", type=Path, help="New output directory; existing directories are refused")
    parser.add_argument("--approve-synthetic-case", action="store_true",
                        help="Explicitly approve one synthetic candidate and create a disposable SQLite lab case")
    args = parser.parse_args()
    try:
        if args.out_dir is None:
            # Default leaves no local files behind.
            with tempfile.TemporaryDirectory(prefix="atlas-soc-demo-") as tmp:
                report = run(Path(tmp) / "results", args.approve_synthetic_case)
                print(json.dumps({k: v for k, v in report.items() if k not in ("dashboard", "html_preview")},
                                 indent=2))
                print("Temporary output removed. Use --out-dir to preserve local demo artifacts.")
        else:
            report = run(args.out_dir, args.approve_synthetic_case)
            print(json.dumps(report, indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        # Existing components may print structured errors; do not echo arbitrary payloads.
        parser.error(f"Synthetic demo failed ({type(exc).__name__}); verify local dependencies and fixture")


if __name__ == "__main__":
    main()
