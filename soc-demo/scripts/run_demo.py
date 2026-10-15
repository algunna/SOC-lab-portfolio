"""Repeatable, fully offline SOC portfolio walkthrough using fixed synthetic data.

Preparation never creates an incident case. A separate explicit approval command
uses the manual promotion CLI; no live SIEM, secret, or network connection is used.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "splunk-readonly-connector" / "fixtures" / "synthetic_saved_search_alerts.jsonl"
MANIFEST_VERSION = "1"
PREPARED = ("alerts.jsonl", "ingestion.json", "correlation.json", "dashboard.json")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(stage, *args):
    # Fixed local scripts; never invoke a shell or user-provided Python source.
    result = subprocess.run([sys.executable, *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=40, check=False)
    if result.returncode:
        raise ValueError(f"Offline stage {stage} failed (exit {result.returncode})")


def prepare(output_dir):
    output_dir = Path(output_dir).resolve()
    if not output_dir.parent.is_dir():
        raise ValueError("Parent directory must already exist")
    # Fail rather than overwriting a previous investigation or following output symlinks.
    output_dir.mkdir(mode=0o700, exist_ok=False)
    try:
        files = {name: output_dir / name for name in PREPARED}
        run("normalize", ROOT / "splunk-readonly-connector/src/normalize.py", FIXTURE,
            "--out", files["alerts.jsonl"])
        run("ingestion", ROOT / "soc-event-ingestion/src/ingest.py",
            files["alerts.jsonl"], "--out", files["ingestion.json"])
        run("correlation", ROOT / "soc-incident-correlation/src/correlate.py",
            files["ingestion.json"], "--out", files["correlation.json"])
        run("dashboard", ROOT / "soc-command-center/src/adapter.py",
            "--ingestion", files["ingestion.json"], "--correlation", files["correlation.json"],
            "--out", files["dashboard.json"])
        ingest = json.loads(files["ingestion.json"].read_text(encoding="utf-8"))
        correlation = json.loads(files["correlation.json"].read_text(encoding="utf-8"))
        dashboard = json.loads(files["dashboard.json"].read_text(encoding="utf-8"))
        if (ingest.get("counts", {}).get("accepted") != 3
                or ingest.get("counts", {}).get("rejected") != 0
                or correlation.get("counts", {}).get("candidates") != 3
                or len(dashboard.get("alerts", [])) != 3
                or len(dashboard.get("candidates", [])) != 3
                or dashboard.get("cases") != []):
            raise ValueError("Synthetic result does not match expected demo pipeline")
        manifest = {
            "version": MANIFEST_VERSION,
            "mode": "synthetic_offline_only",
            "fixture_sha256": sha256(FIXTURE),
            "artifacts_sha256": {name: sha256(path) for name, path in files.items()},
        }
        (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except Exception:
        # Preserve a failed output directory for diagnosis, but without a manifest,
        # so approval can never treat it as complete.
        (output_dir / "manifest.json").unlink(missing_ok=True)
        raise
    return output_dir


def check_manifest(output_dir):
    output_dir = Path(output_dir).resolve()
    manifest_path = output_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict)
            or manifest.get("version") != MANIFEST_VERSION
            or manifest.get("mode") != "synthetic_offline_only"
            or manifest.get("fixture_sha256") != sha256(FIXTURE)
            or not isinstance(manifest.get("artifacts_sha256"), dict)
            or set(manifest["artifacts_sha256"]) != set(PREPARED)):
        raise ValueError("Not a recognized or unchanged synthetic SOC demo")
    for name in PREPARED:
        if (output_dir / name).is_symlink() or sha256(output_dir / name) != manifest["artifacts_sha256"][name]:
            raise ValueError("Demo artifact changed after preparation; refusing promotion")
    return output_dir


def approve_demo_case(output_dir, candidate_id, analyst, *, approve=False):
    if approve is not True:
        raise ValueError("Explicit --approve-demo-case required")
    output_dir = check_manifest(output_dir)
    correlation = json.loads((output_dir / "correlation.json").read_text(encoding="utf-8"))
    options = {c["candidate_id"] for c in correlation["incident_candidates"]}
    if candidate_id not in options or not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Use a candidate ID from this demo and a nonempty analyst identifier")
    db = output_dir / "cases.db"
    if db.exists() or db.is_symlink() or (output_dir / "approved-dashboard.json").exists():
        raise ValueError("Demo case already exists; refusing to overwrite")
    run("explicit analyst case promotion", ROOT / "soc-case-promotion/src/promote.py",
        output_dir / "correlation.json", "--db", db, "--candidate-id",
        candidate_id, "--analyst", analyst, "--approve")
    run("read-only case dashboard", ROOT / "soc-command-center/src/adapter.py",
        "--ingestion", output_dir / "ingestion.json", "--correlation",
        output_dir / "correlation.json", "--cases-db", db,
        "--out", output_dir / "approved-dashboard.json")
    result = json.loads((output_dir / "approved-dashboard.json").read_text(encoding="utf-8"))
    if len(result.get("cases", [])) != 1 or result["cases"][0]["status"] != "open":
        raise ValueError("Synthetic approved-case snapshot did not match expected result")
    return result


def main():
    parser = argparse.ArgumentParser(description="Entirely offline SOC demo; no automatic case promotion")
    command = parser.add_subparsers(dest="command", required=True)
    start = command.add_parser("prepare", help="Create isolated synthetic alerts, candidates and dashboard")
    start.add_argument("--out-dir", required=True, type=Path)
    approve = command.add_parser("approve", help="Explicitly approve exactly one synthetic case")
    approve.add_argument("--demo-dir", required=True, type=Path)
    approve.add_argument("--candidate-id", required=True)
    approve.add_argument("--analyst", required=True)
    approve.add_argument("--approve-demo-case", action="store_true", help="Mandatory explicit authorization")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            directory = prepare(args.out_dir)
            report = json.loads((directory / "correlation.json").read_text(encoding="utf-8"))
            print(f"Prepared offline synthetic demo in {directory}; NO cases created")
            for candidate in report["incident_candidates"]:
                print(f"Candidate: {candidate['candidate_id']} ({candidate['source_system']}, unverified)")
        else:
            approve_demo_case(args.demo_dir, args.candidate_id, args.analyst,
                              approve=args.approve_demo_case)
            print("Created one explicitly approved synthetic case and read-only dashboard snapshot")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        parser.error(f"Demo refused or failed: {type(exc).__name__}. See docs; no live data was used.")


if __name__ == "__main__":
    main()
