"""Explicit local analyst approval to promote a correlation candidate to a case."""
import argparse
import importlib.util
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("soc_cases", ROOT/"soc-incident-case-lab"/"src"/"cases.py")
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)
seal_spec = importlib.util.spec_from_file_location("soc_promotion_integrity", ROOT/"soc-event-ingestion"/"src"/"artifact_integrity.py")
integrity = importlib.util.module_from_spec(seal_spec)
seal_spec.loader.exec_module(integrity)

# Case severities have no "informational"; the lowest case level is used instead
CASE_SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

def promote(db, report, candidate_id, analyst, severity=None, approve=False):
    """severity=None takes the candidate's highest alert severity, so a critical alert
    does not silently become a medium case."""
    if approve is not True:
        raise ValueError("Explicit --approve required; no automatic promotion")
    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Nonempty analyst identifier required")
    if severity is not None and severity not in cases.SEVERITIES:
        raise ValueError("Invalid severity")
    if not isinstance(report, dict) or report.get("version") != "0.2" or not isinstance(report.get("incident_candidates"), list):
        raise ValueError("Expected correlation v0.2 report")
    matches = [c for c in report["incident_candidates"] if isinstance(c,dict) and c.get("candidate_id")==candidate_id]
    if len(matches)!=1:
        raise ValueError("Candidate not found or ambiguous")
    candidate=matches[0]
    if candidate.get("classification")!="unverified" or not isinstance(candidate.get("alert_ids"),list) or not candidate["alert_ids"]:
        raise ValueError("Invalid candidate")
    refs=candidate.get("evidence_references")
    if not isinstance(refs,list) or any(not isinstance(r,str) or not r.strip() for r in refs):
        raise ValueError("Invalid evidence references")
    if any(not isinstance(a,str) or not a.strip() for a in candidate["alert_ids"]):
        raise ValueError("Invalid alert IDs")
    if severity is None:
        severity=CASE_SEVERITY.get(candidate.get("highest_severity"),"medium")
    system=str(candidate.get("source_system") or "")
    who=" / ".join(str(candidate[k]) for k in ("actor","asset") if candidate.get(k))
    title=f"Unverified SOC candidate: {who} ({candidate_id})" if who else "Unverified SOC candidate: " + candidate_id
    # Unique mappings protect against repeated promotions across invocations: by candidate ID,
    # and by alert, because a re-run that changes batch membership gives the same alerts a new candidate ID.
    db.execute("CREATE TABLE IF NOT EXISTS promoted_candidates (candidate_id TEXT PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), approved_by TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS promoted_alerts (source_system TEXT NOT NULL, event_id TEXT NOT NULL, case_id INTEGER NOT NULL REFERENCES cases(id), PRIMARY KEY (source_system, event_id))")
    already=[a for a in candidate["alert_ids"] if db.execute("SELECT 1 FROM promoted_alerts WHERE source_system=? AND event_id=?",(system,a)).fetchone()]
    if already:
        raise ValueError(f"Alerts already promoted to a case: {', '.join(already)}")
    try:
        with db:
            cursor=db.execute("INSERT INTO cases(title,severity,created_at) VALUES (?,?,?)", (title, severity, cases.now()))
            case_id=cursor.lastrowid
            cases.record(db,case_id,"created",f"Severity: {severity}")
            for ref in refs:
                cases.record(db,case_id,"evidence",ref)
            cases.record(db,case_id,"note",f"Manual approval by {analyst}; original classification unverified; alerts: {', '.join(candidate['alert_ids'])}")
            db.execute("INSERT INTO promoted_candidates(candidate_id,case_id,approved_by) VALUES (?,?,?)", (candidate_id,case_id,analyst))
            db.executemany("INSERT INTO promoted_alerts(source_system,event_id,case_id) VALUES (?,?,?)",
                           [(system,a,case_id) for a in candidate["alert_ids"]])
    except sqlite3.IntegrityError as exc:
        raise ValueError("Candidate already promoted") from exc
    return case_id

def main():
    parser=argparse.ArgumentParser(description="Manually promote an unverified candidate")
    parser.add_argument("report",type=Path,nargs="?",help="Legacy trusted synthetic candidate report")
    parser.add_argument("--batch-dir",type=Path,help="Verify a sealed offline batch before promotion")
    parser.add_argument("--db",type=Path,required=True)
    parser.add_argument("--candidate-id",required=True)
    parser.add_argument("--analyst",required=True)
    parser.add_argument("--severity",choices=sorted(cases.SEVERITIES),help="Override; default is the candidate's highest alert severity")
    parser.add_argument("--approve",action="store_true",help="Required explicit human authorization")
    args=parser.parse_args()
    if not args.approve:
        parser.error("Explicit --approve is required")
    if (args.batch_dir is None) == (args.report is None):
        parser.error("Choose exactly one: legacy report or --batch-dir")
    if args.batch_dir is not None and args.db.resolve().is_relative_to(args.batch_dir.resolve()):
        parser.error("Case database must not be inside the sealed batch directory")
    try:
        if args.batch_dir is not None:
            _, report = integrity.verified_reports(args.batch_dir)
        else:
            report = json.loads(args.report.read_text(encoding="utf-8"))
        args.db.parent.mkdir(parents=True,exist_ok=True)
        with cases.connect(args.db) as db:
            identifier=promote(db,report,args.candidate_id,args.analyst,args.severity,approve=args.approve)
    except (OSError,UnicodeDecodeError,ValueError,sqlite3.DatabaseError) as exc:
        parser.error(str(exc))  # e.g. already promoted, unknown candidate, bad report
    print(f"Created analyst-approved case {identifier}")

if __name__=="__main__":
    main()
