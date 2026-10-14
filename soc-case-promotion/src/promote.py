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

def promote(db, report, candidate_id, analyst, severity="medium", approve=False):
    if approve is not True:
        raise ValueError("Explicit --approve required; no automatic promotion")
    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Nonempty analyst identifier required")
    if severity not in cases.SEVERITIES:
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
    # Unique mapping protects against repeated promotions across invocations.
    db.execute("CREATE TABLE IF NOT EXISTS promoted_candidates (candidate_id TEXT PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), approved_by TEXT NOT NULL)")
    try:
        with db:
            db.execute("INSERT INTO promoted_candidates(candidate_id,case_id,approved_by) VALUES (?,0,?)", (candidate_id, analyst))
            case_id=cases.create_case(db, "Unverified SOC candidate: " + candidate_id, severity)
            for ref in refs:
                cases.record(db,case_id,"evidence",ref)
            cases.record(db,case_id,"note",f"Manual approval by {analyst}; original classification unverified; alerts: {', '.join(candidate['alert_ids'])}")
            db.execute("UPDATE promoted_candidates SET case_id=? WHERE candidate_id=?", (case_id,candidate_id))
    except sqlite3.IntegrityError as exc:
        raise ValueError("Candidate already promoted") from exc
    return case_id

def main():
    parser=argparse.ArgumentParser(description="Manually promote an unverified candidate")
    parser.add_argument("report",type=Path)
    parser.add_argument("--db",type=Path,required=True)
    parser.add_argument("--candidate-id",required=True)
    parser.add_argument("--analyst",required=True)
    parser.add_argument("--severity",choices=sorted(cases.SEVERITIES),default="medium")
    parser.add_argument("--approve",action="store_true",help="Required explicit human authorization")
    args=parser.parse_args()
    if not args.approve:
        parser.error("Explicit --approve is required")
    report=json.loads(args.report.read_text(encoding="utf-8"))
    args.db.parent.mkdir(parents=True,exist_ok=True)
    with cases.connect(args.db) as db:
        identifier=promote(db,report,args.candidate_id,args.analyst,args.severity,approve=args.approve)
    print(f"Created analyst-approved case {identifier}")

if __name__=="__main__":
    main()
