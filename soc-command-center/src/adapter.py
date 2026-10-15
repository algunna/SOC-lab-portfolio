"""Offline adapter for validated ingestion and correlation reports, plus local cases."""
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod
contract=load_module("soc_event_contract",ROOT/"soc-event-contract"/"src"/"validate.py")
case_snapshot=load_module("soc_case_snapshot",Path(__file__).resolve().parent/"case_snapshot.py")
integrity=load_module("soc_batch_integrity_verified",ROOT/"soc-event-ingestion"/"src"/"artifact_integrity.py")

def build(ingestion,correlation,cases=None):
    if ingestion.get("rejected") or not isinstance(ingestion.get("accepted"),list):
        raise ValueError("Ingestion must have an accepted list and no rejected events")
    alerts=ingestion["accepted"]
    if any(contract.validate(alert) for alert in alerts):
        raise ValueError("Invalid normalized alert")
    candidates=correlation.get("incident_candidates")
    if correlation.get("version") not in ("0.2",) or not isinstance(candidates,list):
        raise ValueError("Invalid correlation report")
    ids={a["event_id"] for a in alerts}
    if len(ids)!=len(alerts):
        raise ValueError("Duplicate event IDs")
    for c in candidates:
        if not isinstance(c,dict) or c.get("classification")!="unverified" or not isinstance(c.get("alert_ids"),list) or not set(c["alert_ids"]).issubset(ids):
            raise ValueError("Invalid or unknown incident candidate")
    case_rows=cases if cases is not None else []
    if not isinstance(case_rows,list) or any(not isinstance(x,dict) for x in case_rows):
        raise ValueError("Invalid case rows")
    return {"alerts":alerts,"candidates":candidates,"cases":case_rows}

def main():
    import argparse
    p=argparse.ArgumentParser(description="Generate read-only dashboard fixture from trusted offline SOC reports")
    p.add_argument("--ingestion",type=Path,help="Legacy trusted synthetic report; use with --correlation")
    p.add_argument("--correlation",type=Path,help="Legacy trusted synthetic report; use with --ingestion")
    p.add_argument("--batch-dir",type=Path,help="Verify sealed offline batch before loading report bytes")
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--cases-db",type=Path,help="Existing local SQLite case database (read-only); optional")
    args=p.parse_args()
    if args.out.exists():p.error("Refusing to overwrite output")
    if args.batch_dir is not None:
        if args.ingestion is not None or args.correlation is not None:
            p.error("--batch-dir cannot be combined with legacy report options")
    elif args.ingestion is None or args.correlation is None:
        p.error("Choose --batch-dir or both --ingestion and --correlation")
    try:
        if args.batch_dir is not None:
            ingestion,correlation=integrity.verified_reports(args.batch_dir)
            if args.out.resolve().is_relative_to(args.batch_dir.resolve()):
                p.error("Output must not be written into sealed batch directory")
        else:
            ingestion=json.loads(args.ingestion.read_text(encoding="utf-8"))
            correlation=json.loads(args.correlation.read_text(encoding="utf-8"))
        case_rows=case_snapshot.read_cases(args.cases_db) if args.cases_db is not None else []
        data=build(ingestion,correlation,cases=case_rows)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, case_snapshot.sqlite3.DatabaseError) as exc:
        p.error(f"Invalid input: {type(exc).__name__}")
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open("x",encoding="utf-8") as f:json.dump(data,f,indent=2)
    print("Generated offline dashboard snapshot with {} local cases; no live telemetry".format(len(data["cases"])))
if __name__=="__main__":main()
