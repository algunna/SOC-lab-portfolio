"""Offline, read-only JSON/JSONL ingestion with deterministic deduplication."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "soc-event-contract" / "src" / "validate.py"
spec = importlib.util.spec_from_file_location("soc_contract_validator", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

def ingest(paths):
    accepted, rejected, seen = [], [], set()
    for path in paths:
        path = Path(path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines() if path.suffix == ".jsonl" else [path.read_text(encoding="utf-8")]
        except (OSError, UnicodeError) as exc:
            rejected.append({"file": str(path), "line": 0, "errors": [f"Unable to read input: {type(exc).__name__}"]})
            continue
        for line_number, line in enumerate(lines, 1):
            if not line.strip() and path.suffix == ".jsonl":
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                rejected.append({"file": str(path), "line": line_number, "errors": ["Invalid JSON"]})
                continue
            errors = validator.validate(event)
            if errors:
                rejected.append({"file": str(path), "line": line_number, "errors": errors})
                continue
            key = validator.deduplication_key(event)
            if key in seen:
                continue
            seen.add(key)
            accepted.append(event)
    return {"schema_version": "1.0", "accepted": accepted, "rejected": rejected,
            "counts": {"accepted": len(accepted), "rejected": len(rejected)}}

def main():
    p = argparse.ArgumentParser(description="Offline normalized SOC event ingestion")
    p.add_argument("inputs", nargs="+", type=Path, help="JSON or JSONL synthetic alert files")
    p.add_argument("--out", required=True, type=Path, help="Output JSON path (new file only)")
    args = p.parse_args()
    if args.out.exists():
        p.error("Refusing to overwrite an existing output")
    report = ingest(args.inputs)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(f"Accepted {report['counts']['accepted']}; rejected {report['counts']['rejected']}")
    if report["counts"]["rejected"]:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
