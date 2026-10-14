"""Offline SQLite-backed SOC case management training lab."""
import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = """CREATE TABLE IF NOT EXISTS cases (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history (
 id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
 kind TEXT NOT NULL, detail TEXT NOT NULL, recorded_at TEXT NOT NULL);
"""
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"open", "investigating", "closed"}

def connect(path):
    db = sqlite3.connect(str(path))
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    return db

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def create_case(db, title, severity):
    if not title.strip() or severity not in SEVERITIES:
        raise ValueError("A nonempty title and valid severity are required")
    with db:
        cursor = db.execute("INSERT INTO cases(title,severity,created_at) VALUES (?,?,?)", (title, severity, now()))
        record(db, cursor.lastrowid, "created", f"Severity: {severity}")
    return cursor.lastrowid

def record(db, case_id, kind, detail):
    if kind not in {"created", "note", "evidence", "status"} or not detail.strip():
        raise ValueError("Invalid history entry")
    if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise ValueError("Unknown case")
    db.execute("INSERT INTO history(case_id,kind,detail,recorded_at) VALUES (?,?,?,?)",
               (case_id, kind, detail, now()))

def transition(db, case_id, status):
    if status not in STATUSES:
        raise ValueError("Unknown status")
    row = db.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise ValueError("Unknown case")
    allowed = {"open": {"investigating"}, "investigating": {"closed", "open"}, "closed": set()}
    if status not in allowed[row[0]]:
        raise ValueError("Invalid status transition")
    with db:
        db.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
        record(db, case_id, "status", f"{row[0]} -> {status}")

def export_case(db, case_id):
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        raise ValueError("Unknown case")
    history = db.execute("SELECT kind, detail, recorded_at FROM history WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
    return {"case": dict(row), "history": [dict(x) for x in history]}

def main():
    parser = argparse.ArgumentParser(description="Offline SOC case management")
    parser.add_argument("--db", type=Path, default=ROOT / "cases.db")
    sub = parser.add_subparsers(dest="command", required=True)
    new = sub.add_parser("new")
    new.add_argument("title")
    new.add_argument("--severity", choices=sorted(SEVERITIES), default="medium")
    for command in ("note", "evidence"):
        p = sub.add_parser(command)
        p.add_argument("case_id", type=int)
        p.add_argument("detail")
    state = sub.add_parser("status")
    state.add_argument("case_id", type=int)
    state.add_argument("value", choices=sorted(STATUSES))
    show = sub.add_parser("show")
    show.add_argument("case_id", type=int)
    args = parser.parse_args()
    args.db.parent.mkdir(parents=True, exist_ok=True)
    try:
        with connect(args.db) as db:
            if args.command == "new":
                print(f"Created case {create_case(db, args.title, args.severity)}")
            elif args.command in ("note", "evidence"):
                with db:
                    record(db, args.case_id, args.command, args.detail)
                print("History updated")
            elif args.command == "status":
                transition(db, args.case_id, args.value)
                print("Status updated")
            else:
                print(json.dumps(export_case(db, args.case_id), indent=2))
    except (ValueError, sqlite3.DatabaseError) as exc:
        parser.error(str(exc))  # unknown case, invalid transition, empty text, unreadable database

if __name__ == "__main__":
    main()
