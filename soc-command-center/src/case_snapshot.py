"""Read-only, bounded snapshot of local SOC case metadata for the demo dashboard.

This does not use the case manager's schema-initializing connect() function.
No audit history, evidence descriptions, or notes are read.
"""
import sqlite3
from contextlib import closing
from pathlib import Path

MAX_CASES = 200
REQUIRED_COLUMNS = {"id", "title", "severity", "status"}
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"open", "investigating", "closed"}


def read_cases(db_path):
    """Read existing case metadata without creating or changing a SQLite database."""
    path = Path(db_path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("Cases database must be an existing regular file")
    # SQLite URI mode=ro refuses to create an absent DB or write to it.
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only = ON")
        db.execute("PRAGMA busy_timeout = 5000")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(cases)")}
        if not REQUIRED_COLUMNS.issubset(columns):
            raise ValueError("Unsupported cases database schema")
        count = db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        if count > MAX_CASES:
            raise ValueError(f"Case count exceeds demo limit of {MAX_CASES}; refusing partial display")
        rows = db.execute("SELECT id, title, severity, status FROM cases ORDER BY id").fetchall()
        results = []
        for record in rows:
            case = dict(record)
            if (
                type(case["id"]) is not int or case["id"] <= 0
                or not isinstance(case["title"], str)
                or not 0 < len(case["title"].strip()) <= 500
                or case["severity"] not in SEVERITIES
                or case["status"] not in STATUSES
            ):
                raise ValueError("Invalid case metadata: refusing unverified snapshot")
            results.append(case)
        return results
