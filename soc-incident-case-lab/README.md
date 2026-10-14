# SOC Incident Response Case Management Lab

Offline, Python/SQLite training project to track security investigation cases and preserve an append-only application-level history of notes, evidence references, and status transitions.

## Capabilities

- Open an incident with title and severity (low, medium, high or critical).
- Add analyst notes and evidence **references** (not uploads).
- Progress case status `open → investigating → closed`, or `investigating → open`.
- Display a case with a chronological audit history as JSON.
- Use local SQLite storage without any hosted services or API credentials.

## Run from repository root

```bash
python soc-incident-case-lab/src/cases.py --db /tmp/soc-cases.db new "Unusual PowerShell execution" --severity high
python soc-incident-case-lab/src/cases.py --db /tmp/soc-cases.db note 1 "Initial triage of synthetic Sysmon event"
python soc-incident-case-lab/src/cases.py --db /tmp/soc-cases.db evidence 1 "Fixture: sample_sysmon.xml, Event ID 1"
python soc-incident-case-lab/src/cases.py --db /tmp/soc-cases.db status 1 investigating
python soc-incident-case-lab/src/cases.py --db /tmp/soc-cases.db show 1
python -m unittest discover -s soc-incident-case-lab/tests -v
```

Use a suitable writable path instead of `/tmp` on Windows.

## Data model

A `cases` table stores title, severity and current status. A `history` table records creation, notes, evidence references and status changes with UTC timestamps. The command-line interface only appends history entries; this is **not a tamper-proof audit log** against a user with database file access.

## Investigation workflow

Create a case from a synthetic detection finding, add an evidence reference, document validation and benign explanations, change to investigating, then close it after review. The tool does **not** automatically correlate other lab alerts or fetch event data.

## Security, testing and limitations

Tests cover case creation, history, valid and invalid status transitions, severity validation and unknown cases. No authentication, permissions, encrypted database, multi-user locking, attachments, or chain-of-custody assurance is implemented. **Do not use this lab to store patient data, passwords, or sensitive real-world incident evidence.** Designed for authorized synthetic training scenarios only.
