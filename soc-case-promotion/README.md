# Manual SOC Case Promotion

This offline training lab bridges [unverified correlation candidates](../soc-incident-correlation) with the [SQLite case manager](../soc-incident-case-lab). **Promotion is never automatic.**

## Example commands

```bash
python -m pip install -r soc-event-contract/requirements.txt
python soc-event-ingestion/src/ingest.py soc-event-contract/examples/windows_alert.json --out /tmp/soc-ingested.json
python soc-incident-correlation/src/correlate.py /tmp/soc-ingested.json --out /tmp/soc-candidates.json
# Read the candidates report and choose the printed candidate_id, then:
python soc-case-promotion/src/promote.py /tmp/soc-candidates.json --db /tmp/soc-cases.db --candidate-id YOUR_CANDIDATE_ID --analyst demo-analyst --approve
python -m unittest discover -s soc-case-promotion/tests -v
```

Select a candidate ID from the report; it is intentionally not guessed. Change file paths for Windows.

## Controls and limitations

- Explicit `--approve`, analyst identifier and exact candidate ID are required.
- The candidate must be marked `unverified` and include alert IDs.
- SQLite stores unique candidate ID and alert mappings. A candidate is refused if its ID, or any of its alerts, was already promoted in the same database; this also catches a re-run that gives the same alerts a new candidate ID. The error names the overlapping alerts, and any new alerts in that candidate must be added to the existing case by hand.
- The case severity defaults to the candidate's highest alert severity (`informational` becomes `low`); `--severity` overrides it. The case title names the actor and asset when the candidate has them.
- Case creation, mapping, evidence references and approval note occur within one database transaction.
- The output case stays in `open` status and is not a finding of compromise.
- **No authentication verifies the analyst's identity**; the flag is a local human acknowledgment, not a security boundary.
- Correlation report JSON is not cryptographically authenticated or independently tied to raw log evidence; only use trusted synthetic files. Candidate IDs can change if batch membership changes; alerts already in a case are blocked, but two cases about the same activity are still possible when they share no alert.
- No networking, automatic remediation, background operations, encryption or production-grade concurrency protection.

The Titans should review input provenance, identity verification, duplicate semantics and audit integrity before integration into any real alert workflow.

## Verified sealed batch (Pipeline 9.0)

For batch-health output, **verify completion and integrity before promoting a candidate**. Only an explicitly approved candidate can create a case, and the SQLite database must be outside the sealed batch:

```bash
python soc-event-ingestion/src/batch_health.py soc-event-contract/examples/windows_alert.json --out-dir /tmp/soc-approved-batch
# Inspect the unverified candidates in /tmp/soc-approved-batch/correlation.json
python soc-case-promotion/src/promote.py --batch-dir /tmp/soc-approved-batch --db /tmp/soc-cases.db --candidate-id YOUR_CANDIDATE_ID --analyst demo-analyst --approve
```

The new `--batch-dir` option checks the completion marker, SHA-256 hashes, expected files and health/report counters, consumes the verified bytes and rejects blocked/incomplete/tampered batches **before opening or creating the SQLite case database**. It cannot be combined with the positional legacy report argument. A batch hash is still **not authenticated provenance or analyst authentication**; a user with write access to the files and manifest can forge both. The original positional correlation report input is retained solely for trusted synthetic/legacy exercises, without integrity guarantees. No automatic case creation or live Splunk connection occurs.

## Pipeline 10.0 review gate

Sealed case promotion additionally benefits from independently recomputed, schema-validated candidates. A case with a forged severity, evidence reference or candidate identity no longer passes just because its unsigned manifest was updated to match. The local approval flag remains necessary but is not a verified analyst identity. See the [live acceptance and residual risks](../docs/SOC_PIPELINE_10_ACCEPTANCE.md).
