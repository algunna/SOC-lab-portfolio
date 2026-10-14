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
- SQLite stores a unique candidate ID mapping to prevent repeat promotions against the same database.
- Case creation, mapping, evidence references and approval note occur within one database transaction.
- The output case stays in `open` status and is not a finding of compromise.
- **No authentication verifies the analyst's identity**; the flag is a local human acknowledgment, not a security boundary.
- Correlation report JSON is not cryptographically authenticated or independently tied to raw log evidence; only use trusted synthetic files. Candidate IDs can change if batch membership changes, and logically duplicate incidents with different IDs remain possible.
- No networking, automatic remediation, background operations, encryption or production-grade concurrency protection.

The Titans should review input provenance, identity verification, duplicate semantics and audit integrity before integration into any real alert workflow.
