# Offline SOC Event Ingestion MVP

Consumes **normalized** alert JSON or JSONL, validates against [SOC Event Contract v1](../soc-event-contract), skips duplicate source observations for the same detection rule, and produces a local JSON report. This is not a detector adapter or SIEM connection.

## Run

```bash
python -m pip install -r soc-event-contract/requirements.txt
python soc-event-ingestion/src/ingest.py soc-event-contract/examples/windows_alert.json --out /tmp/soc-ingestion-output.json
python -m unittest discover -s soc-event-ingestion/tests -v
```

Use an appropriate writable destination on Windows. Output is created with exclusive mode to avoid overwriting an existing report.

## Processing and data protection

Inputs are read as local UTF-8 files. Invalid rows are quarantined in the `rejected` array with their source path, line number, and validation errors; malformed JSON is not echoed. **Validation errors can still include submitted field values**, and accepted alerts include all schema-permitted text. Therefore use synthetic/sanitized input only and protect generated reports.

Deduplication uses the tuple (`source.system`, `source.record_id`, `rule_id`) within **one run only**. Skipped duplicates are listed in the report's `duplicates` array (file, line, event ID) and counted in `counts.duplicates`; nothing is persisted across executions. An alert that reuses another alert's `event_id` from the same source system for a different observation is rejected, because event IDs must be unique and [SOC Incident Correlation](../soc-incident-correlation) refuses batches that repeat one. There is no automatic incident creation, authentication, file-integrity assurance, isolation, concurrency control, rate limiting, alert transport, or error recovery queue. Exit code 2 indicates that one or more rows were rejected even if accepted rows were written.

## Boundaries

The Titans are reviewing current detectors; **this lab does not import or modify CloudTrail, Windows, authentication, or AI SOC Copilot detection modules**. No claims are made about live ingestion, reliable production deduplication, accurate detections, or correlation.
