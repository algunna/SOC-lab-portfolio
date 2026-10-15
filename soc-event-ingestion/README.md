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

## Optional cross-run replay protection (offline lab)

The default `ingest.py` still performs **in-run** deduplication only. For a trusted, sanitized offline batch, explicitly run the new opt-in SQLite replay guard *after ingestion and before correlation*:

```bash
python soc-event-ingestion/src/ingest.py soc-event-contract/examples/windows_alert.json --out /tmp/ingested.json
python soc-event-ingestion/src/replay_guard.py --ingestion /tmp/ingested.json --state-db /tmp/soc-replay-state.db --out /tmp/filtered-run1.json
python soc-incident-correlation/src/correlate.py /tmp/filtered-run1.json --out /tmp/candidates1.json
```

For a later import, supply a newly generated ingestion report to the same `--state-db` and a **new** output filename. Repeated observations are omitted from `accepted` and counted as `persistent_replay` duplicates. Reuse of a source/event ID for different content, or a changed payload for an already seen record and rule, fails the whole batch without adding the conflicting observations to SQLite. No file is overwritten.

The state contains hashed observation identifiers, hashed event identifiers and canonical alert payload hashes, **not raw log bodies or notes**. Hashes are not anonymization; protect the database and derived reports. The new report retains the existing ingestion report shape so correlation can consume its `accepted` observations, and includes a `replay_guard` count.

**Limits:** This is an *offline, opt-in training safeguard*, not live streaming, durable queueing, alert attestation, exactly-once delivery, cryptographic authentication or production persistence. A process crash between the output file and database commit, manual removal of an output file, or a maliciously altered SQLite state can still cause loss, replay or inconsistency. Use trusted directories, keep files private, and do not attach live or sensitive telemetry. It does not approve incidents, modify the detector modules, or contact Splunk.

## Reliability 2.0 — offline batch health and sanitized quarantine (opt-in)

Use the new **batch-health gate** with already sanitized, synthetic alerts:

```bash
python soc-event-ingestion/src/batch_health.py soc-event-contract/examples/windows_alert.json --out-dir /tmp/soc-health-run-01
```

The output directory **must not already exist**. A successful run creates `health.json` with stage status and numeric counts, plus `ingestion.json` and `correlation.json` for downstream dashboard preparation. No automated case approval is performed.

If preflight, ingestion or correlation cannot safely process the **entire batch**, the gate instead produces **only** `health.json` and `quarantine.json`. Quarantine records contain stable reason codes, source *indices* and line numbers, **not original filenames, raw records, validation messages, passwords, actor names or evidence text**. Accepted records from a partially rejected batch are not published. The command exits with status **2** for a quarantined batch.

To retry, inspect and correct the original synthetic input **manually**, then use a *new* `--out-dir`. No background polling, automatic retry or overwrite occurs. Prior failed health/quarantine reports remain unchanged for investigation.

Safety limits: 1–8 existing regular `.json`/`.jsonl` files, each at most 1 MB and up to 2,000 accepted alerts. Symbolic-link inputs are rejected. The source input files are still read by the existing ingestion code, and **successful ingestion reports contain all schema-permitted alert data**; protect and sanitize them. The gate is not an authenticated provenance service, exactly-once transport, live Splunk connector, immutable audit log or a durable retry queue. File input may change between preflight and read, and an interrupted write can leave a partially written output directory. Use only trusted, private training data.

**Replay guard compatibility:** the optional cross-run SQLite replay guard remains separate, and this gate does **not** commit replay state. A future integrated, recoverable queue must coordinate state commits with delivery before production use.
