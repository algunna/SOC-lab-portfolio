# Shared SOC Event Contract (v1)

A **proposed**, offline normalized alert format for future integration of Windows, AWS CloudTrail, authentication, and case-management labs. No detector integration or automatic incident creation is implemented.

## Contents

- `schema/event.schema.json`: JSON Schema Draft 2020-12, required source provenance, severity, evidence references and optional ATT&CK hypotheses.
- `src/validate.py`: schema validator and source-scoped deduplication-key helper.
- `examples/windows_alert.json`: synthetic alert.
- `tests/test_contract.py`: positive and negative validation cases.

## Run from repository root

```bash
python -m pip install -r soc-event-contract/requirements.txt
python soc-event-contract/src/validate.py soc-event-contract/examples/windows_alert.json
python -m unittest discover -s soc-event-contract/tests -v
```

## Design decisions

- Events carry `schema_version: 1.0` and a unique, externally assigned `event_id`.
- `occurred_at` must be an RFC 3339 date-time with a timezone (`2026-10-14T12:00:00Z` or `...+02:00`). The validator checks this itself, because jsonschema only enforces `format` when optional packages are installed.
- No string field may contain control characters (newlines, tabs, escape codes), so alert text cannot forge extra lines in reports or IDs.
- `source.system` and `source.record_id` identify the originating observation.
- `rule_id` identifies the originating detection; `severity` is a triage category, **not a calibrated compromise probability**.
- `evidence` stores references and sanitized descriptions, not raw log payloads.
- `deduplication_key` is a *proposed* tuple of source, source record, and rule; it is not yet used in a pipeline.

## Security and limitations

Use authorized synthetic data. No database, bus, parser adapters, SIEM integration, or external API calls are included. JSON Schema validates shape, not truthfulness, event integrity, uniqueness, trusted provenance or maliciousness. Avoid embedding secrets, patient details or confidential telemetry in text fields. Titans may propose amendments to the schema in review before detector integrations begin.
