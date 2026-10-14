# Splunk Read-only Connector — Opt-in Connectivity Probe

This **opt-in** client uses Splunk's search/export REST endpoint over HTTPS to retrieve **event counts grouped by sourcetype** from an explicitly authorized index. It does not download raw events, create SOC alerts, mutate Splunk data, or connect to the Command Center yet.

## Offline test (no Splunk required)

```bash
python -m unittest discover -s splunk-readonly-connector/tests -v
```

Mock requests verify the fixed, read-only SPL; TLS endpoint restrictions, output redaction, size limits and injection resistance. **These tests do not validate credentials, Splunk API connectivity, index permissions, or live server compatibility.**

## Authorized live lab — manually initiated only

1. Set up a Splunk instance or authorized lab account. Use a least-privileged token scoped to the designated lab index and search capability. Never expose the management port publicly.
2. Trust the server's CA certificate. Do not turn off TLS verification; use `--ca-cert` for a lab's self-signed CA if appropriate.
3. Store the credential only in your local environment:

```bash
# Example: set SOC_SPLUNK_TOKEN securely in your local shell (do not commit it).
python splunk-readonly-connector/src/probe.py --endpoint https://127.0.0.1:8089 --index soc_lab --minutes 15 --out /tmp/splunk-summary.json
```

The command refuses to run without `SOC_SPLUNK_TOKEN`. An existing output file cannot be overwritten. On Windows, use a suitable private output location. Optionally add `--ca-cert /path/to/splunk-ca.pem`.

## Security contract

- A manually supplied **HTTPS origin and explicit port** is required. URLs containing embedded credentials, arbitrary paths, queries or fragments are rejected.
- Authorization is via the `SOC_SPLUNK_TOKEN` environment variable, never the URL or repository.
- No redirects: authorization headers cannot be forwarded to a redirected host.
- TLS certificate verification is required; no insecure bypass exists.
- Fixed SPL: `search index=<validated_index> earliest=-15m latest=now | stats count by sourcetype | sort - count | head 25`. An allowlisted index name and bounded time window are the only variable query terms.
- The result stores only `sourcetype` and integer `count` for up to 25 groups. Extra Splunk fields such as `_raw` are discarded.
- HTTP response is limited to 256 KB; errors suppress server text and token values.

**Current limitations:** This is not a live event stream, not an alert normalizer, not a full SIEM ingestion connector, and has not yet been verified against a real Splunk deployment. Token permissions, CA trust, index mapping and query behavior must be tested in an authorized instance. Even metadata can reveal operational details; safeguard the output JSON.

## Next milestones

Only after controlled live connectivity is verified: implement a separately reviewed field mapping into SOC Event Contract v1 using strictly synthetic or authorized, sanitized events, then attach it to the existing validation/correlation pipeline. Keep case promotion manual and dashboard read-only.

## Offline synthetic saved-search alerts to SOC pipeline

This separate adapter demonstrates a bounded **synthetic alert** handoff. It does **not** connect the Splunk REST API to raw-event detection or assert that a saved search has been deployed. The count-only HTTPS probe remains separate.

From repository root, install the validator dependency and run the synthetic fixture:

```bash
python -m pip install -r soc-event-contract/requirements.txt
python splunk-readonly-connector/src/normalize.py splunk-readonly-connector/fixtures/synthetic_saved_search_alerts.jsonl --out /tmp/splunk-alerts.jsonl
python soc-event-ingestion/src/ingest.py /tmp/splunk-alerts.jsonl --out /tmp/splunk-ingestion.json
python soc-incident-correlation/src/correlate.py /tmp/splunk-ingestion.json --out /tmp/splunk-candidates.json
python soc-command-center/src/adapter.py --ingestion /tmp/splunk-ingestion.json --correlation /tmp/splunk-candidates.json --out /tmp/splunk-dashboard.json
python soc-command-center/src/dashboard.py --data /tmp/splunk-dashboard.json
```

On Windows, use a private temporary directory instead of `/tmp`.

Input is UTF-8 JSONL, up to 200 alerts and 1 MB in total, with these exact fields: `search_name`, `record_id`, `occurred_at` (RFC3339 with timezone), and optional `actor`, `asset`. Unknown columns, including `_raw`, `password`, and `severity`, are rejected. Currently allowlisted search names are `windows_encoded_powershell`, `auth_failed_login_burst`, and `aws_cloudtrail_logging_change`. Rule IDs, severities, titles, and MITRE techniques are assigned by local reviewed mappings, never claimed by arbitrary source data.

Each result is validated against SOC Event Contract v1 and assigned a stable namespaced ID and *synthetic* opaque evidence reference. This output is an **unverified investigation lead**, not a verified intrusion. Conversion fails closed on a duplicate ID, invalid identity, unknown detector, control character, malformed JSON, bad timestamp or oversized input. A failed batch never produces a new output file. Existing outputs are not overwritten.

**Data minimization:** Do not feed raw logs, personal information, real patient data, API keys or production SIEM exports into this synthetic training adapter. Actor/asset values are copied after structural validation, **not anonymized**. It intentionally has no API request, network listener, secret access, privilege escalation or automatic case promotion. Real Splunk event mapping, authorization checks, deduplication across multiple live batches and provenance validation still require additional design and live-lab tests.
