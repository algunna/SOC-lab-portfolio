# SOC Command Center — Read-Only Demo

A **local Python standard-library dashboard** displaying synthetic alerts, unverified incident candidates and investigation cases. This is a portfolio UI prototype, not a live SOC service.

## Run

```bash
python soc-command-center/src/dashboard.py
```

Then open http://127.0.0.1:8765/ in your browser. Stop with Ctrl+C.

## Scope and safeguards

- Fixed, synthetic JSON fixture loaded at startup. `--data` can point to another **trusted, sanitized** JSON fixture.
- Data model: `alerts` follow [SOC Event Contract v1](../soc-event-contract) (the fixture is checked against it in the tests); `candidates` follow the [correlation](../soc-incident-correlation) report; `cases` follow the [case lab](../soc-incident-case-lab) database. Missing values show as `—`.
- On screens up to 580 px wide, each table row is shown as a labelled card so no field is hidden off-screen.
- All display fields are HTML-escaped. No JavaScript, frontend dependencies, write routes, background agents, or remote APIs.
- Bound to loopback (127.0.0.1), and only requests addressed to `127.0.0.1`, `localhost` or `[::1]` on the dashboard port are answered (others get 421), so a DNS-rebinding web page cannot read it.
- Every response, including error pages, carries a restrictive Content Security Policy (with `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff` and `no-referrer`.
- GET or HEAD `/` (query strings ignored) renders the dashboard; other paths return 404; POST returns 405.
- Counts show demonstration fixture values, **not actual incidents, telemetry or response performance**.
- Do not expose this dev server to the Internet, use real sensitive data, or treat it as an authenticated production service.
- Live source detector integrations remain disabled. An explicit offline adapter option can read existing local SQLite case metadata without modifying the database.

## Tests

```bash
python -m unittest discover -s soc-command-center/tests -v
```

The tests start a real server on a free port and need `jsonschema` (`python -m pip install -r soc-event-contract/requirements.txt`). Review findings: [docs/TITAN_DASHBOARD_REVIEW.md](../docs/TITAN_DASHBOARD_REVIEW.md).

## Offline pipeline adapter

Run ingestion and correlation on sanitized synthetic alerts, then:

```bash
python soc-command-center/src/adapter.py --ingestion /tmp/ingest.json --correlation /tmp/correlate.json --out /tmp/dashboard.json
python soc-command-center/src/dashboard.py --data /tmp/dashboard.json
```

The adapter revalidates normalized alerts and verifies candidate alert references. It is read-only and does not query the SIEM, inspect live databases or perform actions. Case rows remain optional. Add `--cases-db /path/to/existing/cases.db` to read an **existing** local case database in SQLite read-only mode. Without it, the adapter continues to export an empty cases list. Only `id`, `title`, `severity` and `status` are displayed; history, evidence and analyst notes are never loaded. Missing or malformed databases fail closed, and more than 200 cases will be rejected rather than silently truncated. The adapter makes a one-time snapshot at launch; it does not stream live changes. Do not use confidential or patient data.


For a fully synthetic demonstration, run ingestion, correlation, explicit test-only case approval (`soc-case-promotion/src/promote.py --approve`), then run this adapter with the resulting database. The CI workflow verifies that sequence and checks that reading leaves the SQLite file unchanged.

## Offline batch-health observability (Reliability 3.0)

The optional `health_dashboard.py` is a **separate read-only local view** of the sanitized `health.json` produced by the [offline batch-health gate](../soc-event-ingestion/README.md). Create at least two synthetic batch outputs (one healthy, one intentionally quarantined), then start the dashboard from the repository root:

```bash
python soc-command-center/src/health_dashboard.py --runs /tmp/soc-healthy-batch /tmp/soc-quarantined-batch --port 8766
```

Open `http://127.0.0.1:8766/` on the same PC; Ctrl+C stops the server. On Windows, substitute your own local temporary batch directories. Order of `--runs` arguments controls the displayed `Run 1`, `Run 2`, etc.

The static snapshot shows counts for runs, passed, blocked, accepted, rejected, duplicates and unverified candidates plus a table of each run's status, stage and counts. It does **not** automatically monitor directories, refresh, retry, diagnose causes, correlate recovery runs, or access live Splunk.

**Privacy and access boundaries:** Only explicitly supplied `health.json` files are opened. Source paths and batch directory names are never displayed or included in the HTML. No `quarantine.json`, `ingestion.json`, case data, raw logs or credential files are read. Exactly the known version, mode, status, stage and nonnegative bounded integer count keys are permitted. Unknown keys, inconsistent status/counts, overly large files, symlinked input directories or health files, duplicate runs and malformed JSON fail closed. Each health report is limited to 4 KiB and at most 30 reports may be compared.

The HTTP server reuses the original loopback/Host-validation and restrictive security-header implementation; it has **no write routes**. File reads are a one-time snapshot at launch. The health data and counts are supplied by local synthetic batch runs, not independently authenticated evidence. Filesystem aliasing and time-of-check/time-of-use races remain out of production scope. Never expose the service to the Internet, or include protected/real workplace data in the test files.

A later passed run is **not** shown as recovery of a previous blocked run unless a future trusted run-linkage model is designed. Blocked batch `accepted` counts can represent validated input that was **not published** to the correlation output; interpret accordingly.

## Pipeline 9.0 — verified sealed-batch consumption

For an offline batch produced by the [batch-health gate](../soc-event-ingestion/README.md), use `--batch-dir` to **require verification** before preparing the Command Center snapshot:

```bash
python soc-event-ingestion/src/batch_health.py soc-event-contract/examples/windows_alert.json --out-dir /tmp/verified-soc-batch
python soc-command-center/src/adapter.py --batch-dir /tmp/verified-soc-batch --out /tmp/verified-soc-dashboard.json
python soc-command-center/src/dashboard.py --data /tmp/verified-soc-dashboard.json
```

This mode checks the final completion marker, fixed expected files, byte lengths, SHA-256 digests and health/correlation/ingestion counts. It reads the **exact report bytes that passed verification**, rather than checking a path and subsequently reopening it. Blocked batches, incomplete or altered reports, malformed counters and output paths inside the sealed batch directory are refused. The dashboard output is always an explicitly separate, new file; no automatic case promotion occurs. Optional `--cases-db` still reads only existing SQLite case metadata.

Existing `--ingestion ... --correlation ...` remains supported for **legacy trusted synthetic exercises**, but **does not verify sealed-batch provenance**. Do not use it as a substitute for the sealed mode when processing batch-health outputs. The two input styles cannot be combined.

**Security caveat:** The manifest is unkeyed SHA-256 metadata, not a signature or externally authenticated chain of custody. Someone who can alter both reports and manifest may forge consistent hashes. This does not eliminate symlink-parent swaps, concurrent modification outside the open file window, or establish a durable message queue. It is not an authorization mechanism, real-time ingestion or live Splunk telemetry.
