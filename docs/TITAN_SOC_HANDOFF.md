# Titan Handoff — SOC Event Contract, Ingestion and Correlation

**Owner:** ATLAS workstream. **Scope:** `soc-event-contract/`, `soc-event-ingestion/`, `soc-incident-correlation/`, `soc-case-promotion/` and `soc-command-center/`. **No Titan detection modules edited.**

## ATLAS update — bounded correlation (PR #22, merged)

- Revalidates accepted events against the SOC Event Contract before grouping.
- Uses 15-minute fixed UTC event-time windows by default; timezones are normalized before comparisons.
- Rejects duplicate source-system/event IDs, invalid inputs, and reports containing rejected events.
- Please challenge the conservative exact-match grouping and fixed-window semantics with cross-source examples. No detector adapters or automatic case promotion exist yet.

## ATLAS update — Manual case promotion (PR #23, merged)

- New isolated `soc-case-promotion/` requires explicit `--approve`, analyst string, candidate ID, and writes a SQLite mapping and case audit in one transaction.
- Unique candidate ID prevents repeated promotion in the same database, but IDs may change with batch composition; it is NOT semantic incident deduplication.
- Reviewer priorities: validate provenance of correlation reports, analyst authentication requirements, transaction safety, concurrency, case ID mapping, and evidentiary integrity before production use.
- The pipeline does not automatically create cases or ingest Titan detector output.

## ATLAS update — Read-only SOC dashboard (PR #24, merged)

- Added `soc-command-center/` as a standalone Python loopback HTTP demo with synthetic JSON only.
- No detector or case database reads, no write endpoints, no live alert indicators. HTML escapes all display fields.
- Please review UI data contracts, display semantics, evidence provenance, and potential risks of connecting live data in future.

## Titan review status

- **Items 2 and 3 below** (CloudTrail and Copilot correctness) and fixes to ingestion, correlation and promotion were addressed in merged PR #18.
- **Dashboard (PR #24):** Titan findings are in [TITAN_DASHBOARD_REVIEW.md](TITAN_DASHBOARD_REVIEW.md); follow-up PR #25 has been merged.

## ATLAS update — SQLite case snapshot (PR pending)

- Optional `--cases-db` reads only case ID, title, severity and status from an *existing* SQLite file in read-only mode; no history, private notes or evidence text is read.
- Fail-closed schema and row validation; max 200 cases; absent file must not be created; synthetic CI verifies database hash stays unchanged.
- Titan review requests: SQLite WAL concurrency/sidecar behavior, malformed/corrupt databases, data minimization, duplicate case display semantics and privacy before any live feed.

## Current state
- PR #19 merged: normalized JSON Schema v1 plus timestamp validation and tests.
- PR #20 merged: offline JSON/JSONL ingestion, per-run deduplication by source system + record ID + rule ID, explicit rejection report and tests.
- PR #21 merged: offline conservative incident-*candidate* grouping; PR #22 merged: bounded UTC windows and input validation.
- PR #23 merged: manual, analyst-approved promotion of candidates into SQLite cases.
- PR #24 merged: read-only SOC Command Center dashboard.
- None of these import or connect real CloudTrail, Windows, SSH, or Copilot detector modules.
- These are synthetic lab implementations, **not production-integrated**.

## Please independently review

1. **Schema compatibility:** Does each detector have stable record IDs, consistently normalized timestamps, actor/asset values, and meaningful evidence references? Flag mismatches before writing adapters.
2. **CloudTrail correctness:** Complete the separately identified private/public IP categorization, IAM privilege escalation, and root-activity grouping fixes. Document regression fixtures and avoid exporting inaccurate conclusions into normalized alerts.
3. **Copilot correctness:** Document concrete bugs, fixed behavior and tests; preserve offline/safe handling of untrusted log text.
4. **Grouping safety:** Exact system+actor+asset equality can over-group unrelated events; a bounded 15-minute fixed window now exists. Recommend bounded windows, provenance policy, namespace of identities, trust assumptions, deduplication behavior across runs, and stable IDs.
5. **Data integrity:** Rejected records currently prevent correlation for the whole batch; consider whether a quarantined partial-processing model is preferable. Examine accepted-event trust and schema revalidation before production use.
6. **Analyst workflow:** Clarify severity calculation, candidate versus case transition, false positives, evidence retention and audit requirements.
7. **Test evidence:** Run unit suites and synthetic integration examples, record precise commands/outputs/commit SHA. Submit findings in a separate review/PR; do not merge or edit ATLAS branches.

## Shared conventions

Continue working on a **new Titan-named branch derived from current main**, submit independent PRs, and do not modify AETHERION. No secrets, sensitive real incident content, or unsafe auto-response operations.

## Questions requiring team decision

- Should correlations be scoped to a 5, 15, or 30-minute sliding/rolling window, or per-rule policy?
- How should AWS account, Windows SID and SSH user identities be namespaced to avoid collisions?
- Should malformed rows block processing, or permit sanitized partial results under explicit quarantine?
- ~~Should incident candidates be promoted to SQLite cases only by human approval?~~ Decided in PR #23: yes, explicit `--approve` only.

ATLAS recommendation: review detections first, agree on schema adapter mapping, add strict bounded temporal grouping and provenance checks **before** connecting automatic case creation.

## ATLAS — Pipeline-to-dashboard adapter (PR #26, merged)

- Added offline adapter converting validated ingestion and correlation outputs into the dashboard JSON contract.
- Rejects malformed alerts, rejected ingestion batches, duplicate event IDs, invalid candidates and missing candidate references.
- Live SIEM connectivity remains out of scope; a separate opt-in read-only SQLite case snapshot is proposed in Pipeline 6.0. Review cross-source identity collisions, provenance and incident reference integrity before enabling live feeds.

## ATLAS — Opt-in Splunk SIEM connectivity probe (PR pending)

- New `splunk-readonly-connector/` runs an explicitly invoked, fixed, read-only SPL query over validated HTTPS with a token from the `SOC_SPLUNK_TOKEN` local environment variable.
- No live call is made in CI. Tests inject mock HTTP responses, reject insecure origins and injection attempts, and verify raw event fields are excluded from the returned summary.
- Please review least-privilege Splunk capability requirements, HTTPS trust, redirect handling, query bounds, metadata disclosure, and required event-field mapping before any SIEM-to-alert integration.
- Real Splunk connection and field mappings are not yet verified. No production telemetry or tokens belong in this repository.

## ATLAS — Synthetic Splunk alert normalizer (PR pending)

- New offline `splunk-readonly-connector/src/normalize.py` accepts only three locally allowlisted synthetic saved-search alert categories, validates bounded JSONL and normalizes to SOC Event Contract v1. It never imports raw SIEM exports, fetches remote records or assigns incidents automatically.
- Integration CI runs saved-search fixture → normalization → ingestion → correlation → read-only dashboard output. Data type mappings are **hypotheses for synthetic tests**, not verified deployed SPL detection outputs.
- Review before a live connector: evidence provenance, Splunk saved-search response formats and extraction fields, true detection thresholds, permissions/least-privilege, multi-batch replay/deduplication, redaction, source identity collisions and deterministic ID stability.
- Continue to require analyst approval for promotion and preserve no raw-log export in count-only probe.
