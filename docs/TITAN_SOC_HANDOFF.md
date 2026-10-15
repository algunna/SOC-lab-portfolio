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

## ATLAS — Offline end-to-end demo (PR pending)

- [SOC demo](../soc-demo/README.md) prepares synthetic events → ingestion → correlation → dashboard with **zero cases** by default. Only a separate command with `--approve-demo-case` creates one training case and then snapshots the read-only case metadata.
- Manifest SHA-256 checks guard against accidental local file changes, not maliciously forged provenance or user authentication. No live Splunk request, secret or production dataset is involved.
- Replay, tampering, missing manifest, manual approval and case audit are regression-tested. Independently review synthetic-vs-live provenance claims and operational limits.
- **Deferred home checkpoint:** [SPLUNK_HOME_CHECKPOINT.md](SPLUNK_HOME_CHECKPOINT.md). Owner is at work; do not ask for home PC operations until they return. No live SIEM connectivity verified.

## ATLAS — persistent offline replay safeguard (PR #32, merged)

- New optional `soc-event-ingestion/src/replay_guard.py` filters previously seen validated normalized alerts across invocations using SHA-256 identifiers and a local SQLite state database. Existing ingestion behavior stays unchanged unless explicitly enabled.
- Replays are skipped; conflicting reuse of source/event ID or observation identity fails the entire batch. Transaction rollback and unmodified output checks are included in regression tests.
- Limitations for independent review: SQLite file can be forged, hashes may be guessable, sidecar/concurrency edge cases, output/state crash window, lack of real message acknowledgement, missing queue/outbox, state durability and privacy. Do not advertise exactly-once semantics.
- Splunk home checkpoint remains pending; verify installation/authorized REST connectivity only when user returns home, and never ask for credentials in chat.

## ATLAS — Offline batch health and manual recovery (PR #33, merged)

- `soc-event-ingestion/src/batch_health.py` adds a separate, explicitly invoked offline gate with health counts/stage status. It publishes validated ingestion and correlation only on complete success; otherwise emits metadata-only `quarantine.json` + `health.json`.
- Redaction by design: quarantine issues have source indices, line numbers and categorical reasons only; no source paths, values, validation strings or raw logs. The gate never retries automatically, never touches replay state, never promotes a case and never calls Splunk.
- Titan security review: TOCTOU between preflight and input read, atomic multi-file publishing/crashes, symlink swaps, filesystem access controls, replay-state coordination, bounded memory/throughput and operational observability. **Not production durability or live telemetry.**
- Splunk home-PC checkpoint is still pending until the owner returns home; see the SOC demo README.

## ATLAS — Offline SOC observability snapshot (PR #34, merged)

- New `soc-command-center/src/health_dashboard.py` displays only strictly validated, metadata-only batch health reports as loopback-served HTML. It reads no alert, quarantine, SQLite, evidence, token or log content.
- Enforces 1–30 explicitly supplied health directories, 4 KiB per health file, status/stage consistency and bounded integer counts; rejects extra fields, malformed JSON, symlinks and repeated runs.
- CI generates healthy and blocked synthetic batch output and verifies a read-only dashboard summary without raw text exposure. Existing Host validation and security headers are reused.
- Titan review: snapshot authenticity, directory symlink parents and TOCTOU, meaningful health metrics beyond counts, monitoring/alerting semantics, cardinality bounds and anti-CSRF/read-only posture. **No live telemetry, polling, verified recovery tracking or production observability exists.**
- **Splunk setup remains deferred** per [home checkpoint](SPLUNK_HOME_CHECKPOINT.md).

## ATLAS — Offline batch artifact completeness (PR #35, merged)

- `soc-event-ingestion/src/artifact_integrity.py` creates a final `integrity.json` marker only after a batch has written its other files, pinning expected names, bounded sizes and SHA-256 digests.
- Read-only verification catches missing, unexpected, malformed, symlinked or changed outputs. Health status/stage and counters are validated. This covers both passed and quarantined offline runs.
- Integrity proof is only local change detection: an adversary who can edit both artifacts and the manifest can forge a consistent set. A crash between writes or before filesystem directory durability can leave unsealed or lost files; **no atomic multi-file commit, authenticated provenance, production guarantee or live SIEM connection**.
- Titan to review TOCTOU/symlink parent races, platform-specific durability semantics, privacy of diagnostic artifacts, manifest spoofing and integration with a future durable queue. Splunk at-home checkpoint is still pending.

## ATLAS — sealed batch consumption at dashboard boundary (PR #36, merged)

- Both the Command Center adapter and manual case-promotion CLI now support `--batch-dir` to enforce local hash/completeness checks, keep the verified report bytes in memory and refuse blocked/incomplete/tampered batches before creating a dashboard artifact or opening a case database. Case creation still requires an explicit `--approve` flag.
- Cross-checks sealed health counts against ingestion and correlation counts; never writes output inside the sealed directory. The legacy trusted synthetic `--ingestion/--correlation` mode remains but **does not** attest integrity.
- Regression tests include missing manifests, tampering, symlinked inputs, blocked batches, improper output locations, counter mismatch and explicit demonstration that forged unsigned manifests can fool local hash checks.
- Titan review: remaining file race and symlink-parent risks, local unsigned manifest authenticity, stronger cross-report consistency, limits on batch file sizes and case-promotion provenance boundary. Real Splunk setup remains deferred pending the home-PC checkpoint.

## ATLAS — Pipeline 10.0 semantic audit and home Splunk acceptance (PR #37, merged)

- Sealed batch consumption now validates normalized ingestion structure and exact counts, revalidates the accepted alerts, and independently recomputes correlation under the fixed batch-health policy, rejecting differences in all candidate fields even if a changed correlation file's SHA-256 manifest is refreshed.
- Added adversarial regression tests for forged candidate severities, IDs, evidence references, grouping reasons, alert references, duplicate IDs and malformed accepted records. Dashboard and manual case-promotion paths reject a rehashed but semantically forged candidate prior to output/database modification.
- [Pipeline 10.0 acceptance checklist](SOC_PIPELINE_10_ACCEPTANCE.md) distinguishes completed **offline** tests from pending live Splunk proof and records residual security risks. **No reviewer sign-off, production hardening or real SIEM verification is claimed.**
- Review priorities: verify source provenance, independently recomputed correlation’s fixed-window assumptions, handling of source namespaces, file races, untrusted event-content forgery, and how a durable queue would connect to real Splunk.

## ATLAS — Pipeline 11.0 synthetic Splunk live-readiness matrix (PR #38, merged)

- New fixed [field mapping spec](SPLUNK_FIELD_MAPPING_SPEC.md) differentiates hypothetical detector classes from actual Windows/Sysmon, auth and AWS CloudTrail event fields. All SPL/detectors, source event IDs, thresholds and response formats require real lab verification.
- Offline `splunk-readonly-connector/src/readiness_matrix.py` runs 12 synthetic cases: four positive scenarios through normalized alerts → sealed batch ingestion/correlation → integrity+semantic verification → read-only Command Center adapter, and eight fail-closed negative cases. A new CI check asserts sanitized results and `live_splunk_verified: false`.
- No API calls, no token, no unattended task, no raw event import or automatic incident promotion. The real Splunk installation and authorized probe are still pending at home.
- Titan/VORTEX review: detector fidelity, timestamp identity namespaces, late-arriving events, relation to pre-classified saved-search results, provenance, replay behavior, and real SPL/field extraction test design.

## ATLAS — Pipeline 12.0 synthetic detection policy assessment (PR #39, merged)

- `detection-accuracy-lab/` runs 32 curated policy scenarios directly against the existing Windows and AWS CloudTrail offline hunters and emits confusion counts for eight rule classes; these are NOT production detector accuracy estimates.
- Windows authentication correlation now skips records with missing/empty/unknown host, account or source IP to avoid joining unrelated audit gaps into a false positive success-after-failures finding. Dedicated detector and matrix regression tests added.
- Review questions: alert vs compromise labeling, realistic administrator/service-account baselines, duplicated/missing log IDs, NAT/proxy source ambiguity, hidden/obfuscated commands, detection threshold choices, CloudTrail delays and missing events. **No independent VORTEX/Titan sign-off yet.**
- Home Splunk installation and live telemetry evaluation are still pending.

## ATLAS — Pipeline 13.0 synthetic detector-to-alert handoff (PR #40, merged)

- Added `detection-accuracy-lab/src/to_soc_alerts.py`, which runs the actual Windows and AWS offline hunters against fixed labeled **synthetic** scenarios and creates schema-validated SOC alerts using code-owned metadata.
- No attempt to match raw records to outputs by guessing: stable alert and evidence IDs are derived from source fixture scenario, rule and repeated-finding index, explicitly labeled `lab-` / `synthetic-fixture:`. Real Windows EventRecordID, CloudTrail eventID and externally authenticated provenance are **not present**.
- CI verifies alert-contract validation and an end-to-end synthetic run through batch-health ingestion, correlation, integrity manifest, semantic recheck and read-only Command Center with no case creation. Unexpected detector decisions and malformed metadata fail closed.
- Reviewer priorities: stable ordering for multi-event findings, provenance, actor/host privacy, source identity collision across repeated exports, canonical timestamps, verified live detector logic and replay semantics. Home Splunk live check remains pending.

## ATLAS — Pipeline 14.0 replay-alias ledger (PR #41, merged)

- Replay guard now writes all observed source/event ID aliases, including alternate IDs seen on skipped observations, to an SQLite ledger. A later conflicting use of any known alias rejects the entire batch and rolls back attempted inserts.
- Legacy `observed` database records seed `event_aliases` on first use; conflict checks detect a mismatched legacy primary ID and alias mapping.
- The synthetic detector bridge keeps its stable fixture/rule alert IDs but includes a scenario-input SHA-256 hint in `synthetic-fixture:` evidence references. This catches source-input changes that still produce identical detector rule results. No authenticated original EventRecordID or CloudTrail eventID is represented.
- Review: atomic DB migration behavior, alias table index growth, delayed/reordered batches, rollback under real disk failure, unhashed metadata exposure elsewhere, source-event replay namespaces, source digest privacy/dictionary attacks, and lack of durable delivery confirmation. Live Splunk remains deferred.

## ATLAS — Pipeline 15.0 controlled source identity design (PR #42, merged)

- `controlled-telemetry-lab/src/source_identity.py` validates **synthetic only** source-scoped Windows host/channel/log_epoch/record number or AWS account/region/eventID and rejects ambiguous or malformed fields. `log_epoch` is lab-generated, not a real Windows field.
- Produces stable opaque `lab-src-` record identifiers, `synthetic-source:` reference hashes and offset-normalized UTC dates. Clock-review labels distinguish delayed arrivals and future timestamps without declaring malicious behavior.
- CI tests repeated record numbers after a Windows log reset, host/account namespace separation, duplicate collisions, invalid date/times, unknown fields, privacy and contract compatibility. No device authentication, Splunk REST queries, token exchange, real detection output or case creation.
- Independent VORTEX/Titan review and local Splunk service check remain pending. The synthetic hashing layer is not an authenticated chain of custody.

## ATLAS — Pipeline 16.0 synthetic source-to-alert handoff (PR pending)

- Added `controlled-telemetry-lab/src/to_soc_alerts.py` to turn strictly scoped synthetic source preflight outputs into **informational observation alerts**, using a code-owned fixed lab rule, `labobs-` event IDs and matching `synthetic-source:` references.
- The bridge fails closed on ambiguous source IDs, incomplete log generations, malformed times, unexpected source fields or conflicting evidence references; it never accepts client-supplied severity, detector rule, actor, asset or provenance claims.
- CI exercises six synthetic observations through the existing sealed batch-health and read-only Command Center pipeline, producing only six unverified informational candidates and no case creation. Timestamp changes retain stable source IDs for future replay conflict analysis.
- Reviewer warning: event identity remains entirely synthetic/unauthenticated; fixed informational rule is **not a security detection**. Real source-to-detector linkage, attested Splunk event IDs and collector authentication must be designed and tested after the owner's home-PC checkpoint.

## ATLAS — Pipeline 17.0 collector trust readiness

- Added a strictly offline trust-policy simulation and 18 adversarial tests, including sealed source-to-Command-Center integration. Credential and transport outcomes are test doubles, not verified authentication facts.
- Simulates fail-closed identity, credential status, transport, source validation and session-local replay checks. No network, real credentials, live telemetry or automatic incident cases.
- Review [trust boundaries and limitations](COLLECTOR_TRUST_READINESS.md), especially client-supplied assertion misuse, restart/concurrent replay, real issuer/revocation checks and collector identity versus source authenticity.
- Home-PC `Get-Service *Splunk*`, live connectivity/field mapping, and independent VORTEX/Titan review remain pending.

## ATLAS — Pipeline 18.0 durable offline delivery

- Added an atomic SQLite synthetic queue with persistent replay identities and verified local sealed receipts. Reuses replay key semantics without the separate replay DB/file commit boundary.
- Tests cover process death before/after acknowledgment, concurrent workers/imports, partial write rollback, corruption, unavailable processing and duplicate imports. No external exactly-once delivery claim.
- Review [durable delivery limits](DURABLE_DELIVERY_RECOVERY.md). Independent VORTEX/Titan review and home-PC Splunk checkpoint remain pending; no real collector enabled.

## ATLAS — Pipeline 19.0 offline health and audit

- Added read-only queue/receipt/audit verification and transactional schema-19 operational audit. Start/outcome records expose unresolved process crashes; successful acknowledgment and audit commit together.
- Review [health and audit boundaries](COLLECTOR_HEALTH_AUDIT.md): migration rollback, failed audit writes, historical gaps, local clock trust, cap exhaustion, and lack of tamper-proof storage.
- Independent VORTEX/Titan review and home-PC Splunk verification remain pending. No real collector, remote monitoring or automatic recovery enabled.

## ATLAS — Pipeline 20.0 live acceptance preparation

- Added [live acceptance requirements](LIVE_SPLUNK_ACCEPTANCE.md), an all-pending evidence checklist and a bounded offline structure validator. Synthetic evidence kinds and skipped prerequisites are rejected.
- Even complete evidence claims remain unverified, require manual inspection and never authorize collector enablement. Hashes do not establish authenticity.
- Home-PC Splunk, real adapter/authentication implementation, independent security review and the real event-to-case demonstration remain pending.

## ATLAS — PowerShell detector tuning

- Both Windows 4688 and Sysmon Event 1 hunters share quote-aware host-flag parsing and stop at explicit Command/File boundaries. Curated 14-case disagreements reduced from 9 to 0 per detector.
- Review [scope and limitations](POWERSHELL_DETECTION_TUNING.md), particularly command-body/nested execution coverage, native argv assumptions and version differences. No maliciousness or production accuracy claim.
- Home-PC Splunk and independent review remain pending.

## ATLAS — Authentication detector tuning

- Generic text detection now uses an inclusive five-minute window and source/account/event scope; both text and Windows detectors reset on every matching success. Four reproduced false-alert cases are fixed.
- Review [policy and remaining limitations](AUTHENTICATION_DETECTION_TUNING.md), especially duplicate source records, equal-time ordering, tenant namespaces and lost cross-account spray coverage.
- Live Splunk and independent security review remain pending.
