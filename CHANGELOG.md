# Changelog

Notable portfolio changes are documented here. Entries describe **merged features**, not production deployments.

## Unreleased

- Added 12 fixed synthetic Splunk live-readiness scenarios, a no-network end-to-end rehearsal using sealed offline SOC batches, and proposed field mappings with explicit unverified prerequisites (PR pending).


- Audited Pipeline 10.0 sealed batch semantics; reject rehashed but altered candidate identity/severity/evidence/grouping by independently recomputing correlation from validated accepted alerts. Added negative tests and a live Splunk acceptance gate document (PR pending).


- Added optional sealed batch consumption in the offline SOC Command Center adapter, validating completion and using exactly the verified report bytes; rejects altered/blocked/incomplete batch inputs (PR pending).


- Added bounded SHA-256 artifact verification and a final completion marker for successful and quarantined offline batch-health runs; rejects partial or altered output directories (PR pending). Not a digital signature or durable transaction.


- Added read-only offline SOC batch observability view with bounded, strict health-report schema; sanitized summary counters and integration tests for healthy and quarantined runs (PR pending).


- Added opt-in offline SOC batch health reporting, metadata-only quarantine and explicit manual recovery controls, plus end-to-end regression tests (PR pending). Does not connect to live Splunk or automatically retry.


- Added opt-in SQLite replay guard for synthetic normalized SOC ingestion reports, fail-closed conflict detection, transactional state updates and regression tests (PR pending). Not a live SIEM or exactly-once transport.


- Added a one-command synthetic SOC pipeline demo with separate opt-in analyst approval, artifact integrity checks, repeatable CI and home Splunk setup checkpoint (PR pending). No live SIEM operations.


- Added allowlisted offline Splunk synthetic saved-search alert normalization into SOC Event Contract v1, with adversarial tests and an integration path to the read-only Command Center (PR pending). Live Splunk feed and raw event mapping remain out of scope.


- Added optional Splunk HTTPS event-count probe with allowlisted SPL, least-privilege credential guidance, mock-only tests and no raw-log export (PR pending).


- Added optional bounded, read-only SQLite case snapshot support to offline SOC dashboard adapter, with regression tests and a synthetic approval-to-dashboard CI workflow (PR pending).


- Added offline pipeline-to-dashboard adapter and regression tests (PR pending).

- SOC Command Center review fixes (PR pending): the fixture and columns now follow SOC Event Contract v1 (real alerts rendered a Python dict), requests for other Host names are refused (DNS rebinding), every response carries the security headers, the phone layout shows every field, startup errors are one-line messages, and HTTP-level tests were added. Findings: docs/TITAN_DASHBOARD_REVIEW.md.

- Added a local read-only SOC Command Center demonstration UI using synthetic fixtures (PR pending).

- Added manual, analyst-approved promotion from unverified incident candidates into SQLite cases, with duplicate safeguards and CI (PR pending).

- Hardened offline incident candidate grouping with contract revalidation, UTC fixed-window correlation and additional edge-case tests (PR pending).

- Added conservative offline SOC incident-candidate grouping and documented Titan handoff for detector integration review (PR pending).

- Added offline SOC Event Ingestion MVP with schema validation, in-run deduplication, synthetic tests and GitHub CI (PR pending).

- Proposed SOC Event Contract v1: normalized alert JSON Schema, validator, six tests and CI (ATLAS PR pending). No live detector integrations yet.

## 2026-10-14

- Case promotion fixes (PR pending): a critical alert became a medium case because promotion ignored the candidate's severity, and the same alerts could be promoted into a second case after a re-run changed the candidate ID. Severity now follows the candidate, promoted alerts are tracked, and the CLI gives usage errors instead of tracebacks.
- Ingestion and correlation fixes (PR pending): ingestion accepted two alerts sharing an `event_id`, which made correlation refuse the batch; it now rejects the reuse and reports skipped duplicates. Correlation candidates now show actor, asset, time range, highest severity and rules, and the CLI gives usage errors instead of tracebacks.
- Fixed findings from a five-part review (detection, red team, security, SOC operations, QA) (PR pending): PowerShell `-e`/`-ec` and other switch abbreviations were missed by the Windows, Sysmon, Sigma and Splunk detections; an attacker-chosen SSH username could spoof the source IP; AWS correlators reported only the first episode per actor and missed common privilege-escalation events; mixed timezone offsets crashed or misordered CloudTrail correlation; reports could be forged by log content; stale AI-era sample reports and a personal EVTX file were removed. Added tests and CI for the threat-intel and two legacy labs. Validated on synthetic data only. An OpenAI API key remains in Git history and must be revoked by the owner.
- Fixed CloudTrail SOC Pipeline detections (PR pending): private IPs were labelled public, public IPv6 root activity was not escalated, IAM privilege and credential changes and CloudTrail logging changes were not detected, and root alerts were split across two incidents. Added a synthetic fixture, tests, CI and a rewritten README. Validated on synthetic data only.
- AI SOC Copilot cleanup (PR pending): replaced the stale AI-generated sample report with current script output, removed the unused `openai` requirement and added CI for the existing tests.
- Added offline SOC incident case management lab with SQLite cases, evidence references, audit history and tests (PR pending).

- Added Splunk SOC Hunting examples with three read-only SPL searches, analyst playbooks and structural CI checks (PR pending). Search syntax has not been validated in a live Splunk instance.

- Added tested Windows Threat Hunting lab (PR #10), including normalized event detections and synthetic fixtures.
- Added AWS CloudTrail Threat Hunting lab (PR #11), CloudTrail 2.0 correlation (PR #12), and account-aware triage scoring (PR #13), with GitHub Actions checks.
- Added experimental Sigma Detection Engineering lab (PR #14), synthetic positive/negative test cases and a limited validation tool.
- Replaced hard-coded Sysmon and phishing findings with evidence-based offline workflows (PR #8).
- Updated IOC classification to avoid unsupported reputation claims, with documented code audit (PR #7).

## Earlier maintenance

- Refreshed main project descriptions and repository navigation (PR #4).
- Clarified Windows Sysmon and AI log summarizer documentation (PR #5).
- Reworked AI SOC Copilot for offline authentication analysis and regression testing (PR #6).

## Conventions

- Add an entry for each significant merged change.
- Link PRs, document changed behavior, and distinguish tests from real deployment evidence.
- Do not claim security fixes removed credentials from Git history without verification.
