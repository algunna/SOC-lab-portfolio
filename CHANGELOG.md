# Changelog

Notable portfolio changes are documented here. Entries describe **merged features**, not production deployments.

## Unreleased

- Hardened offline incident candidate grouping with contract revalidation, UTC fixed-window correlation and additional edge-case tests (PR pending).

- Added conservative offline SOC incident-candidate grouping and documented Titan handoff for detector integration review (PR pending).

- Added offline SOC Event Ingestion MVP with schema validation, in-run deduplication, synthetic tests and GitHub CI (PR pending).

- Proposed SOC Event Contract v1: normalized alert JSON Schema, validator, six tests and CI (ATLAS PR pending). No live detector integrations yet.

## 2026-10-14

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
