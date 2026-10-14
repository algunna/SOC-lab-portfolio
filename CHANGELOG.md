# Changelog

Notable portfolio changes are documented here. Entries describe **merged features**, not production deployments.

## Unreleased

- Added conservative offline SOC incident-candidate grouping and documented Titan handoff for detector integration review (PR pending).

- Added offline SOC Event Ingestion MVP with schema validation, in-run deduplication, synthetic tests and GitHub CI (PR pending).

- Proposed SOC Event Contract v1: normalized alert JSON Schema, validator, six tests and CI (ATLAS PR pending). No live detector integrations yet.

## 2026-10-14

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
