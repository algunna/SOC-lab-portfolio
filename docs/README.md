# SOC Portfolio Documentation

This directory holds shared engineering documentation for the training portfolio.

## Start here

- [Documentation standard](DOCUMENTATION_STANDARD.md) — required headings and evidence rules for lab READMEs.
- [Project README template](PROJECT_TEMPLATE.md) — copy when creating new labs.
- [Testing and evidence](TESTING_AND_EVIDENCE.md) — how to verify code and cite CI runs.
- [Architecture overview](ARCHITECTURE.md) — source-to-finding flow and current boundaries.
- [Code audit (2026-10-14)](SOC_CODE_AUDIT_2026-10-14.md) — existing audit findings and follow-up risks.
- [Changelog](../CHANGELOG.md) — merged developments.

Existing projects retain their own README files. Standards apply to new or modified projects; legacy documentation can be upgraded incrementally.

## Pipeline 10.0: offline audit and live Splunk acceptance

- [Security findings and live Splunk acceptance gate](SOC_PIPELINE_10_ACCEPTANCE.md) — separates verified offline lab behavior from the pending home-PC live telemetry requirements, records residual risks and independent review topics.

## Splunk live-lab preparation

- [Synthetic Splunk field mapping and readiness specification](SPLUNK_FIELD_MAPPING_SPEC.md) — proposed Windows/auth/CloudTrail source fields, 12-scenario offline acceptance matrix, and explicit requirements for the first authorized home-PC test.

## Synthetic detection accuracy review

- [Detection-policy confusion matrix lab](../detection-accuracy-lab/README.md) — 32 labeled synthetic Windows/CloudTrail scenarios, including benign administrative controls; no live accuracy claims.

## Pipeline 13.0 integration

- [Synthetic Windows/CloudTrail detector to SOC event bridge](../detection-accuracy-lab/README.md) — reviewed offline findings become contract-valid, synthetically referenced alerts for the sealed Command Center path; no live event feed or authenticated evidence.

## Pipeline 15.0 source provenance design

- [Controlled synthetic source identity lab](../controlled-telemetry-lab/README.md) — Windows log-epoch and CloudTrail account/region namespace mapping, offset-aware UTC normalization, collision tests and provenance limitations; no live telemetry authentication.

## Pipeline 16.0 source-to-alert compatibility

- [Synthetic identity-to-informational-alert handoff](../controlled-telemetry-lab/README.md) — validates source identity, creates contract-compatible informational observations, and verifies sealed ingestion/Command Center delivery without live source claims.

## Pipeline 17.0 collector trust readiness

- [Collector trust design and offline adversarial rehearsal](COLLECTOR_TRUST_READINESS.md).

## Pipeline 18.0 durable delivery and recovery

- [Durable synthetic queue and verified local receipt recovery](DURABLE_DELIVERY_RECOVERY.md).

## Pipeline 19.0 collector health and reliability

- [Read-only collector queue health and local operational audit](COLLECTOR_HEALTH_AUDIT.md).

## Pipeline 20.0 live acceptance preparation

- [Live Splunk acceptance runbook and pending evidence checkpoints](LIVE_SPLUNK_ACCEPTANCE.md).

## Detection tuning

- [PowerShell quoted host flags and command/script boundary regression](POWERSHELL_DETECTION_TUNING.md).
