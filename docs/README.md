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
