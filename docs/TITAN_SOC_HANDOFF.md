# Titan Handoff — SOC Event Contract, Ingestion and Correlation

**Owner:** ATLAS workstream. **Scope:** `soc-event-contract/`, `soc-event-ingestion/`, and `soc-incident-correlation/`. **No Titan detection modules edited.**

## ATLAS update — bounded correlation (PR pending)

- Revalidates accepted events against the SOC Event Contract before grouping.
- Uses 15-minute fixed UTC event-time windows by default; timezones are normalized before comparisons.
- Rejects duplicate source-system/event IDs, invalid inputs, and reports containing rejected events.
- Please challenge the conservative exact-match grouping and fixed-window semantics with cross-source examples. No detector adapters or automatic case promotion exist yet.

## Current state
- PR #19 merged: normalized JSON Schema v1 plus timestamp validation and tests.
- PR #20 merged: offline JSON/JSONL ingestion, per-run deduplication by source system + record ID + rule ID, explicit rejection report and tests.
- This PR: offline conservative incident-*candidate* grouping plus regression tests. It does not import or connect real CloudTrail, Windows, SSH, or Copilot detector modules.
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
- Should incident candidates be promoted to SQLite cases only by human approval?

ATLAS recommendation: review detections first, agree on schema adapter mapping, add strict bounded temporal grouping and provenance checks **before** connecting automatic case creation.
