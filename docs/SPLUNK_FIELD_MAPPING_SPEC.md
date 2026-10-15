# Splunk Live-Lab Field Mapping — Review Specification (NOT deployed)

**Status: proposed / synthetic-only.** This is a design and test contract for a future authorized Splunk Enterprise or Splunk Cloud lab. The current `probe.py` retrieves **aggregate counts by sourcetype only**; it does not deliver event rows, saved-search results or detector verdicts. The `normalize.py` input is a **synthetic, pre-classified fixture** and is NOT a real Splunk API format. No SPL below has been installed or validated in a real Splunk instance.

## Separation of responsibilities

1. **Raw event source** — Windows test VM / Sysmon or Security events, isolated authentication lab, or an AWS sandbox account. Only data from systems the owner is authorized to test; never workplace, hospital or patient telemetry.
2. **Reviewed detector** — A specific, version-controlled SPL detection, independently tested on known-positive and known-negative fixtures. Detection logic, threshold, lookback window, scheduled execution, index/sourcetype permissions and field extraction **remain to be designed and verified**.
3. **Controlled result extraction** — A strictly selected and approved set of saved-search-result fields. This does not permit raw event export or arbitrary result columns. Do not assign `search_name` from a free-form field supplied by an event.
4. **Normalized SOC alert** — The existing synthetic `normalize.py` demonstrates the target output contract, *not* a permitted production ingestion implementation. Source provenance and approved detector identity must be validated independently before any non-synthetic mode.
5. **Review gate** — Contract validation, replay checks, bounded correlation into **unverified candidates**, an explicit analyst approval action for a case, and a read-only Command Center.

## Future event-source mapping decisions to verify at home

| Lab source | Intended detector class | Reviewed source-event fields to verify | Unknown / to test live |
| --- | --- | --- | --- |
| Windows Security / Sysmon test VM | `windows_encoded_powershell` | Event channel, EventID (e.g. 4688 or Sysmon process create), event record ID, `_time`, hostname, subject SID/account, process command flags | Which Windows audit policy / Sysmon config records the field? How are host SID, domain and EventRecordID namespaced? Is encoding actually suspicious after contextual review? |
| Controlled authentication lab | `auth_failed_login_burst` | Host, account, source address, auth event IDs, bounded event-time window, distinct underlying record identifiers | Exact threshold, success-after-failure interpretation, account normalization and grouping policy; benign negative samples |
| AWS sandbox CloudTrail | `aws_cloudtrail_logging_change` | CloudTrail `eventID`, `eventTime`, account ID, `eventSource`, `eventName`, role/user ARN and target resource | Which approved logging-change API names indicate meaningful risk? CloudTrail delivery delay, cross-account namespace and actor parsing |

These are **candidate fields for a future integration**. A Windows process-create EventID or a CloudTrail API name is not by itself a confirmed attack. The current synthetic `search_name` values represent hypothetical pre-classified detections, not a validated event-level mapping.

## Synthetic saved-search row contract (current)

| Accepted input | Limit / transformation | Failure behavior |
| --- | --- | --- |
| `search_name` | Exact allowlist: `windows_encoded_powershell`, `auth_failed_login_burst`, `aws_cloudtrail_logging_change` | Unknown search rejected; source row cannot supply detection rules or severity |
| `record_id` | 1–128 characters, alphanumeric plus `.`, `_`, `:`, `-`; deterministic namespaced output alert ID | Missing, malformed or duplicate observation rejected |
| `occurred_at` | RFC3339 offset-aware timestamp required by SOC Event Contract v1 | Invalid or timezone-less timestamp rejected |
| `actor`, `asset` | Optional, bounded allowlisted identifiers; copied after validation, **not anonymized** | Control characters and arbitrary free-form values rejected |
| `_raw`, `password`, `severity`, `rule_id`, arbitrary columns | **Not accepted** | Entire synthetic batch rejected before output |

Output includes locally mapped `rule_id`, `title`, `severity`, `attack_techniques`, namespaced `event_id`, and `splunk-synthetic:` evidence reference. This reference is **not** a trusted Splunk link, proof of logging, or established detector provenance. Require separately verified, stable source identifiers before adding a real connector.

## Local acceptance rehearsal (zero live connections)

From repository root, after installing `soc-event-contract/requirements.txt`:

```bash
python splunk-readonly-connector/src/readiness_matrix.py
python -m unittest discover -s splunk-readonly-connector/tests -v
```

Optional sanitized, summary-only report (new file, no overwrite):

```bash
python splunk-readonly-connector/src/readiness_matrix.py --out /tmp/synthetic-readiness-summary.json
```

The fixed scenario matrix is in [live_readiness_scenarios.json](../splunk-readonly-connector/fixtures/live_readiness_scenarios.json), and the runner is `splunk-readonly-connector/src/readiness_matrix.py`. Valid scenarios pass through the allowlisted normalizer → **batch-health ingestion + correlation** → verified sealed artifacts → read-only dashboard adapter. Invalid scenarios must be rejected at normalization; no cases are automatically created. Outputs summarize only scenario IDs and counts. The fixture matrix and CI are **not evidence of live connection success**.

## First authorized Splunk acceptance session — pending at home

1. Confirm Splunk installation with `Get-Service *Splunk*` in local PowerShell (or identify authorized Splunk Cloud access); never run commands against a workplace system.
2. Verify locally reachable HTTPS management origin, a trusted CA, permitted lab index and least-privilege token stored outside Git/chat.
3. Run count-only `probe.py` manually. Record its sanitized count result and errors without printing secrets.
4. Validate the exact Splunk version and responses, field extractions, detector SPL, known-good/known-bad event fixtures, auth scopes and provenance under least privilege.
5. Only after controlled results are validated, design a separate **real** read-only event-to-alert adapter with explicit authentication/trust, redaction and bounded pagination. Review it before implementation or connection to downstream artifacts.

**Do not claim that the synthetic field mapping is a deployed Splunk detector or that passing this rehearsal proves live SOC readiness.** See [Pipeline 10.0 acceptance](SOC_PIPELINE_10_ACCEPTANCE.md) and [Splunk at-home checkpoint](SPLUNK_HOME_CHECKPOINT.md) for additional security gates.

## Pipeline 15.0 — proposed, synthetic source-scoped record identities

The [controlled telemetry namespace lab](../controlled-telemetry-lab/README.md) now validates Windows tuples of `host/channel/lab-defined log_epoch/record_id` and CloudTrail tuples of `account_id/region/event_id`, producing only opaque, **unauthenticated synthetic** record identifiers and clock-review labels. The lab distinguishes equal record numbers after a synthetic Windows log reset and equal CloudTrail event UUIDs in different sandbox-account namespaces.

The input `log_epoch` is a training placeholder: it is NOT a verified Windows event field or automatically assigned by Splunk. Real collection must establish a defensible log generation identity rather than assuming record numbers never recur. CloudTrail uniqueness and regional delivery semantics must also be checked on authorized lab data. The summary does not authenticate either source; no live endpoint is queried.
