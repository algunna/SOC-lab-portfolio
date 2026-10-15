# SOC Pipeline 12.0 — Offline Detection Accuracy and False Positive Tests

**Scope:** Synthetic, curated policy expectations only. This is NOT a measured real-world detection rate, a validated Splunk detector, or a claim that any scenario is truly malicious.

The [labeled scenarios](fixtures/labeled_scenarios.json) exercise the **actual offline Windows** and **AWS CloudTrail** hunter implementations, not mocked detector verdicts. Every event is synthetic. The runner compares each detector's returned rule IDs to the expected rule IDs in the fixture and produces a summary-only confusion matrix for every rule.

## Run locally (no accounts, services or credentials needed)

From repository root:

```bash
python detection-accuracy-lab/src/evaluate.py
python -m unittest discover -s detection-accuracy-lab/tests -v
```

For a sanitized JSON summary in a new file only:

```bash
python detection-accuracy-lab/src/evaluate.py --out /tmp/synthetic-detector-policy.json
```

The runner does not contact Splunk, Windows endpoints, AWS, the network, or a case database. It runs source-local Python functions on synthetic objects and removes no files. It exports only rule names, counts, scenario IDs and mismatches (never full event bodies, user names, hostnames, IPs or command lines).

## Coverage and interpretation

The 32 reviewed synthetic scenarios comprise **22 Windows** and **10 CloudTrail** cases. Each of the eight implemented offline rule types has both positive and negative cases. Positive expectations represent *signals for further analyst review*, not confirmed compromise:

| Offline detector rule | Positive signals under test | Important benign interpretations and limitations |
| --- | --- | --- |
| Windows `suspicious_powershell` | Encoded command abbreviations, bypass or hidden-window flags | Administration, packaging and automation can legitimately use these switches; does not inspect the decoded payload |
| Windows `privileged_group_change` | Addition to selected privileged groups | Authorized system administration is common; identity/approval context needed |
| Windows `scheduled_task_created` | Windows task-creation event | Windows updates, installers and IT automation create benign tasks |
| Windows `success_after_failures` | At least five 4625 failures followed by a 4624 success on exact host/account/IP within five minutes | Not a brute-force verdict; fail-only bursts intentionally do not trigger; clock/order/forwarded logs and duplicate-event IDs are not independently verified |
| CloudTrail `root_account_activity` | Root identity usage, including denied calls | Not every root call is malicious; root use warrants review |
| CloudTrail `iam_permission_or_identity_change` | Completed IAM change from selected API names | Expected administrative updates are common; missing/cloud-delayed records matter |
| CloudTrail `logging_configuration_change` | Selected successful logging API calls | Authorized trail maintenance can trigger; denied calls are excluded from this class |
| CloudTrail `role_assumption_review` | STS AssumeRole call | Routine cross-account and workload roles are common; low severity is not a compromise finding |

All per-rule TP, FP, FN and TN counts are calculated **at the scenario level**, not the raw event level. True/false mean agreement or disagreement with fixture-defined expectations only. A scenario may contain multiple events or multiple expected rules.

### One concrete false-positive safeguard

The offline Windows hunter previously could group records with an absent source IP into a `success_after_failures` candidate. It now refuses authentication correlation unless **host, user and source IP are nonempty, non-`unknown` strings**. This prevents unrelated incomplete audit records from being joined into one suspicious account/session history. This is not a validated identity-resolution scheme for NAT, proxy or distributed authentication environments.

### What this cannot prove

Synthetic fixture conformance can be perfect while performance on actual production events is poor. The current fixtures are tiny, curated and not representative of attack prevalence, log loss, novel obfuscations, parser errors, service-account baselines, approved administrator activity or unknown adversaries. They do not provide sensitivity, specificity, operational precision, false positive rate, or false negative rate for a deployed SOC. The Splunk SPL queries remain structurally tested but **not executed against a Splunk server**.

Before claiming measured accuracy, create an authorized, independently labeled corpus of **realistic lab telemetry**, validate field extraction and source provenance, preserve base rates and negative examples, manually adjudicate disagreements, and report metrics with sample sizes and limitations. See [Splunk field mapping specification](../docs/SPLUNK_FIELD_MAPPING_SPEC.md) and [Pipeline 10.0 live acceptance](../docs/SOC_PIPELINE_10_ACCEPTANCE.md).

**Review status:** Awaiting independent VORTEX/Titan detection-rule assessment. No reviewer sign-off or live evaluation claimed.
