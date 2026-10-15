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

## Pipeline 13.0 — Synthetic detector finding → SOC alert handoff

The new `src/to_soc_alerts.py` executes the reviewed Windows and AWS offline hunter functions over the **fixed labeled synthetic fixtures**, then transforms positive findings into SOC Event Contract v1 alerts with code-defined rule IDs, titles, severities and ATT&CK technique tags. It rejects contradictory findings, unexpected rules, incomplete identities, invalid timestamps and any detector attempt to override a reviewed severity/technique. No source system, Splunk API, AWS account or Windows host is contacted.

From repository root:

```bash
python -m pip install -r soc-event-contract/requirements.txt
python detection-accuracy-lab/src/to_soc_alerts.py --out /tmp/synthetic-detector-alerts.jsonl
python soc-event-ingestion/src/batch_health.py /tmp/synthetic-detector-alerts.jsonl --out-dir /tmp/synthetic-detector-batch
python soc-command-center/src/adapter.py --batch-dir /tmp/synthetic-detector-batch --out /tmp/synthetic-detector-dashboard.json
python soc-command-center/src/dashboard.py --data /tmp/synthetic-detector-dashboard.json
```

Use new, private output paths and a new batch directory on each run; on Windows substitute appropriate local paths. CI checks the generated alerts, sealed-batch semantic integrity and read-only Command Center view. Only **synthetic, unverified investigation candidates** are created, and the case database remains empty. The bridge writes opaque `synthetic-fixture:` evidence references and `lab-` IDs derived from fixture IDs, rule names and occurrence indices; **these are not original Windows EventRecordIDs or CloudTrail eventIDs, and are not authenticated evidence**.

The source matrix contains expected outcomes curated for training. It is not a representative threat dataset, a production detector or a live-Splunk response schema. Actor/asset labels are copied from controlled synthetic findings when structurally valid, not independently authenticated or anonymized. Do **not** submit workplace logs, patient information, personal data or production events to this training bridge. Future live integrations require authenticated source-event identity and reviewed, versioned field mappings.

## Pipeline 14.0 — detecting changed synthetic input under a stable lab ID

The `lab-` alert ID and synthetic source record ID remain stable for a fixture scenario/rule/occurrence, which permits replay tracking. Each generated `synthetic-fixture:` evidence reference additionally includes a bounded SHA-256 snapshot hint derived from the **entire curated scenario's events**. Changing a synthetic source command while the same detector rule still fires now changes the normalized alert's evidence reference and is rejected by the opt-in persistent replay guard as a conflicting previously seen observation.

This fingerprint is a consistency hint for synthetic tests only; it cannot authenticate Windows, CloudTrail or Splunk events, cannot identify a single original event in a multi-event scenario, and is not safe to treat as anonymization for real data. See [replay guard notes](../soc-event-ingestion/README.md).
