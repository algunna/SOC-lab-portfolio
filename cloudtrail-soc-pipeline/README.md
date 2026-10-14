# CloudTrail SOC Detection Pipeline

## Purpose and scope

This lab walks through how a SOC analyst turns raw AWS CloudTrail JSON into a timeline, rule-based alerts and grouped incidents without a managed detection service. It is an educational lab, not a production detection system.

It was the first CloudTrail lab in this portfolio. [AWS CloudTrail Threat Hunting](../aws-cloudtrail-threat-hunting) is the newer lab and goes further: correlation by actor and account, and triage scoring. This pipeline stays as the simpler three-step introduction.

## Data inputs

- CloudTrail JSON exports in the standard `{"Records": [...]}` format.
- Fields used: `eventTime`, `eventName`, `userIdentity.type`, `sourceIPAddress`, `awsRegion`.
- [fixtures/sample_cloudtrail.json](fixtures/sample_cloudtrail.json) is **synthetic**. It uses the AWS documentation account ID `123456789012` and documentation IP ranges.
- Files that are not valid JSON, files without a `Records` list and records that are not objects are skipped.

## Detections

| Rule | Condition | Severity | ATT&CK hypothesis |
| --- | --- | --- | --- |
| Root from public IP | `userIdentity.type` is `Root` and source is a public IPv4/IPv6 address | CRITICAL | T1078.004 Cloud Accounts |
| Root activity | `Root` from any other source (AWS Internal, AWS service, private IP) | HIGH | T1078.004 Cloud Accounts |
| IAM permission or credential change | `CreateUser`, `CreateLoginProfile`, `UpdateLoginProfile`, `CreateAccessKey`, `Attach*Policy`, `Put*Policy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CreateRole`, `UpdateAssumeRolePolicy`, `AddUserToGroup`, permissions-boundary changes, `DeactivateMFADevice` | HIGH | T1098 Account Manipulation |
| Service-linked role created | `CreateServiceLinkedRole` | MEDIUM | T1098 Account Manipulation |
| CloudTrail logging changed | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `StopEventDataStoreIngestion`, `DeleteEventDataStore` | HIGH | T1562.008 Disable or Modify Cloud Logs |
| Role assumption | `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`, `AssumeRoot`, `GetFederationToken` | MEDIUM | T1078.004 Cloud Accounts |

"Private" means 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, loopback, link-local and IPv6 unique-local (`fc00::/7`). IPv4-mapped IPv6 addresses (`::ffff:10.1.2.3`) are judged by their IPv4 address. Any other valid IP address counts as public.

ATT&CK mappings are investigation hypotheses, not proof of compromise.

**Expected false positives:** approved break-glass root use, infrastructure-as-code deployments creating roles and policies, trail updates during planned logging changes, and AWS services assuming their own roles during onboarding.

## Run

From the repository root (the scripts work from any directory):

```bash
python cloudtrail-soc-pipeline/scripts/parse_cloudtrail.py
python cloudtrail-soc-pipeline/scripts/detect_cloudtrail_risks.py
python cloudtrail-soc-pipeline/scripts/correlate_cloudtrail_incidents.py
python -m unittest discover -s cloudtrail-soc-pipeline/tests -v
```

No packages need to be installed; the scripts use only the Python standard library. By default the parser reads the synthetic fixture. To analyse your own authorized export, place the JSON files in `cloudtrail-soc-pipeline/sample-logs/` (gitignored) and run `parse_cloudtrail.py --input-dir cloudtrail-soc-pipeline/sample-logs`. Each script also accepts `--input`/`--output`.

## Outputs

Written to `cloudtrail-soc-pipeline/output/` (gitignored):

- `cloudtrail_timeline.txt`: one line per event, sorted by UTC time (offsets such as `+02:00` are converted): `Time | Event | UserType | SourceIP | Region`.
- `cloudtrail_alerts.txt`: `[SEVERITY] CATEGORY title | MITRE technique | <timeline line> | AnalystAction: guidance`.
- `cloudtrail_incidents.txt`: one incident per alert category, with its time window in UTC and related alerts. Its severity is that of its most severe alert.

The synthetic fixture produces 10 timeline events, 9 alerts and 4 incidents (root activity, IAM change, logging change, role assumption).

[output/cloudtrail_analyst_notes.txt](output/cloudtrail_analyst_notes.txt) are historical analyst notes from an earlier run against a private AWS account. Those logs are not in the repository, so the notes cannot be reproduced from it.

## Tests

[tests/test_pipeline.py](tests/test_pipeline.py) covers source IP classification (IPv4, IPv6, private, AWS sources), the expected alerts and incidents from the fixture, a benign event that must not alert, malformed files and records, and field values containing `|` or newlines that try to inject extra fields. CI runs the tests and the full pipeline in [cloudtrail-soc-pipeline-tests.yml](../.github/workflows/cloudtrail-soc-pipeline-tests.yml). Passing tests show the rules behave as written on synthetic data, not that they detect real attacks.

## Security and privacy

The scripts run offline, use no credentials and make no network calls. Use only synthetic or authorized, sanitized logs. Never commit real CloudTrail exports: they contain account IDs, ARNs and source IPs.

## Limitations

- Incidents are grouped by alert category only, not by actor, account, source or time window. See the newer lab for actor-based correlation.
- No thresholds or baselines: every matching event alerts.
- `ConsoleLogin` success/failure, MFA use and the `errorCode` field are not evaluated.
- Only five event fields are kept, so the actor ARN is not shown in alerts.
