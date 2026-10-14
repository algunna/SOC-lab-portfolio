# AWS CloudTrail Threat Hunting Lab

An **offline, synthetic-data** blue-team lab for reviewing AWS CloudTrail-style JSONL records. This is a separate lab from the repository's earlier CloudTrail pipeline.

## Detection scenarios

| Scenario | Example event | Interpretation |
| --- | --- | --- |
| Root usage | ConsoleLogin by Root identity, including denied calls | High-priority investigation lead |
| IAM permission / identity modifications | Attach*/Put* policies, CreatePolicyVersion, SetDefaultPolicyVersion, CreateUser, CreateRole, CreateAccessKey, Create/UpdateLoginProfile, UpdateAssumeRolePolicy, AddUserToGroup, permissions-boundary removal, DeactivateMFADevice | Verify authorization and scope |
| Logging configuration changes | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, StopEventDataStoreIngestion, DeleteEventDataStore | Investigate possible impairment of defenses |
| Role assumption | AssumeRole | Low-severity context signal, **not inherently malicious** |

Failed API calls with an `errorCode` are not counted as completed changes, but a denied call made with root credentials is still reported as root usage. The MITRE ATT&CK mappings in output are hypotheses for human review and are not proof of compromise. The detector does **not** claim to establish unusual behavior through historical baselining.

## Run from repository root

```bash
python aws-cloudtrail-threat-hunting/src/hunt.py
python -m unittest discover -s aws-cloudtrail-threat-hunting/tests -v
```

Override paths with `--input events.jsonl --output findings.json`. The input format is one CloudTrail-style JSON object per line, not the nested CloudTrail Records export format. Reports include no credentials, API keys, or automatic remediation. No AWS account, internet connection, or third-party API is required.

## Roadmap

Add support for real `Records` exports, actor/asset correlation, event-time anomaly windows, severity tuning and adversarial test fixtures.
