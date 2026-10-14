# Account-Aware CloudTrail Correlation

This extension to CloudTrail 2.0 groups completed actions by **AWS account and identity**. It requires an account ID plus ARN, principal ID or username to avoid combining unrelated or unattributed events. Correlation requires an IAM change and a logging configuration change within 30 minutes for the same identity.

## Run
```bash
python aws-cloudtrail-threat-hunting/src/account_triage.py
python -m unittest discover -s aws-cloudtrail-threat-hunting/tests -v
```

The tool accepts the existing CloudTrail-style JSONL and Records JSON input formats. Use `--input`, `--output` and `--markdown` for custom paths.

**Scoring:** correlated IAM and logging changes +40; root identity activity +25; StopLogging or DeleteTrail +20. A score of 80 or more is labeled critical; other correlated cases are labeled high. These are illustrative review priorities, not calibrated risk probabilities. The report includes the exact rationale and timeline.

All fixture data is synthetic. No AWS API calls, automatic remediation, or claims of confirmed compromise.
