# CloudTrail 2.0 — Correlated Investigations

This upgrade extends the [offline threat hunting lab](README.md) with an analyst-friendly correlation workflow.

## Capabilities

- Accepts CloudTrail-style JSONL events, JSON arrays, or AWS export-shaped `{"Records":[...]}` JSON files.
- Correlates IAM changes followed by (or occurring near) CloudTrail logging changes from the **same actor** within a default 30-minute window.
- Excludes events reporting an AWS `errorCode` from completed-action correlation.
- Writes both JSON findings and a Markdown analyst timeline.
- Does not send data to AWS, APIs, or an LLM.

## Run from repository root

```bash
python aws-cloudtrail-threat-hunting/src/correlate.py --input aws-cloudtrail-threat-hunting/fixtures/records_export.json --output /tmp/cloudtrail2.json --markdown /tmp/cloudtrail2.md
python -m unittest discover -s aws-cloudtrail-threat-hunting/tests -v
```

## Interpretation and limitations

The sample is synthetic. The correlator groups by identity ARN/principal ID/username, not verified sessions, and it is not a production-ready actor attribution engine. Root usage and ordinary role assumptions may be legitimate; IAM changes and logging updates are suspicious **only in context**. ATT&CK labels are investigation hypotheses. Some event configurations and sources require fuller CloudTrail record normalization; timestamps without valid timezone data are excluded from correlations. Do not upload sensitive cloud audit logs or treat these detections as confirmed incidents.
