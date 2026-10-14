# Failed Authentication Correlation Lab

An offline SOC detection lab that examines timestamped authentication events using a five-minute sliding window. It groups by **source IP and username** to reduce cross-account false positives.

## Detections

- Five failed authentications against an account from the same source within five minutes.
- Successful authentication after five recent failures from that same source and account.
- Malformed records and invalid IP addresses are ignored.

These alerts are investigation leads, **not proof of compromise**. Review device context, approved behavior, identity events, and source timestamps before escalation.

## Run

From the repository root:

```bash
python excessive-failed-auth/scripts/detect_failed_auth.py
python -m unittest discover -s excessive-failed-auth/tests -v
```

Default sample: `sample-logs/auth_timeline.txt`; default output: `output/failed_auth_alerts.txt` inside this lab. The script also accepts `--input` and `--output`.

## Limitations

Demonstration thresholds are not tuned for production. Data is sorted by event time and no ingestion service, credential validation, identity enrichment, or automatic remediation is provided. Use only synthetic or authorized data.
