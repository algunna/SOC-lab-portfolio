# Excessive Failed Authentication Detection

## Purpose

This lab shows how a SOC analyst spots possible brute-force or password-guessing activity in raw authentication logs: repeated failed logins from one source, and above all a successful login that follows them. It is an educational lab, not a production detection system.

## Detection

| Alert | Condition | Severity |
| --- | --- | --- |
| Excessive failed authentication attempts | 5 failed logins within five minutes for the same source IP, account and event type | HIGH |
| Successful login after failures | A matching success after at least 5 failures in the preceding five minutes, with no intervening matching success | CRITICAL |

HIGH alerts include the canonical source IP, failure count, first/last failure time and account; CRITICAL alerts include the success time and account. Records require a valid IP, explicit-timezone timestamp, nonempty account/event type and recognized result. Unknown identities, malformed times and duplicate fields are skipped. Events are sorted by UTC time, preserving input order for ties. Every matching success resets the sequence, even below threshold. Generic account and event names are case-sensitive.

This is now an account-scoped consecutive-burst policy, not a cross-account password-spray detector. The five-minute boundary is inclusive. See [authentication tuning and limitations](../docs/AUTHENTICATION_DETECTION_TUNING.md).

ATT&CK T1110 (Brute Force) is an investigation hypothesis. A successful login after failures may be a user who finally remembered their password; confirm with the account owner and other telemetry before escalating.

## Run

From the repository root:

```bash
python excessive-failed-auth/scripts/detect_failed_auth.py
python -m unittest discover -s excessive-failed-auth/tests -v
```

The input is `sample-logs/auth_timeline.txt` (one `Time | Event | Result | User | SourceIP` line per event) and alerts are written to [output/failed_auth_alerts.txt](output/failed_auth_alerts.txt). Use `--input` and `--output` for other files. CI runs the tests in [legacy-lab-tests.yml](../.github/workflows/legacy-lab-tests.yml).

## Analyst workflow

1. Start with any CRITICAL alert: a success after repeated failures.
2. Check whether the source IP and usernames match known users, systems or expected behavior.
3. Review what the account did after the successful login.
4. Escalate for blocking, password reset or further investigation, and document the outcome.
