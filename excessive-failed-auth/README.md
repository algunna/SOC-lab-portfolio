# Excessive Failed Authentication Detection

## Purpose

This lab shows how a SOC analyst spots possible brute-force or password-guessing activity in raw authentication logs: repeated failed logins from one source, and above all a successful login that follows them. It is an educational lab, not a production detection system.

## Detection

| Alert | Condition | Severity |
| --- | --- | --- |
| Excessive failed authentication attempts | 5 failed logins (`Result: Failure`) from the same `SourceIP` | HIGH |
| Successful login after failures | A `Result: Success` from a source that has already reached 5 failures | CRITICAL |

Each alert includes the source IP, failure count, first and last failure time and the usernames tried. Lines without a `SourceIP` or `Result` are skipped. Failures are counted over the whole file, not within a time window, and per source only, so a password spray spread across many IPs is not detected.

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
