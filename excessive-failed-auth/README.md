Excessive Failed Authentication Detection
Purpose

This lab simulates how a SOC analyst detects excessive failed authentication attempts using raw log data. The goal is to identify potential brute-force or credential abuse activity based on repeated failures from the same source, without relying on automated detection platforms.

The focus is on recognizing patterns in authentication behavior and escalating based on risk and frequency.

What This Lab Demonstrates

This project follows a simple SOC detection workflow.

Authentication events are reviewed from a timeline-style log file.

Repeated failed login attempts are counted per source IP.

Sources exceeding a defined threshold are flagged as high-risk.

Alerts are generated to highlight potential brute-force or password-guessing activity.

Why This Detection Matters

Excessive failed authentication attempts are a common early indicator of account compromise attempts.

Attackers often test credentials at scale before succeeding.

Identifying these patterns early allows SOC teams to block sources, protect accounts, and prevent further access.

Even when no successful login occurs, repeated failures still represent active threat behavior.

Analyst Workflow

A SOC analyst reviewing this output would:

Review the source IPs generating repeated failures.

Determine whether the activity aligns with known users, systems, or expected behavior.

Check for successful logins following the failed attempts.

Escalate high-risk sources for blocking, monitoring, or further investigation.

Document findings and response actions.

How to Run This Lab

Place authentication log data in the sample-logs directory:

sample-logs/auth_timeline.txt


Run the detection script:

python scripts/detect_failed_auth.py


Review generated alerts in:

output/failed_auth_alerts.txt

Key Takeaway

This lab demonstrates how simple logic applied to authentication logs can uncover meaningful security risks. It reflects how SOC analysts identify brute-force behavior through repetition, context, and thresholds rather than complex tooling.