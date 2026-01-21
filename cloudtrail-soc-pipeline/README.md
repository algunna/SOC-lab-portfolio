CloudTrail SOC Detection Pipeline
Purpose

This lab simulates how a SOC analyst investigates AWS CloudTrail activity without relying on managed detection services. The goal is to work directly with raw CloudTrail logs, identify risky behavior, and escalate meaningful security incidents based on context rather than alert volume.

The focus is on analyst reasoning and investigation flow, not automated tooling.

What This Lab Demonstrates

This project walks through a realistic SOC workflow using real CloudTrail logs.

CloudTrail events are parsed into a readable timeline that shows who performed an action, when it occurred, and where it originated.

Custom detection logic is applied to identify high risk behaviors such as root account usage, IAM configuration changes, and role assumption activity.

Alerts are enriched with severity levels, MITRE ATT&CK technique mappings, and recommended analyst actions to reflect how findings are handled in an operational SOC.

Related alerts are correlated into incidents to reduce noise and provide a clear investigative narrative.

Why These Detections Matter

Root account activity is rare and high impact. Any use outside of break glass scenarios requires immediate review, especially when originating from public IP addresses.

IAM configuration changes can indicate privilege escalation, persistence, or misconfiguration that weakens the security posture of the account.

Role assumption activity may be benign or malicious depending on context. Reviewing frequency, source, and trust relationships helps distinguish normal service behavior from abuse.

Analyst Workflow

A SOC analyst reviewing this output would:

Review the timeline to understand the sequence and scope of account activity.

Validate whether root usage aligns with approved administrative actions.

Investigate IAM changes for unauthorized role creation or trust policy abuse.

Confirm that role assumption behavior matches expected AWS services.

Escalate critical findings and document response actions.

Key Takeaway

This lab emphasizes analyst thinking over tool dependency. It demonstrates how raw cloud logs can be transformed into actionable security incidents using structured logic, context, and prioritization.