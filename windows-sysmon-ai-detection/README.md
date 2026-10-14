# Windows Sysmon AI Detection Lab

A Windows endpoint-investigation lab focused on reviewing Sysmon activity for suspicious PowerShell behavior and documenting potential findings.

## Investigation goals

- Inspect Sysmon process events for command-line indicators such as encoded PowerShell commands and execution-policy bypass.
- Identify relevant host, user, process, and timestamp context.
- Map supported observations to MITRE ATT&CK techniques, while distinguishing suspicious behavior from confirmed malicious activity.
- Prepare an analyst report for human review.

## Lab workflow

1. Collect **authorized test-environment** Sysmon events.
2. Inspect available Python scripts, input files and dependencies in this project directory.
3. Review indicators and validate each finding against source events.
4. If using an AI API, **sanitize sensitive logs before submission**, and verify generated explanations manually.
5. Write an incident summary with indicators, confidence, limitations and recommended next steps.

## Scope and limitations

This is a learning project, not an enterprise endpoint-detection system. Documentation of a detection scenario does not establish a tested detection rate. Do not claim an alert was confirmed without reviewing underlying events. Do not upload live credentials or confidential log data. Availability of scripts and sample outputs may vary; check the repository contents before running.

## Related projects

- [AI SOC Copilot](../ai-soc-copilot)
- [CloudTrail SOC Pipeline](../cloudtrail-soc-pipeline)
