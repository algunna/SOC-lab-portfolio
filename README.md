# Alen Guner | SOC Lab Portfolio

Hands-on cybersecurity labs focused on SOC monitoring, detection, investigation and incident reporting. These are training projects and simulations, not production deployments.

## Featured Projects

| Project | Focus |
| --- | --- |
| [AI SOC Copilot](./ai-soc-copilot) | SSH log analysis, brute force detection, MITRE ATT&CK T1110, incident reports |
| [Windows Sysmon Detection](./windows-sysmon-ai-detection) | Endpoint telemetry and suspicious PowerShell investigation |
| [CloudTrail SOC Pipeline](./cloudtrail-soc-pipeline) | Cloud security events, IAM risks, incident correlation |
| [Threat Intelligence Enrichment](./threat-intel-enrichment-lab) | IOC triage and analyst reporting |
| [Phishing Email Analyzer](./phishing-email-analyzer) | Phishing indicator analysis |
| [Brute Force Detection](./brute-force-detection) | Investigation write-up of a brute-force scenario (no code) |
| [Excessive Failed Authentication](./excessive-failed-auth) | Repeated failed logins and success-after-failure alerts |
| [IP Obfuscation Detection](./ip-obfuscation-detection) | External source IP review in CloudTrail activity (early-stage) |
| [Windows Threat Hunting](./windows-threat-hunting-lab) | Windows event correlation and threat hunting |
| [AWS CloudTrail Threat Hunting](./aws-cloudtrail-threat-hunting) | Cloud identity monitoring and event correlation |
| [Sigma Detection Engineering](./sigma-detection-lab) | Portable detection rules and synthetic test fixtures |
| [Splunk SOC Hunting](./splunk-soc-hunting) | SPL searches and practical investigation playbooks |
| [SOC Incident Case Management](./soc-incident-case-lab) | Offline investigation cases, audit history and analyst notes |

[AI Log Summarizer](./ai-log-summarizer) is an earlier prototype that sends redacted logs to an external AI API; it is kept for reference and is not part of the offline labs above.

## Planned Shared SOC Infrastructure

- [SOC Event Contract v1](./soc-event-contract)
- [SOC Event Ingestion MVP](./soc-event-ingestion) — offline validation, in-run deduplication and quarantined rejection reports — versioned normalized alert schema, synthetic example, validation and integration boundaries

## Engineering Documentation

- [Documentation hub](./docs/README.md) — architecture, testing practices and standards
- [Project template](./docs/PROJECT_TEMPLATE.md) — consistent setup and investigation walkthroughs
- [Testing evidence guide](./docs/TESTING_AND_EVIDENCE.md) — what the automated checks verify
- [Changelog](./CHANGELOG.md) — merged project improvements

New labs follow a common documentation checklist. All detections and MITRE ATT&CK mappings are training-oriented investigation hypotheses and require analyst validation.

## Skills

Python, Linux, Windows Sysmon, AWS CloudTrail, MITRE ATT&CK, incident documentation, investigation workflows, Git/GitHub, Splunk, and Wazuh.

## Professional Background

I currently serve as a Security Officer with Valley Health System, supporting building security operations and incident documentation. Previously, I worked as a Security Supervisor with Elite Investigations, helping coordinate security staff, CCTV monitoring, access control, alarm triage, and first-responder communication. I am pursuing opportunities in SOC and GSOC analysis.

## Portfolio Guide

Open a project folder to review the available source code, sample logs, reports, and setup notes. Each lab is a learning exercise; outputs and dependencies vary by project.

## Contact

[LinkedIn](https://www.linkedin.com/in/alen-guner) | [GitHub](https://github.com/algunna)

## SOC Incident Correlation (experimental)

- [Offline incident candidate grouping](./soc-incident-correlation)
- [Titan review and integration handoff](./docs/TITAN_SOC_HANDOFF.md)

## SOC Pipeline 4.0 — Analyst case promotion

- [Manual candidate-to-case promotion](./soc-case-promotion) — explicit analyst approval, SQLite duplicate guard and audit notes
