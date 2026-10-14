# Training Portfolio Architecture

The repository is a **collection of independently runnable labs**, not yet a unified SOC platform.

```text
Authorized synthetic inputs
      |
      +-- Windows event / Sysmon XML samples
      |        +-- Windows hunting and Sysmon detection scripts
      |
      +-- AWS CloudTrail-style JSON or JSONL
      |        +-- Event classification and IAM/logging correlation
      |
      +-- Email / authentication / IOC samples
               +-- Phishing, SSH and IOC analysis scripts
      |
      v
Evidence-based findings and reports
      |
      v
Analyst review, false-positive validation, escalation decision
```

The Sigma lab separately hosts portable YAML rules and a **limited synthetic fixture matcher**. It does not perform SIEM conversion or deploy detections.

Some earlier projects may include optional API libraries or historical prototype reports. Consult the individual README and code before running. Do not assume all labs share an event bus, dashboard, database, or central case-management application. Those would be future extensions.
