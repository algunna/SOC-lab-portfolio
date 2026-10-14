# Encoded PowerShell — Analyst Playbook

**Trigger:** Process creation telemetry shows PowerShell with encoded command indicators. **ATT&CK hypothesis:** T1059.001.

1. Validate source event timestamp, host, user, process image and full command line.
2. Review parent process, execution context, approved automation and change tickets.
3. Examine related Sysmon events and Windows Event ID 4688 where available.
4. If authorized, safely decode the command as text without executing it; preserve original evidence.
5. Compare neighboring process/network activity and document benign explanations.
6. Escalate only where supporting evidence indicates unauthorized execution.

**False positives:** Endpoint management tools, scheduled administration, automation.

**Evidence to record:** Original event reference, process GUID/PID, command-line indicators, parent image, analyst decision and review timestamp.

**Limitations:** Encoded command flags are not proof of malware; logging/field mappings vary by environment.
