# Scheduled Task Creation — Analyst Playbook

**Trigger:** Windows Security Event ID 4698. **ATT&CK hypothesis:** T1053.005.

1. Confirm task name, creation timestamp, user, system, and event record.
2. Review task action, executable, arguments, triggers and related process creation data.
3. Check software deployment records, update schedules and known management tools.
4. Identify unexpected persistence indicators using authorized triage procedures.
5. Document findings and escalate only if context justifies it.

**False positives:** Routine installers, updates, administrators and legitimate scheduled maintenance.

**Limitations:** Task creation alone does not establish malicious persistence. TaskContent availability varies.
