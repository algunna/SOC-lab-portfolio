# Privileged Group Change — Analyst Playbook

**Trigger:** Windows Security Event ID 4728 or 4732 targeting a privileged group. **ATT&CK hypothesis:** T1098.

1. Verify the added member, target group, initiating subject, domain and host.
2. Compare against identity governance approvals and authorized provisioning.
3. Review related logons, account management events, and any subsequent privileged use.
4. Determine whether the actor is expected and whether the membership remains in place.
5. Escalate unexpected additions via the organization's identity-response procedure.

**Evidence:** Event record ID, source host/DC, subject SID, member SID, group SID, approval record and analyst notes.

**False positives:** Approved onboarding, role changes, break-glass operations.

**Limitations:** Windows event IDs and group fields must match the log source; group names can be renamed/localized.
