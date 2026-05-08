# AI SOC Copilot Incident Report

Generated: 2026-05-08 17:50:58

## Summary

Possible SSH brute-force activity was detected based on repeated failed login attempts.

## Key Findings

- Failed login attempts: 4
- Successful logins: 1
- Source IPs observed: 192.168.1.20, 192.168.1.45
- Severity: Medium

## MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## Analyst Notes

The log shows multiple failed SSH login attempts against different usernames. A successful login was also observed from a separate internal IP address.

## Recommended Response

1. Review SSH access logs for additional activity.
2. Confirm whether the successful login was expected.
3. Block or investigate suspicious source IPs.
4. Enforce strong passwords and consider disabling root SSH login.
5. Enable MFA where possible.

## Raw Log Sample

May 08 10:14:21 ubuntu sshd[1123]: Failed password for invalid user admin from 192.168.1.45 port 51234 ssh2
May 08 10:14:28 ubuntu sshd[1127]: Failed password for invalid user test from 192.168.1.45 port 51238 ssh2
May 08 10:14:35 ubuntu sshd[1131]: Failed password for root from 192.168.1.45 port 51242 ssh2
May 08 10:14:41 ubuntu sshd[1135]: Failed password for invalid user oracle from 192.168.1.45 port 51246 ssh2
May 08 10:14:59 ubuntu sshd[1140]: Accepted password for alen from 192.168.1.20 port 50122 ssh2
