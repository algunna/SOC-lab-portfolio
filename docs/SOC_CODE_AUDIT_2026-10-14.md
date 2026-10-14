# SOC Repository Code Audit — 2026-10-14

This is a source-code review, **not** a completed end-to-end test or security certification.

## Findings

| Area | Finding | Priority | Follow-up |
| --- | --- | --- | --- |
| Threat intelligence | Previous heuristic assigned malicious/benign reputation without feed evidence | High | Replaced with offline IOC format classification and unknown reputation; added tests |
| Windows Sysmon | Script reports predefined PowerShell indicators without parsing the EVTX input | High | Implement real event parsing, validated synthetic fixtures, detection tests |
| Phishing analyzer | Sender, subject, risk and indicators are hard-coded; real email is not parsed for these fields | High | Parse headers and body and calculate evidence-backed findings |
| CloudTrail | Source IP handling counts IPv4-like strings as public; deduplication relies on fragile string splits | Medium | Use Python ipaddress and structured event identifiers; test malformed data |
| IP obfuscation | Public source IP alone is labeled suspicious or obfuscated | High | Rename as external-source identification; require evidence for proxy/VPN claims |
| Excessive failed auth | No explicit event-time window; relative paths depend on current working directory | Medium | Add timestamp parsing, source windowing, and path-safe invocation |
| AI summarizer | Duplicate nested project directory and historical outputs remain | Low | Consolidate only after comparing files and preserving valuable examples |
| Secret exposure | Old environment files were removed from current tree, but remain in Git history | High | Verify all prior credentials revoked; consider carefully planned history rewrite |

## Principles

- Treat detections as hypotheses, not proof of compromise.
- Verify outputs against synthetic fixtures and adversarial edge cases.
- Keep sensitive log data and API keys out of externally hosted services by default.
- Record run instructions, test evidence, and limitations for every lab.
- Make subsequent fixes in small pull requests so regressions can be reviewed.
