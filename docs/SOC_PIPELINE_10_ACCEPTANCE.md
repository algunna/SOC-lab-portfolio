# SOC Pipeline 10.0 — Integration Audit and Live Splunk Acceptance Gate

**Scope:** Defensive, authorized, synthetic SOC lab only. This checklist is a gate for a future *local, live-connected demonstration*, not an assertion of production readiness.

## Offline acceptance — available today

- [x] Normalized SOC Event Contract v1 with bounded RFC3339 timestamps and mandatory evidence references.
- [x] Offline ingestion, in-run deduplication and opt-in cross-run SQLite replay guard.
- [x] Conservative correlation produces **unverified candidates**, not findings of compromise.
- [x] Explicit analyst approval for case creation; duplicate candidate/alert protection in one SQLite case database.
- [x] Read-only Command Center snapshot and separate offline health dashboard.
- [x] Sanitized failure/quarantine health counts with manual retry and no raw rejected values in health output.
- [x] Batch completeness marker, bounded SHA-256 verification, and fail-closed sealed-batch inputs at the dashboard and case-promotion boundaries.
- [x] Semantic re-check **recomputes correlation from validated sealed alerts**, requires full candidate-report equality, and refuses mismatched counts, malformed or rejected records, and duplicated events. Verification consumes the same report bytes it hashed.
- [x] Synthetic CI tests include normal flow and negative cases for tampering, missing markers, blocked batches, duplicate IDs and missing analyst approval.

All checked items refer to offline repository code/tests, not real Splunk behavior. A local attacker who can change both files and unkeyed manifest can still forge valid source alerts and consistent correlations.

## Live-Splunk prerequisites — NOT YET VERIFIED

- [ ] **Owner present at their own PC:** PowerShell `Get-Service *Splunk*` or determine if Splunk Cloud is intended. No workplace endpoints, hospital/patient data, or third-party telemetry.
- [ ] Confirm authorized Splunk edition, local HTTPS management endpoint/port, server trust chain and a dedicated local index. **Never paste credentials in chat, README, issues or PRs.**
- [ ] Provision a least-privileged, opt-in read-only token stored only in a private local environment variable; verify index/sourcetype capabilities and retention.
- [ ] Run the existing **count-only** HTTPS probe against authorized lab events; demonstrate trusted TLS, no redirects, and correct returned aggregate counts.
- [ ] Verify source events from a controlled Windows lab (Sysmon/auth), optional isolated AWS test account, and expected parsing/timestamp/identity namespaces.
- [ ] Independently review exact Splunk REST/export response structure and saved-search field mappings. The existing allowlist adapter accepts synthetic classification input only; no real Splunk alert feed exists.
- [ ] Test real event → reviewed detector → normalized contract → ingestion → **semantically consistent** candidate → analyst-only case → read-only dashboard using sanitized, authorized lab telemetry.
- [ ] Verify repeat imports, conflicting IDs, replay behavior, quarantine/retry, data minimization and persistent audit records across restart.
- [ ] Review resource bounds, durable checkpoint/recovery behavior, filesystem races, permissions, and limitations of SQLite/concurrent writers before unattended operation.
- [ ] Preserve a dated test record with exact commands, sanitized counts, CI commit SHA, and known limitations; no claims of enterprise SOC production readiness.

## Findings and engineering residual risks

| ID | Observation | Current mitigation / gap | Disposition |
|---|---|---|---|
| A10-01 | SHA-256 can verify files yet permit rewritten candidate severity, evidence or alert IDs if the manifest is refreshed | Pipeline 10.0 recomputes conservative correlation exactly from accepted, contract-valid alerts | Addressed for sealed **semantic consistency**; not authenticated source integrity |
| A10-02 | An attacker can rewrite source alerts and create matching candidate results and manifest | No signatures, attested upstream provenance, immutable event store or verified analyst identities | Open for any production/external use |
| A10-03 | Input path aliases, symlink-parent and between-stat/read swaps remain possible; multi-file directory writes are not atomic | Bounds, no direct symlinked artifacts, exclusive output, completion marker and same-byte consumer check | Open; trusted local-only use |
| A10-04 | The separate legacy ingestion/correlation arguments bypass sealed-batch verification | Legacy option is labeled for trusted synthetic testing, `--batch-dir` is the verified path | Open; prohibit legacy unsealed mode for live lab |
| A10-05 | There is no live Splunk installation/access confirmation or verified raw event-to-alert pipeline | Home-PC checkpoint, read-only probe, synthetic-only integration tests | Deferred pending owner at home |
| A10-06 | Replay/SQLite and case approvals lack externally authenticated identities and exactly-once durability | Local opt-in state, explicit approval, bounded replay tests | Open; not suitable as an unattended response system |

## Owner handoff

When the owner is home, begin with [SPLUNK_HOME_CHECKPOINT.md](SPLUNK_HOME_CHECKPOINT.md). Run local detection and connection checks only against systems the owner controls, inspect results without posting tokens, and do **not** represent the system as 100% live-ready until every relevant live prerequisite above is verified.

**Review request to VORTEX / Titan:** Independently challenge the correlation recomputation check, duplicate/reference semantics, unkeyed manifest threat model, cross-file race conditions, and real Splunk mapping assumptions. External reviewer approval has **not** been recorded in this document.
