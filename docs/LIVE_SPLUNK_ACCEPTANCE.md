# Pipeline 20.0 — Live Splunk integration acceptance preparation

**Status: preparation only. All eleven live acceptance checkpoints remain pending.**
Pipelines 17–19 provide synthetic trust-policy, local queue recovery and health/audit
rehearsals. They do not implement a live authenticated event collector. The current
Splunk probe is count-only; the saved-search normalizer accepts synthetic fixtures.
A real event-to-detector-to-alert adapter still needs implementation and review.

## First home-PC session: inspect, then stop at the first unmet dependency

At the owner's Windows PC, start with the existing checkpoint:

```powershell
Get-Service *Splunk*
```

Record whether a service is present and running. No output does not establish that
Splunk Cloud or another authorized environment is unavailable; identify the actual
installation/access before deciding what to install. Do not install anything or
change audit policies merely to fill this checklist.

Then follow [the home-PC checkpoint](SPLUNK_HOME_CHECKPOINT.md) and
[the count-only probe instructions](../splunk-readonly-connector/README.md).
Confirm the lab scope, endpoint, CA trust, index and least-privileged credential
locally. Keep credentials out of chat, Git, screenshots and command arguments.
The probe is explicitly opt-in and must target only the authorized lab index.

A successful probe shows aggregate connectivity only. It does not demonstrate
Windows event collection, detector execution, source identity or case creation.
If the probe fails, preserve sanitized error codes, check the relevant configuration,
and stop. Do not disable certificate checks or broaden token permissions to bypass
an unexplained failure.

## Acceptance checkpoints and evidence to inspect

Complete these in order. `recorded` means a person has supplied an evidence reference,
not that this program has independently verified the claim.

| Gate | Required observation and evidence | Stop or failure condition |
| --- | --- | --- |
| `authorized_lab` | Owner confirms isolated personal lab scope and permitted systems in a private review note | Scope includes unauthorized, hospital, patient or workplace telemetry |
| `splunk_installation` | Local service/install or authorized Cloud access evidence, with actual environment/version recorded privately | Environment/access remains unknown |
| `tls_and_permissions` | Verified CA/server identity and scoped index/token permissions; retain sanitized configuration review | TLS bypass, public management exposure or excessive/unexplained privilege |
| `count_only_probe` | Manually run existing probe and inspect sanitized aggregate output against the intended lab index | Request error, unexpected index or incorrect/unknown results |
| `source_mapping` | Inspect actual lab fields, time normalization, source IDs and Windows generation or AWS account/region scope | Fixture-only fields treated as real, missing generation/scope, ambiguous record reuse |
| `detector_validation` | Versioned detector and positive plus benign controls; record expected and actual alert counts and matched source IDs | Missed expected event, unexplained false positive, detector/source mismatch |
| `independent_security_review` | Independent VORTEX/Titan review of the specific real adapter/authentication design and implementation revision, with blocking findings resolved | Review absent, stale after relevant changes, or blocking findings open |
| `collector_authentication` | Controlled tests of reviewed real collector identity, source scope, invalid/expired/revoked credentials and verification outages | Self-asserted trust, credentials leaked, anonymous fallback or incorrect source binding |
| `delivery_recovery` | Authorized lab event delivered through the real adapter; restart/interruption/reimport observations confirm no loss or unintended duplicate alerts | Only local synthetic receipts tested, early acknowledgment or inconsistent delivery state |
| `analyst_case` | Analyst inspects the live-derived unverified candidate, explicitly approves one case and verifies history; duplicate approval refused | Case appears automatically or lacks source/detector traceability |
| `command_center` | Read-only dashboard displays the reviewed case and its linked alerts/evidence with expected counts | Counts/IDs diverge, fabricated provenance, or dashboard mutates cases |

Do not use the current synthetic normalizer or trust simulator as a live admission
gate. After initial connectivity/mapping observations, implement the separate real
adapter and authentication boundary, obtain independent review, then conduct
controlled live collector testing. The existing count-only probe is not that collector.

## Private evidence capture template

For each gate, keep a private local note with:

1. Exact repository commit, actual lab version/configuration and UTC test time.
2. Authorized test scenario, expected result and observed result, including benign controls.
3. Opaque source record → detector revision → alert → candidate → analyst case linkage,
   where applicable. Keep raw events and personal identifiers out of the public repo.
4. Sanitized evidence artifact name and SHA-256, plus who inspected the content.
5. Failure or uncertainty, corrective action, and retest result; preserve failed evidence.

Use [live_acceptance_checklist.json](../splunk-readonly-connector/fixtures/live_acceptance_checklist.json)
as a **copy in a private working directory**. The committed template stays all-pending.
Each gate has `status` (`pending`, `blocked`, `recorded`) and `evidence` (0–4 entries).
Recorded gates require evidence; pending/blocked gates have no evidence references.
For recorded review gates, each reference has `kind: operator_review`; other gates
use `kind: authorized_live_lab`. `sha256` is the lowercase SHA-256 of the sanitized
artifact. Never put file paths, URLs, token values, raw events or free-form notes
inside the checklist. Store detailed notes privately alongside the evidence.

A hash detects changes only when checked against the actual artifact. The validator
**does not open evidence**, attest who created it, or prove that a claimed live
artifact is real. Relabeling a synthetic hash as live would be a false claim, not
successful verification. A human must inspect the contents and provenance.

```bash
python splunk-readonly-connector/src/acceptance_plan.py
python splunk-readonly-connector/src/acceptance_plan.py --checklist PRIVATE_CHECKLIST.json
python -m unittest discover -s splunk-readonly-connector/tests -v
```

The default output lists all gates pending. It rejects unknown fields, duplicated
JSON keys, malformed hashes, synthetic evidence kinds, missing evidence and skipped
prerequisites. Output omits supplied hashes and emits fixed gate IDs only. Exit 0
means the checklist is structurally valid, even if every gate is pending. Even all
recorded gates produce `claims_complete_manual_review_required`, with:

- `evidence_contents_verified: false`
- `live_splunk_verified: false`
- `collector_enablement_authorized: false`

This is an evidence organizer, not an authorization or go-live decision engine.

## Stop, rollback and completion

On an unexpected result, stop the manually initiated collector/test. Preserve the
original queue DB, receipts and evidence; do not clear replay history to force a
passing result. Revoke a compromised lab credential through the authorized local
administration process. Roll back only the known lab change after reviewing its
impact. No destructive cleanup, automatic remediation or response execution is
part of this milestone.

Completion requires a witnessed, authorized **real lab event → validated detection
→ normalized alert → correlation → analyst approval → incident case → read-only
Command Center**, with supporting evidence and independent security review. An
intentional benign test event may exercise a detector; it is not proof of an attack.
Windows acceptance does not automatically establish AWS acceptance, or vice versa.

The existing [offline SOC demo](../soc-demo/README.md) remains useful interview
practice, clearly labeled synthetic. After this preparation milestone, prioritize
the home-PC checkpoint and the missing real adapter over additional numbered
synthetic milestones.
