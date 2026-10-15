# Authentication burst detection tuning

## Reproduced false-alert cases

Before this fix, the generic text-log detector generated a critical success-after-
failures lead for a different account's success, for failures an hour earlier, and
twice for two successive successes after one burst. The Windows 4625/4624 hunter
combined three failures, a success, then two more failures into a five-failure lead.
These synthetic reproductions are now covered by regression tests.

## Explicit detector policy

The generic text detector groups by canonical IP address, exact account and exact
event type. It requires explicit-timezone timestamps, sorts chronologically in UTC,
and counts failures in an inclusive five-minute sliding window. Five failures
produce the existing HIGH lead; a matching success after at least five produces
the existing CRITICAL lead. Every matching success clears the sequence, including
one below threshold. Another account's success does not clear the target account.

This intentionally narrows the old source-only whole-file policy. Accounts and
event names are case-sensitive in the generic format because provider semantics
are not known. IPv6 textual equivalents normalize to the same address. The Windows
hunter retains its own case-insensitive host/account policy and source grouping;
only its success-reset behavior changes.

Missing/unknown identity, invalid IP, malformed/naive timestamp and duplicated
text fields cannot establish a generic correlation and are skipped. The function's
optional threshold must be an integer from 1 to 10,000; window must be 1–3,600 seconds
(default 300). Invalid settings raise an error. Command-line defaults remain the
same sample input/output paths; no new network or automation is introduced.

## Evidence and limits

Twenty new regression tests cover the four reproduced gaps, account/source/event
separation, post-success bursts, boundary times, offsets, sorting, malformed input,
IPv6 normalization and settings. Several run the same sequence through both the
text and normalized Windows detectors. The original sample still produces HIGH,
CRITICAL, HIGH; existing detection-policy fixtures remain unchanged.

These tests validate curated sequence expectations, not real-world maliciousness.
A user mistyping a password can satisfy the rule. Severity labels remain heuristic
triage labels; no alert automatically proves compromise or creates a case.

**Duplicate raw records remain a limitation:** the text fixture has no trustworthy
source event ID or generation field. Equal timestamps/contents may be distinct
attempts, so this fix does not silently deduplicate them. Repeated input failures
can inflate the count. Source-identity-aware deduplication must happen before real
detection; downstream alert replay protection does not retroactively correct a
source-level count. Equal-time order follows input order, not an invented sequence.

The generic lab lacks host/account-tenant namespaces and must not combine logs from
unrelated systems sharing account names, event types or NAT addresses. Its bounded
window is per correlation key, not a bound on whole-file memory. It is not a live
streaming engine and does not detect low-and-slow or cross-account password spray.
Malformed-row skips are not yet summarized in a telemetry quality report.

## Verification

```bash
python -m unittest discover -s excessive-failed-auth/tests -v
python -m unittest discover -s windows-threat-hunting-lab/tests -v
python -m unittest discover -s detection-accuracy-lab/tests -v
```

CI's legacy suite also watches the Windows detector/shared PowerShell helper because
the cross-detector sequence regressions import that code. No credentials, live
telemetry or response execution is involved. The home-PC Splunk checkpoint and
independent VORTEX/Titan review remain pending.
