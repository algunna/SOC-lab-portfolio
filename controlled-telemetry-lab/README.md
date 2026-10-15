# Controlled Telemetry Lab — Pipeline 15.0

**Offline synthetic design exercise, not a live connector or authenticated chain of custody.** This lab tests how to form stable, source-scoped Windows and CloudTrail record identifiers **before** real Splunk integration. It neither fetches logs nor claims an event indicates an attack.

## Run locally

From the repository root, install the existing SOC event validator and run the offline preflight:

```bash
python -m pip install -r soc-event-contract/requirements.txt
python -m unittest discover -s controlled-telemetry-lab/tests -v
python controlled-telemetry-lab/src/source_identity.py --out /tmp/synthetic-source-summary.json
```

Use your own private temporary path on Windows. Output files are created exclusively and never overwritten. The fixture is fixed at [synthetic_sources.json](fixtures/synthetic_sources.json), and `source_identity.py` rejects extra or missing columns rather than reading arbitrary event structures.

## Namespace model

| Input | Required synthetic namespace | Why |
| --- | --- | --- |
| Windows Security or Sysmon training observation | `host`, `channel`, `log_epoch`, `record_id` | Windows event record numbers can recur across hosts, channels, or log resets. The `log_epoch` here is an explicitly supplied **lab generation UUID**, not an actual Windows Event Log field. |
| CloudTrail training observation | 12-digit `account_id`, `region`, `event_id` UUID | Avoid conflating superficially identical event identifiers from different synthetic accounts or regions. Verify true uniqueness/scoping and CloudTrail delivery behavior later with an isolated AWS test account. |

Each namespace tuple is serialized in fixed order and hashed to an opaque `lab-src-` record ID and `synthetic-source:` reference. Hostnames are lowercased; source raw identifiers, account IDs, event UUIDs, and simulated log-epoch values are not printed in the summary. This is stable mapping for **synthetic fixtures only**, not real source identity attestation. Hashes can be vulnerable to guessing and are not anonymization.

The field `occurred_at` is parsed as offset-aware RFC3339, converted to UTC with six fractional digits, and remains separate from `received_at`. The clock-review label is `within_lab_window`, `delayed_arrival` (more than 15 minutes after event time), or `future_event_time` (more than 5 minutes into the future). These are configurable *design thresholds in source code*, not indications of hostile behavior, reliable proof of clock correctness, or a guarantee of delivery order.

## Explicit trust boundaries

1. **Untrusted fixture values** may supply identifiers and timestamps but never assign `verified`, `severity`, `rule_id`, analyst identity, or any detection verdict.
2. **Structural preflight** requires exact columns, bounded data, explicit timezone, source namespace fields, unique scoped IDs per batch, and rejects malformed UUID/account/host fields.
3. **Opaque projected output** is `unauthenticated_synthetic_fixture`, not authenticated telemetry. It can be copied into an existing **synthetic** SOC Event Contract v1 alert for compatibility testing; preflight alone never creates a real alert or a case.
4. **Future real source mapping** needs actual device/event source authentication, collection permissions, trusted transport, record identity namespace verification, reviewed evidence retention and redaction, out-of-order handling, signed or server-side provenance as appropriate, clock synchronization evidence, and a durable ingestion design.

Run only on isolated fixtures. Do not use this mapping as an explanation for importing work logs, patient records, personal data or production CloudTrail dumps. Real Splunk version, settings, certificate trust, index and event extraction are still unverified. The [home-PC checkpoint](../docs/SPLUNK_HOME_CHECKPOINT.md) must be completed before claiming any live telemetry.

## Reviewer handoff

VORTEX/Titan should independently challenge: whether Windows log generation IDs can be verified at collection time, event record reuse and host renaming, regional/account CloudTrail scope, duplicate eventIDs, source-time parsing, clock skew, opaque hash collision/guessability, untrusted namespace forgery, and semantics of delayed delivery. Independent reviewer sign-off has not been recorded.
