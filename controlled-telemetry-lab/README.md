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

## Pipeline 16.0 — source identity to informational SOC alerts

The new `src/to_soc_alerts.py` consumes the **strictly validated synthetic source preflight** and creates SOC Event Contract v1 JSONL observations. These are tagged with a fixed `lab.synthetic.source_observation` rule and `informational` severity. They **are not detection results**, proof of compromise, or externally verified source events.

```bash
python controlled-telemetry-lab/src/to_soc_alerts.py --out /tmp/synthetic-source-alerts.jsonl
python soc-event-ingestion/src/batch_health.py /tmp/synthetic-source-alerts.jsonl --out-dir /tmp/synthetic-source-batch
python soc-command-center/src/adapter.py --batch-dir /tmp/synthetic-source-batch --out /tmp/synthetic-source-dashboard.json
```

Every generated alert contains the source-scoped `lab-src-` record identifier, a stable derived `labobs-` event identifier, normalized UTC timestamp, code-owned informational title/rule/severity, and a matching `synthetic-source:` evidence reference. No actor, asset, original source IDs, attack techniques, source clock classifications or claim of authenticated provenance are transferred. A change to the event time does **not** change its scoped event identifier, so the existing opt-in replay guard can flag a later payload conflict.

The entire fixture is rejected before any file output if any source row is missing required context, duplicates an observation, contains unexpected fields, or has malformed event times. Direct projections are also checked for evidence-reference consistency; a caller cannot independently supply a reference to another synthetic source. CI tests the six informational records through ingestion, correlation, the sealed batch, and the read-only Command Center. Correlation still produces six **unverified informational candidates**; no analyst case is automatically created.

This path deliberately **does not** connect real detector verdicts to real source-event identities. That is future work after the exact Splunk collector format and trusted source fields have been validated at the owner's home PC. Never use source preflight alone to assert a finding, and do not supply personal, workplace, patient or production log contents.

## Pipeline 17.0 — collector trust policy rehearsal

See [collector trust readiness](../docs/COLLECTOR_TRUST_READINESS.md) for the offline,
synthetic authentication-outcome simulation, adversarial tests and future trust
boundaries. No actual collector or source authentication is established.

## Pipeline 18.0 — durable synthetic delivery

[Durable delivery and recovery](../docs/DURABLE_DELIVERY_RECOVERY.md) adds a bounded
SQLite queue, persistent replay identity reservations, verified local receipts,
explicit retries and crash recovery tests. This does not deliver to a live service.
