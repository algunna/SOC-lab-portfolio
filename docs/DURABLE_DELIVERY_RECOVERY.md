# Pipeline 18.0 — Durable event delivery and recovery

## What acknowledgment means

This is a bounded, **synthetic offline queue**. Acknowledgment means the local
batch processor completed, sealed reports passed semantic and integrity checks,
and the exact verified receipt committed in the queue database. It is not an
acknowledgment from Splunk, a remote service or an analyst. No network, live
collector, real credential, incident execution or automatic case creation exists.

Pipeline 17's credential/transport assertions remain test doubles. The CLI's
`enqueue-fixture` command explicitly simulates successful policy checks against
the fixed synthetic fixture. These values must never authorize live ingestion.
Queued records retain their synthetic informational status on delivery.

## Durable state and replay behavior

`controlled-telemetry-lab/src/durable_delivery.py` maintains one private SQLite DB:

- `batches`: normalized synthetic observations, payload digest, pending or
  acknowledged status, and verified downstream receipt.
- `identities`: source observation key, event key and payload fingerprint bound to
  the owning batch. These reuse the existing replay guard's canonical key logic.

Enqueue commits the observations and identity reservation together. Identical
reimports skip reserved records even before delivery. Changed content under a
reserved identity rejects the entire import. Overlapping batches enqueue only new
observations. Identity reservations are not delivery acknowledgments.

Delivery holds a SQLite writer transaction during bounded local processing. It
validates the stored synthetic alert semantics, digest and identity bindings,
processes a temporary batch, verifies the seal and recomputed correlation, and
checks the receipt matches the queued observations exactly. Status and receipt
commit together using SQLite `synchronous=FULL`. Competing workers serialize or
fail with a safe busy error; no background retries are scheduled.

The existing replay guard's separate database/file-write transaction is **not**
used for delivery: its own documented crash limitation would leave two independent
commit boundaries. This queue owns a separate ledger using the same key semantics;
it does not import or share another replay database. Synthetic IDs are deterministic,
so alternate event aliases are not accepted in this path.

## Recovery matrix

| Interruption or invalid input | Expected result |
| --- | --- |
| Before enqueue commit | Batch and identity reservations roll back together |
| Restart with pending batch | Observations remain available for explicit delivery |
| Downstream unavailable, blocked, malformed or unverifiable | Batch stays pending; no receipt or acknowledgment |
| Worker killed after processing but before commit | SQLite rolls back; retry recomputes temporary output |
| Worker killed after commit | Receipt survives; repeat delivery finds no pending batch |
| Repeated or overlapping imports | No second queue reservation for the same observation |
| Changed payload or damaged identity binding | Delivery refuses; evidence is retained for inspection |
| Corrupt receipt | Explicit receipt verification refuses; no false successful verification |
| Corrupt database or unknown schema | Fail closed; never silently replace state |
| Queue capacity reached | Reject new batch atomically; preserve existing state |

Temporary processing can occur more than once after a crash. Only the committed
local receipt is the delivery record. This is **not an exactly-once external
transport**. Temporary directories left by a killed process are unacknowledged
scratch data and must not be discovered or ingested as successful outputs.

## Run the offline rehearsal

Choose a new private queue directory. On POSIX the queue directory and database
must not be group/world accessible. On Windows protect the directory using local
ACLs. Never use a shared or attacker-writable parent directory or network filesystem.

```bash
python -m pip install -r soc-event-contract/requirements.txt
python controlled-telemetry-lab/src/durable_delivery.py --queue-dir /tmp/soc-delivery-demo enqueue-fixture
python controlled-telemetry-lab/src/durable_delivery.py --queue-dir /tmp/soc-delivery-demo deliver-one
python controlled-telemetry-lab/src/durable_delivery.py --queue-dir /tmp/soc-delivery-demo verify-receipt --batch-id 1
python controlled-telemetry-lab/src/durable_delivery.py --queue-dir /tmp/soc-delivery-demo enqueue-fixture
python controlled-telemetry-lab/src/durable_delivery.py --queue-dir /tmp/soc-delivery-demo deliver-one
python -m unittest discover -s controlled-telemetry-lab/tests -v
```

Expected initial counts: queued 6, acknowledged 6. Reimport: queued 0, duplicates 6.
Repeat delivery: acknowledged 0. Verification rereads and checks the stored receipt.
The receipt API returns verified report bytes for explicit read-only consumption;
integration tests feed those reports to the Command Center adapter, yielding six
informational observations, six unverified candidates and zero cases.

## Limits and remaining gates

- Maximum 100 retained batches, at most 40 observations per import. No automatic
  deletion or retention pruning; deleting the DB destroys deduplication history.
- No automatic retry loop, remote delivery, authentication protocol or credential
  refresh. Real revocation must be checked at the future live delivery boundary.
- Corrupt head-of-queue data blocks progress. Preserve the DB and investigate;
  automatic quarantine, health reporting and operator recovery are future work.
- Tests exercise abrupt **process** death, SQL write failure, concurrent imports
  and workers, unavailable processing, corruption and restart. They do not prove
  durability under hardware/power loss, filesystem failure or malicious local admin.
- SQLite and local hashes are not authenticated provenance. A user able to rewrite
  the database, identities and receipts can forge consistent state. Queue initialization
  must be completed before starting concurrent workers; interrupted initial creation
  is refused rather than repaired. Trusted local directory ownership is required.
- Independent VORTEX/Titan security review remains pending and is required before
  enabling a real collector. Review transaction boundaries, local file races,
  identity retention, corruption recovery and remote acknowledgment semantics.
- [Home-PC Splunk checkpoint](SPLUNK_HOME_CHECKPOINT.md) remains pending, starting
  with `Get-Service *Splunk*`. No live event-to-incident workflow has been proven.

Next candidates: collector health/audit/reliability, then live acceptance preparation.
These do not replace the home-PC setup and authorized live end-to-end demonstration.
