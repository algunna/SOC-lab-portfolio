# Pipeline 19.0 — Collector health, audit and reliability

This milestone adds **read-only offline queue verification** and a bounded local
operational audit. It does not monitor a live collector, authenticate provenance,
repair data, schedule retries or enable Splunk.

## Read-only health

```bash
python controlled-telemetry-lab/src/collector_health.py --queue-dir /tmp/soc-delivery-demo
```

The checker opens an existing database with SQLite `mode=ro` and `query_only`,
using one consistent read transaction. It never initializes a missing queue,
migrates a database, or changes queue records. Receipt verification uses disposable
temporary files outside the queue; tests confirm the queue files remain byte-identical.

Before reporting counts, it checks SQLite integrity and foreign keys, every stored
synthetic payload and identity binding, acknowledged receipt semantics, and audit
record structure and attempt relationships. Invalid data yields a fixed reason
code; payloads, credentials, source identities and supplied paths are not echoed.

| Status | Meaning |
| --- | --- |
| `idle` | Verified snapshot has no pending batches or recorded warnings; not proof of collector liveness |
| `pending` | Verified observations await explicit delivery; age/staleness is not inferred |
| `attention` | Historical failures, unresolved attempts or capacity limits need operator review |
| `blocked` | Queue, receipt or audit validation failed; preserve state and investigate |
| `unavailable` | State cannot be read, is missing, busy or otherwise unavailable |
| `uninstrumented` | Pipeline 18 state verifies but has no Pipeline 19 audit history |

CLI exits 2 for blocked, unavailable or uninstrumented state. Attention is an
operational warning reported in JSON; it is not a failed integrity check.
Output contains counts, fixed action/reason codes and up to 20 recent audit entries
with local sequence, local Unix timestamp and observation count. It is not streamed
to an external dashboard and does not include raw event contents.

## Audit and transaction boundaries

The first write transaction upgrades schema 18 to 19 atomically, adding the audit
table and SQL triggers that reject updates/deletes. Existing batches and receipts
are preserved. Failed migration rolls back; unsupported versions are refused.
The read-only checker never performs this migration.

Events recorded:

- `enqueued`: written in the same transaction as new observations and identities.
- `duplicates_skipped`: a fully duplicate import was skipped.
- `delivery_started`: committed before local processing begins.
- `delivery_acknowledged`: committed atomically with the verified receipt/status.
- `delivery_empty`: the attempt found no pending batch.
- `delivery_refused`: processing failed; the pending batch remains unchanged.

Each delivery outcome refers to its start sequence. Abrupt process death leaves
an unresolved start. This means the outcome is unknown in the audit, **not** that
a worker is currently running. A later successful retry does not erase this history.
Acknowledgment audit failure rolls back the receipt. If failure logging itself is
unavailable, the caller gets a fixed failure and the start may remain unresolved.
No background job silently closes or deletes unresolved records.

The audit has a 10,000-entry cap. Delivery checks room for start and outcome;
capacity exhaustion refuses writes safely. Concurrent writers can consume space
between start and outcome, so an outcome write can still fail and roll back the
acknowledgment. No automatic pruning removes identity or audit history.

## Scope and reliability limits

- Audit history begins at schema 19. It does not reconstruct previous successful
  operations, rejected preflight/authentication imports, or past failures. Partial
  duplicate imports record the newly queued count; they do not record a separate
  duplicate count. Health explicitly labels the audit scope.
- Triggers enforce append-only behavior for ordinary application operations.
  They are **not tamper-proof storage**: a local administrator can alter schema,
  delete the DB or forge consistent records. `audit_authenticated` remains false.
- Timestamps use the host clock and are not trusted time evidence. Queue age,
  heartbeat, throughput and actual service availability are not inferred.
- A damaged payload at the front of the queue still blocks delivery. Keep the
  original database and inspect trusted local state; no automatic repair, clearing,
  quarantine or destructive recovery command is provided.
- Trusted private local storage is required. Power-loss, disk-full and malicious
  filesystem races are not fully validated. Process crash, SQL audit-write failure,
  failed migration and concurrency behavior have offline regression coverage.
- Warnings remain after a later success because historical failures/unresolved
  attempts remain. Operator acknowledgment of warnings is future work.

## Validation and remaining checkpoints

```bash
python -m unittest discover -s controlled-telemetry-lab/tests -v
```

Tests cover read-only behavior, legacy migration and rollback, missing/corrupt
state, atomic audit/receipt writes, process crash, bounded output, redaction and
safe CLI failure. Pipeline 18's crash/replay/concurrency tests remain active.
CI verifies the queue across separate process invocations and checks its health.

The [home-PC Splunk checkpoint](SPLUNK_HOME_CHECKPOINT.md) remains pending, starting
with `Get-Service *Splunk*`. Independent VORTEX/Titan review remains pending and
must happen before enabling a real collector. Pipeline 20 should prepare acceptance
criteria and evidence capture for authorized real lab telemetry, without claiming
that synthetic success proves live integration.
