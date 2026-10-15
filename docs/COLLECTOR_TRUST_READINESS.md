# Pipeline 17.0 — Collector trust and authentication readiness

## Scope and evidence

This is an **offline policy simulation**, not a live authentication implementation.
`controlled-telemetry-lab/src/collector_trust.py` accepts test-double credential and
transport outcomes. A caller can supply `valid`; that proves nothing about a real
credential. Never expose this API as a receiver or use its result to authorize
live ingestion. It has no network, secret access, listener or production switch.

The fixed lab collector is scoped to synthetic Windows and CloudTrail observations.
All source rows pass the Pipeline 16 strict source/evidence/time validation before
any observations are returned. Accepted results explicitly retain
`live_collector_authenticated: false` and `live_source_verified: false`.
Alerts remain informational and correlation candidates unverified. Cases still
require analyst review; the simulation cannot create or execute an incident.

## Trust boundaries for a future implementation

| Boundary | Required behavior | Current evidence |
| --- | --- | --- |
| Operator to collector configuration | Operator-owned collector ID, permitted indices and source namespaces; payload cannot grant itself scope | Fixed synthetic collector/source scope only |
| Collector to Splunk | Verified HTTPS server identity, no redirects, least-privilege search token, bounded reads | Existing count-only probe has mocked tests; home-PC check pending |
| Collector to future receiver | Independently verified collector credential bound to operator registry and allowed source scope | Policy outcomes simulated only; protocol and credential issuer not selected |
| Source record to alert | Strict source identity, generation, timestamp and evidence matching; reject whole invalid batch | Reuses Pipeline 16 synthetic validation |
| Accepted batch to delivery | Durable atomic replay reservation plus authenticated acknowledgment and recoverable retry | Session-local replay rejection only; existing persistent ingestion guard remains separate |

Authenticating a collector does not authenticate the origin or truth of every
Windows/AWS record it supplies. Future mapping must verify trusted extraction,
Windows log generation, AWS account/region scope and source-to-detector linkage.
A Splunk API credential authenticates the client to Splunk; it does not by itself
identify a collector to a separate SOC receiver.

## Failure and credential design

Missing, invalid, expired, revoked or unavailable simulated credentials refuse
processing before source parsing. Invalid certificate, redirect, timeout or
unavailable transport likewise refuse processing. No fallback to anonymous access,
no credential echo, and no partial batch output are allowed. Unknown statuses,
extra fields (including token/password/authorization), wrong types, unknown
collectors and live-mode claims are rejected with fixed error codes.

Future credentials must stay in a local secret provider or protected environment,
never event payloads, command arguments, URLs, evidence, dashboard or logs. Validate
issuer/audience/expiry and registry binding according to the chosen protocol;
check revocation and deny when verification is unavailable. Rotation must allow a
bounded operator-approved overlap and explicitly retire old credentials. No real
credentials are needed or read for this milestone. Production credential storage,
rotation, revocation freshness, TLS and issuer behavior are not tested here.

The rehearsal rejects repeated source identities, including changed content with
the same identity, within a single session. Failed authentication and malformed
batches reserve no identities. **State is lost on restart**; this is not durable
or concurrent replay protection and does not exercise the downstream persistent
guard. A future receiver must join durable acceptance, replay state and delivery
acknowledgments transactionally before enabling live ingestion. Retry only bounded
transient failures; never retry revoked credentials or invalid records indefinitely.

## Verification

```bash
python -m pip install -r soc-event-contract/requirements.txt
python -m unittest discover -s controlled-telemetry-lab/tests -v
```

Adversarial tests cover credential/transport failures, identity and scope forgery,
secret-field rejection, malformed records, replay/conflicting payloads, failed-batch
state rollback, and the six observations through sealed ingestion and the read-only
Command Center with zero cases. CI discovers these tests automatically.

## Required remaining checkpoints

- [Home-PC Splunk checkpoint](SPLUNK_HOME_CHECKPOINT.md): resume with PowerShell
  `Get-Service *Splunk*`. Installation, connectivity, permissions and actual source
  field mapping remain unverified.
- Independent VORTEX/Titan security review remains pending. Challenge trust-boundary
  confusion, spoofed assertions, revocation outage, credential leakage, concurrency,
  replay across restart, delivery recovery and source-to-detector evidence binding.
- Implement and review a real authentication protocol separately; this simulator
  must not be reused as a live admission gate.
- Demonstrate authorized real lab event → detection → normalized alert → correlation
  → analyst review → incident case → Command Center before claiming completion.
