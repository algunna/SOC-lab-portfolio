# SOC Incident Correlation MVP

Conservative **offline grouping of already-normalized alerts** from [SOC Event Ingestion](../soc-event-ingestion). Produces *unverified incident candidates*, **not proven attacks or automatically opened cases**.

## Run

```bash
python -m pip install -r soc-event-contract/requirements.txt
python soc-event-ingestion/src/ingest.py soc-event-contract/examples/windows_alert.json --out /tmp/soc-ingested.json
python soc-incident-correlation/src/correlate.py /tmp/soc-ingested.json --out /tmp/soc-candidates.json
python -m unittest discover -s soc-incident-correlation/tests -v
```

Use suitable writable paths on Windows. Output files must not exist already.

## Correlation hardening (v0.2)

The engine revalidates all accepted events using SOC Event Contract v1, rejects duplicate source-system/event IDs, normalizes timezone-aware timestamps into UTC and uses a **15-minute fixed window by default** (configurable via `--window-minutes`, 1–1440). The window is anchored to the first event in each group, not extended by subsequent events. No cross-source identity resolution is attempted. The matching logic remains an experimental heuristic, and batch composition affects candidate IDs.

## Exact grouping rule

Alerts only group when `source.system`, `actor`, and `asset` **all exactly match**. If either actor or asset is absent/empty, the alert is isolated using its event ID. The grouping is deterministic within a single report and limited to fixed UTC event-time windows; sorted evidence reference strings are retained. Candidate IDs hash the grouping key plus alert IDs and are only stable for the *same batch composition*. There is no identity resolution, cross-source correlation, persistence, provenance authentication, or link to the case-management database.

The code refuses reports containing any rejected records. It assumes the `accepted` list was validated by the ingestion tool, so **do not treat arbitrary external JSON as trusted**. Even within a time window, unrelated events can group; same actors/assets can represent different real people or systems. Every result is explicitly `classification: unverified` and needs analyst review.

Only synthetic sanitized data should be used. This does not implement threat scoring, incident escalation, or automated remediation.
