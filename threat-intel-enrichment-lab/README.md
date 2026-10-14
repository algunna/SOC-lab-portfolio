# IOC Classification Lab

Offline, evidence-based IOC format classification for a SOC analyst training portfolio.

## What it does

Reads indicators from `iocs/sample_iocs.txt`, recognizes valid IPv4/IPv6 addresses, domains and 32/40/64-character hexadecimal hashes, then produces a Markdown report. It uses standard Python libraries and does **not** call an external API.

The result deliberately reports `Not assessed` reputation and `Unknown` risk. A valid-looking domain, hash or IP address is not proof of malicious activity. Threat-intelligence enrichment requires a trusted, current external source and additional context.

## Run

From the repository root:

```bash
python threat-intel-enrichment-lab/scripts/threat_intel_enrichment.py
python -m unittest discover -s threat-intel-enrichment-lab/tests -v
```

The report is written to `threat-intel-enrichment-lab/reports/threat_intel_report.md`.

## Analyst workflow

1. Classify the indicator format.
2. Verify its provenance, surrounding events, and relevant asset context.
3. If authorized, check current threat-intelligence sources.
4. Only assign a reputation or severity when supporting evidence is available.
5. Record uncertainty and evidence in the final investigation.

This lab does not contact threat feeds, use an LLM, or assert that the sample IOCs are malicious. Older committed example reports are historical and may reflect unverified prototype judgments.
