# SSH Authentication SOC Triage (AI SOC Copilot Lab)

This project now defaults to **offline, deterministic** SSH authentication analysis rather than sending raw logs to an external AI service. It is an educational detection and reporting lab, not a production detection system.

## Run

From the repository root:

```bash
python ai-soc-copilot/scripts/soc_copilot.py
python -m unittest discover -s ai-soc-copilot/tests -v
```

Optionally provide `--input path/to/authorized.log --output path/to/report.md`.

No packages need to be installed; the script uses only the Python standard library. [reports/incident_report.md](reports/incident_report.md) is the output of the default command against the synthetic sample log. CI runs the tests and the sample workflow in [soc-copilot-tests.yml](../.github/workflows/soc-copilot-tests.yml).

## Detection

Parses common OpenSSH failed/accepted password events with valid IPv4/IPv6 addresses. Counts failed passwords *per source IP*. Demo thresholds: 3-4 = Medium, 5+ = High, fewer = Low. This is not a time-windowed detection, nor evidence of compromise. Correlate account activity, timestamps and asset context before escalating.

## Security and scope

No API key, network connection or OpenAI dependency is required. Raw logs are not embedded in reports or transmitted outside the system by the script. Use only synthetic or authorized data. Analyst findings and ATT&CK T1110 mapping are hypotheses requiring human confirmation.

The earlier prototype sent logs to an AI model for summarization; the folder keeps its original name so existing links still work. This offline version has no AI component and emphasizes auditable rules and reproducible tests.
