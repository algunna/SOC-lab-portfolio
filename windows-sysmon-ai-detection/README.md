# Windows Sysmon PowerShell Detection Lab

Offline Sysmon **Event ID 1** triage using XML-exported Windows events. This version examines actual event fields for PowerShell command-line indicators rather than returning fixed findings.

## Run

From the repository root:

```bash
python windows-sysmon-ai-detection/scripts/sysmon_ai_detector.py
python -m unittest discover -s tests -v
```

Custom input: `--input path/to/events.xml --output path/to/report.md`.

## Limits

- Input must be XML exported from Sysmon, **not binary EVTX**. The original `logs/sysmon.evtx` in this repository is empty and is not usable sample evidence.
- Supported detection: Sysmon Event ID 1 with PowerShell executable and encoded command, bypass, or hidden-window switches.
- ATT&CK T1059.001 is a triage hypothesis. A matching command line does not prove compromise.
- Never upload confidential telemetry to an external API; this script runs offline and needs no API key.
- The provided XML fixture is synthetic.
