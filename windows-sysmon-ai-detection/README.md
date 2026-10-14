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

- Input must be XML exported from Sysmon, **not binary EVTX**: either an `<Events>` document or the bare `<Event>` elements that `wevtutil qe ... /f:xml` writes. A binary `logs/sysmon.evtx` captured from a personal workstation was removed from the current tree because it held real account and host details; it remains in Git history.
- Supported detection: Sysmon Event ID 1 where the process is PowerShell (by `Image`, or by `OriginalFileName` for a renamed copy) and the command line has an encoded-command, execution-policy bypass or hidden-window switch. Abbreviations PowerShell accepts (`-e`, `-ec`, `-enc`, `-ep`, `-w`) and `/` or en/em-dash prefixes are matched.
- Log fields are escaped in the Markdown report so log content cannot add headings, links or lines.
- [reports/sysmon_detection_report.md](reports/sysmon_detection_report.md) is the output of the default command against the synthetic fixture.
- ATT&CK T1059.001 is a triage hypothesis. A matching command line does not prove compromise.
- Never upload confidential telemetry to an external API; this script runs offline and needs no API key.
- The provided XML fixture is synthetic.
