# Windows Threat Hunting Lab

A self-contained **offline** blue-team training lab for investigating normalized Windows Security events. This lab produces reproducible investigation leads, not claims of confirmed malicious behavior.

## Detections

| Event ID | Detection | MITRE ATT&CK investigation hypothesis |
| --- | --- | --- |
| 4688 | PowerShell command line contains encoded command, execution-policy bypass, or hidden-window indicators | T1059.001 |
| 4728 / 4732 | Added member to privileged group in the lab sample | T1098 |
| 4698 | Scheduled task created | T1053.005 |
| 4625 followed by 4624 | Five failed logins followed by a success within five minutes from the same host, user and source IP | T1110 |

## Run

From the root of the GitHub repository:

```bash
python windows-threat-hunting-lab/src/hunt.py
python -m unittest discover -s windows-threat-hunting-lab/tests -v
```

Optional `--input path/to/events.jsonl` and `--output path/to/findings.json`. Each input line must be a JSON object containing a numeric `event_id` and relevant event fields (e.g. `timestamp`, `host`, `user`, `image`, `command_line`, `group`, `source_ip`). The sample data is entirely synthetic.

**Important:** This is not a raw EVTX ingestion engine. Export and normalize authorized logs before use. Process-command flags, group changes and scheduled task creation can be legitimate. ATT&CK labels are analyst hypotheses requiring event context. This lab never executes commands from event data, makes network requests, or changes endpoint settings.
