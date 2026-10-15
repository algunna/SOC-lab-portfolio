# Windows Threat Hunting Lab

A self-contained **offline** blue-team training lab for investigating normalized Windows Security events. This lab produces reproducible investigation leads, not claims of confirmed malicious behavior.

## Detections

| Event ID | Detection | MITRE ATT&CK investigation hypothesis |
| --- | --- | --- |
| 4688 | PowerShell command line contains encoded command (`-EncodedCommand` or any abbreviation such as `-e`, `-ec`, `-enc`), execution-policy bypass (`-ExecutionPolicy`/`-ep Bypass`), or hidden-window (`-WindowStyle`/`-w Hidden`) switches. `/` and en/em dashes are accepted as switch prefixes, as PowerShell does | T1059.001 |
| 4728 / 4732 / 4756 | Member added to Administrators, Domain Admins, Enterprise Admins or Schema Admins | T1098 |
| 4698 | Scheduled task created | T1053.005 |
| 4625 followed by 4624 | Five failed logins without an intervening matching success, followed by a success within five minutes from the same host, user (case-insensitive) and source IP; timestamps are compared in UTC | T1110 |

## Run

From the root of the GitHub repository:

```bash
python windows-threat-hunting-lab/src/hunt.py
python -m unittest discover -s windows-threat-hunting-lab/tests -v
```

Optional `--input path/to/events.jsonl` and `--output path/to/findings.json`. Each input line must be a JSON object containing a numeric `event_id` and relevant event fields (e.g. `timestamp`, `host`, `user`, `image`, `command_line`, `group`, `source_ip`). The sample data is entirely synthetic.

**Important:** This is not a raw EVTX ingestion engine. Export and normalize authorized logs before use. Process-command flags, group changes and scheduled task creation can be legitimate. ATT&CK labels are analyst hypotheses requiring event context. This lab never executes commands from event data, makes network requests, or changes endpoint settings.

## Authentication identity guard (Pipeline 12.0)

`success_after_failures` now refuses missing, empty or literal `unknown` host, account or source IP fields rather than correlating unrelated unidentifiable records. The rest of the offline rules remain unchanged. This is a false-positive safeguard, not evidence of real-world detector accuracy. See [synthetic policy evaluation](../detection-accuracy-lab/README.md).

## Host-flag parsing update

The [PowerShell tuning notes](../docs/POWERSHELL_DETECTION_TUNING.md) explain quoted
arguments, explicit Command/File boundaries and the shared repository helper.
Findings remain heuristic investigation leads; command/script bodies require
separate analysis and are not declared safe when this rule is quiet.

## Authentication sequence reset

Every matching success now clears the failure sequence, including successes below
threshold. See [authentication regression details](../docs/AUTHENTICATION_DETECTION_TUNING.md).
