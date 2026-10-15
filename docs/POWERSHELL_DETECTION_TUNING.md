# PowerShell host-flag detection tuning

## Confirmed gaps

Both the normalized Windows 4688 hunter and Sysmon Event ID 1 analyzer previously
split command text on whitespace and searched every token. This missed quoted
host switches/values and confused script parameters or command-body text with
PowerShell host options.

The shared [14-case fixture](../tests/fixtures/powershell_host_flags.json) reproduces
these gaps. Before the change, each detector disagreed with the curated expectations
in 9 of 14 cases: four quote-related missing indicators and five boundary-related
extra indicators. After the change, each matches all 14. The same matrix is tested
through the Windows JSON and Sysmon XML event entrypoints, not just a helper.

These are **synthetic host-flag policy expectations**, not measurements of malicious
activity, production false-positive rate or attack-detection recall. The existing
32-scenario Windows/AWS accuracy matrix remains unchanged and is tested separately.

## Changed behavior

Both detectors now use [the shared host-flag helper](../scripts/powershell_flags.py).
It groups double-quoted argument fragments and handles backslashes before quotes.
It retains case-insensitive switch matching, existing abbreviated/prefix forms,
encoded-command indicators, execution-policy bypass and hidden-window indicators.
Single quotes in native Windows command-line text are treated literally.

The scan stops at explicit `-Command` or `-File` boundaries (including abbreviated
forms), and at `-CommandWithArgs`/`-cwa`. Indicators before the boundary remain;
text after it is not claimed to be a host switch. For example:

| Process command line | Host-flag finding |
| --- | --- |
| `powershell.exe -ExecutionPolicy "Bypass"` | Execution policy bypass |
| `powershell.exe "-EncodedCommand" AAAA` | Encoded command |
| `powershell.exe -ep Bypass -Command Write-Output -enc` | Execution policy bypass only |
| `powershell.exe -File report.ps1 -enc sample` | None from this rule |
| `powershell.exe -Command Write-Output -EncodedCommand` | None from this rule |

A missing encoded payload still produces a review lead, preserving the existing
policy; it does not prove successful execution. A benign encoded `Get-Date` example
also remains a lead. There is no payload-based allowlist and nothing is decoded or
executed. Alert rule IDs, severities and analyst approval behavior are unchanged.

## Interpretation and limits

No host-flag finding does **not** mean a command is safe. Script content, command
bodies, nested PowerShell invocations, implicit file/command syntax, unknown option
semantics and decoded payload analysis need separate detection rules. A child
process may provide its own process event, but collection is not guaranteed.
This helper is a heuristic over logged Windows command-line text, not a complete
PowerShell grammar, exact native parser emulation, or proof of accepted arguments.
Unbalanced quotes may reflect truncated logs; grouping to end is best-effort.
PowerShell versions and invocation environments still need authorized live checks.

Both labs now depend on the repository's `scripts/powershell_flags.py`; copy the
repository rather than only an individual detector file. CI triggers on helper
changes and tests both consumers to prevent drift.

## References and verification

Microsoft documents that values following `-File` belong to the script invocation,
and that string `-Command` consumes following arguments as command text. See
[about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).
Quote/backslash grouping follows the relevant native Windows conventions described
in [Parsing C command-line arguments](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments?view=msvc-170), without claiming full runtime equivalence.

```bash
python -m unittest discover -s tests -p test_powershell_flags.py -v
python -m unittest discover -s windows-threat-hunting-lab/tests -v
python -m unittest discover -s detection-accuracy-lab/tests -v
```

The Splunk home-PC checkpoint and independent VORTEX/Titan review remain pending.
No live telemetry, real collector or automatic incident case is enabled by this fix.
