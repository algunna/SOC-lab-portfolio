# Sigma Detection Engineering Lab

Three experimental, portable Sigma rules for Windows security operations: encoded PowerShell command-line activity, privileged group membership changes, and scheduled-task creation.

## Run validation

From the repository root:

```bash
python -m pip install -r sigma-detection-lab/requirements.txt
python sigma-detection-lab/scripts/validate_rules.py
python -m unittest discover -s sigma-detection-lab/tests -v
```

The 15 synthetic fixture cases include expected matches and benign/non-matching examples, including abbreviated PowerShell switches (`-e`, `/ec`), event IDs stored as text and lowercase group names. The matcher supports the `endswith`, `contains` and `re` modifiers, and compares plain values case-insensitively as Sigma does. `validate_rules.py` is a **purpose-built fixture matcher for the three rules only**, not a complete Sigma specification validator, Sigma CLI replacement, or production SIEM backend. Actual SIEM deployment requires appropriate field mappings, source configuration, rule conversion, and environment-specific tuning.

## Mapping and limitations

- Encoded PowerShell — ATT&CK T1059.001. Legitimate management tools can use encoded commands.
- Privileged membership — ATT&CK T1098. Group naming and event field conventions depend on log ingestion and environment.
- Scheduled tasks — ATT&CK T1053.005. Common software creates legitimate scheduled tasks.

These are investigation hypotheses, not confirmed attacks. Do not assign confirmed maliciousness without contextual review. All fixtures are synthetic; no real endpoints or customer telemetry are accessed.
