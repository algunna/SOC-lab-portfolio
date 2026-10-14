# Project Documentation Standard

Every **new or substantially modified** SOC lab should include:

1. **Purpose and scope:** specific investigative question and training-only limitations.
2. **Data inputs:** accepted formats, event IDs/fields, provenance, and whether fixtures are synthetic.
3. **Detections:** exact conditions, thresholds, ATT&CK hypotheses and false-positive cases.
4. **Run instructions:** working-directory assumptions, Python dependencies and reproducible commands.
5. **Tests:** fixture coverage, expected outcomes, CI workflow path and what it does not prove.
6. **Outputs:** example report schema, output paths and analyst interpretation guidance.
7. **Security and privacy:** offline/API behavior, secret management and sensitive data handling.
8. **Limitations and roadmap:** unsupported formats, missing enrichment and next improvements.

For significant changes, update **CHANGELOG.md**, keep the README aligned with the code, and add or revise tests. Never invent evidence of a successful run. A green CI badge only establishes that its configured checks passed, not detection effectiveness in production. Mapping to MITRE ATT&CK is a *hypothesis*, not attribution or a confirmed incident.

## Pull request checklist

- [ ] Detection logic and documentation match
- [ ] Synthetic success and negative fixtures are included
- [ ] Automated checks run against the exact PR commit
- [ ] Inputs, outputs, dependencies and execution path are documented
- [ ] No credentials, personal data or unredacted sensitive logs committed
- [ ] Changelog entry added for meaningful change
- [ ] Known limitations explicitly stated
