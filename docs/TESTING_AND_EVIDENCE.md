# Testing and Evidence Guide

## What counts as verified

- **Local verification:** run the exact working-tree code with named fixture/test commands and record actual results.
- **GitHub Actions verification:** check the workflow's conclusion and that its `head_sha` matches the PR head being reviewed.
- **Merged validation:** verify merge commit and green workflows where applicable.
- **Production detection accuracy:** requires representative authorized data, meaningful false-positive/false-negative measurements and independent validation. None of the current synthetic tests alone establish this.

## Existing workflows

| Lab | GitHub Actions workflow |
| --- | --- |
| Windows Sysmon and phishing | [soc-detection-tests.yml](../.github/workflows/soc-detection-tests.yml) |
| Windows Threat Hunting | [windows-threat-hunting.yml](../.github/workflows/windows-threat-hunting.yml) |
| AWS CloudTrail | [cloudtrail-threat-hunting.yml](../.github/workflows/cloudtrail-threat-hunting.yml) |
| AWS correlation | [cloudtrail-2-tests.yml](../.github/workflows/cloudtrail-2-tests.yml) |
| AWS identity triage | [cloudtrail-identity-tests.yml](../.github/workflows/cloudtrail-identity-tests.yml) |
| Sigma validation | [sigma-detection-tests.yml](../.github/workflows/sigma-detection-tests.yml) |
| AI SOC Copilot (SSH triage) | [soc-copilot-tests.yml](../.github/workflows/soc-copilot-tests.yml) |
| CloudTrail SOC Pipeline | [cloudtrail-soc-pipeline-tests.yml](../.github/workflows/cloudtrail-soc-pipeline-tests.yml) |
| Threat intel IOC classification | [threat-intel-tests.yml](../.github/workflows/threat-intel-tests.yml) |

Not all legacy labs currently have CI coverage; see their README and source tests individually.

## Safe investigation evidence

Use synthetic or authorized sanitized events. Include at least one matching case, one nonmatching case and a malformed-input case where meaningful. Record the tested input, expected output, actual output and any failures without exposing secrets or patient/customer data.

For examples of earlier successful CI runs, inspect the relevant merged PR's Checks tab. These links are historical, not a guarantee that future builds will pass.
