# Splunk SOC Hunting Searches & Analyst Playbooks

Three example SPL searches aligned with the [Sigma Detection Lab](../sigma-detection-lab) and Windows hunting scenarios. Each search requires **real Splunk field mappings, indexes and sourcetypes to be adapted** to the target deployment.

## Searches

| SPL | Windows source | Analyst playbook |
| --- | --- | --- |
| [Encoded PowerShell](searches/powershell_encoded.spl) | Sysmon Event ID 1 | [PowerShell triage](playbooks/POWERSHELL.md) |
| [Privileged group change](searches/privileged_group_change.spl) | Security 4728/4732 | [Group membership](playbooks/PRIVILEGED_GROUP.md) |
| [Scheduled task creation](searches/scheduled_task_created.spl) | Security 4698 | [Scheduled tasks](playbooks/SCHEDULED_TASK.md) |

## Safe usage

Searches are read-only and written for **training and adaptation**. They do not initiate remediation, execute discovered commands, or access live infrastructure by themselves. Test in a lab Splunk instance with authorized synthetic logs before deployment.

## Verification

The repository's automated checks validate local file integrity and expected search characteristics, **not execution against a real Splunk server or correctness of every vendor-specific field mapping**. Do not call these production-certified searches.
