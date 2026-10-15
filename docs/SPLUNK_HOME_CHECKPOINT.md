# Resume live Splunk setup at home

**Deferred:** October 14, 2026. The owner is at work and has not confirmed whether Splunk is installed on their home Windows PC.

**Status:** Pending. No live endpoint, index permissions, management port, CA certificate, or credentials are confirmed; all current integration demonstrations use synthetic data. Do not assume live readiness.

## First check when the owner returns to their PC

Run this local PowerShell command:

```powershell
Get-Service *Splunk*
```

If it returns nothing, check installed apps for Splunk Enterprise, or discuss a new Splunk Enterprise lab installation. If Splunk Cloud is used, confirm the environment and authorized access rather than installing Enterprise.

After confirmation, configure an authorized test index, least-privileged read-only token and verified HTTPS trust. Never upload secrets or export sensitive workplace/patient logs. Use [the opt-in count-only probe](../splunk-readonly-connector/README.md) first; do not directly connect raw log feeds.

Only after successful local authenticated connectivity should live field mapping, provenance checks, replay protection, refresh behavior and end-to-end validation begin. The synthetic demonstration can continue without the owner's PC: [SOC demo](../soc-demo/README.md).

**To resume:** In ChatGPT say "I'm home, let's resume Splunk." Check installation first; do not claim a successful connection from offline CI.
