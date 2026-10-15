# SOC Demo — Offline End-to-End Walkthrough

A reproducible demonstration spanning **synthetic Splunk saved-search results → validated normalized alerts → offline ingestion → bounded correlation → optional manual case approval → SQLite → read-only SOC Command Center**.

**No network requests, Splunk server, sensitive logs, SIEM credentials, or automatic response actions are required.** Nothing is connected to live systems. These are training data and *unverified* hypotheses.

## Requirements

From repository root, use Python 3.12+ and install the event validator:

```bash
python -m pip install -r soc-event-contract/requirements.txt
```

## Step 1: Prepare synthetic investigation (no cases created)

Choose a fresh, private directory. Example for Linux/macOS:

```bash
python soc-demo/scripts/run_demo.py prepare --out-dir /tmp/atlas-soc-demo-01
```

Example Windows PowerShell:

```powershell
python soc-demo/scripts/run_demo.py prepare --out-dir "$env:TEMP\atlas-soc-demo-01"
```

The directory **must not already exist**. The runner creates validated artifacts: `alerts.jsonl`, `ingestion.json`, `correlation.json`, `dashboard.json`, and `manifest.json` with SHA-256 hashes. It prints the three synthetic, unverified candidate IDs. A missing or invalid manifest prevents later approval.

View the read-only initial dashboard (still no cases):

```bash
python soc-command-center/src/dashboard.py --data /tmp/atlas-soc-demo-01/dashboard.json
```

Open `http://127.0.0.1:8765/` locally. On Windows, replace the example path with your prepared directory.

## Step 2: Optional, explicit **human** case approval

Select one candidate ID printed during preparation or read it from `correlation.json`. In a private **synthetic demo only**, after reviewing the candidate, run:

```bash
python soc-demo/scripts/run_demo.py approve --demo-dir /tmp/atlas-soc-demo-01 --candidate-id candidate-REPLACE-WITH-PRINTED-ID --analyst synthetic-training-reviewer --approve-demo-case
```

No approval takes place without the exact `--approve-demo-case` flag. This action uses the existing case-promotion module and writes one **synthetic** case in `cases.db` with history and audit information. It then creates `approved-dashboard.json` using the SQLite **read-only** case snapshot. Prior generated artifacts are checked against the manifest before approval; repeat approvals and output overwrites are refused.

Display the approved synthetic snapshot:

```bash
python soc-command-center/src/dashboard.py --data /tmp/atlas-soc-demo-01/approved-dashboard.json
```

The manifest is an accidental-change check, **not a cryptographic attestation against an attacker who can rewrite the files and manifest**. Use only locally generated training data in a trusted directory. It does not grant analyst identity assurance or production case authentication.

## Test and CI evidence

```bash
python -m unittest discover -s soc-demo/tests -v
```

CI independently executes these tests plus a CLI smoke test that explicitly simulates training approval. It checks three alerts, three unverified candidates, no case before approval, one case afterward, and confirms the case stays in the local database. **No live SIEM is contacted by the tests**.

## Return-to-Splunk checkpoint — finish when back at home PC

**Deferred by the owner on October 14, 2026 (currently at work).** The Splunk Enterprise/Cloud installation status is unknown. Before implementing **live** SIEM data ingestion:

1. At the owner's own Windows PC, check `Get-Service *Splunk*` in PowerShell. Confirm Splunk Enterprise is installed or decide whether to install it; if using Splunk Cloud, verify authorized access.
2. Configure a dedicated local lab index, HTTPS CA trust and a least-privileged read-only service token. **Never paste or commit credentials.**
3. Execute and validate the existing count-only opt-in HTTPS probe against authorized lab data; confirm actual Splunk REST API behavior and permissions.
4. Only after this, design a separately reviewed live event adapter with provenance checks and redaction. Keep case promotion manual.

**Checkpoint status: PENDING — no live Splunk endpoint or credentials verified.** Continue unrelated offline engineering while owner is at work; never imply a live connection exists.
