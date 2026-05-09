# AI SOC Copilot

A Python-based security automation project that analyzes SSH authentication logs, detects brute-force activity, maps findings to the MITRE ATT&CK framework, and uses the OpenAI API to generate analyst-ready incident reports.

---

## Overview

AI SOC Copilot simulates a lightweight Security Operations Center (SOC) workflow by transforming raw SSH authentication logs into structured incident response reports.

The script performs the following tasks:

- Reads SSH authentication logs
- Detects repeated failed login attempts
- Counts successful logins
- Extracts source IP addresses
- Assigns a severity level
- Maps findings to MITRE ATT&CK T1110 (Brute Force)
- Uses the OpenAI API to generate executive summaries, analyst notes, and recommended response actions
- Exports the final report in Markdown format

---

## Project Structure

```text
ai-soc-copilot/
├── logs/
│   └── sample_bruteforce.log
├── scripts/
│   └── soc_copilot.py
├── reports/
│   └── incident_report.md
├── prompts/
├── screenshots/
├── README.md
└── requirements.txt