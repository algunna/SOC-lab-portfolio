\# Windows Sysmon AI Detection Lab



A Windows-based detection engineering project that uses Sysmon to identify suspicious PowerShell activity and generates analyst-ready incident reports using Python and the OpenAI API.



---



\## Overview



This lab simulates a common endpoint investigation workflow by collecting Sysmon telemetry, identifying suspicious PowerShell execution, and generating a structured incident report.



The project performs the following tasks:



\- Collects Windows endpoint telemetry with Sysmon

\- Detects suspicious PowerShell activity

\- Identifies encoded commands and execution policy bypass

\- Maps findings to MITRE ATT\&CK techniques

\- Generates investigation-ready incident reports using the OpenAI API

\- Exports the final report in Markdown format



---



\## Project Structure



```text

windows-sysmon-ai-detection/

├── logs/

│   └── sysmon.evtx

├── scripts/

│   └── sysmon\_ai\_detector.py

├── reports/

│   └── sysmon\_ai\_report.md

├── screenshots/

├── README.md

└── requirements.txt

