\# AI SOC Copilot



A Python-based security automation project that analyzes SSH authentication logs, detects brute-force activity, maps findings to the MITRE ATT\&CK framework, and generates analyst-ready incident reports in Markdown.



---



\## Overview



AI SOC Copilot simulates a lightweight Security Operations Center (SOC) workflow by converting raw authentication logs into structured incident reports.



The script performs the following tasks:



\- Reads SSH authentication logs

\- Detects repeated failed login attempts

\- Counts successful logins

\- Extracts source IP addresses

\- Assigns a severity level

\- Maps findings to MITRE ATT\&CK T1110 (Brute Force)

\- Generates a professional incident report



---



\## Project Structure



```text

ai-soc-copilot/

├── logs/

│   └── sample\_bruteforce.log

├── scripts/

│   └── soc\_copilot.py

├── reports/

│   └── incident\_report.md

├── prompts/

├── screenshots/

├── README.md

└── requirements.txt

