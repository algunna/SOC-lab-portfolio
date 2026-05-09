\# Threat Intelligence Enrichment Lab



A Python-based threat intelligence project that enriches IP addresses, domains, and file hashes and generates analyst-ready investigation reports using the OpenAI API.



---



\## Overview



This lab simulates a common SOC workflow by analyzing indicators of compromise (IOCs) and generating structured threat intelligence reports.



The project performs the following tasks:



\- Reads a list of IP addresses, domains, and file hashes

\- Classifies each IOC by type

\- Assigns reputation and risk levels

\- Generates investigation-ready reports using the OpenAI API

\- Exports the final report in Markdown format



---



\## Project Structure



```text

threat-intel-enrichment-lab/

├── iocs/

│   └── sample\_iocs.txt

├── scripts/

│   └── threat\_intel\_enrichment.py

├── reports/

│   └── threat\_intel\_report.md

├── screenshots/

├── README.md

└── requirements.txt

