\# Phishing Email Analyzer



A Python-based email security project that analyzes suspicious emails, extracts malicious URLs, identifies social engineering indicators, and generates analyst-ready phishing investigation reports using the OpenAI API.



---



\## Overview



This lab simulates a common SOC workflow by analyzing suspicious emails and producing structured phishing investigation reports.



The project performs the following tasks:



\- Reads raw email content

\- Extracts URLs

\- Identifies common phishing indicators

\- Assigns a risk rating

\- Generates investigation-ready reports using the OpenAI API

\- Exports the final report in Markdown format



---



\## Project Structure



```text

phishing-email-analyzer/

├── emails/

│   └── sample\_phishing\_email.txt

├── scripts/

│   └── phishing\_email\_analyzer.py

├── reports/

│   └── phishing\_report.md

├── screenshots/

├── README.md

└── requirements.txt

