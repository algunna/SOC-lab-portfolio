AI Log Summarizer

Overview  
This project analyzes system and application logs and produces structured, human readable summaries to support security operations and incident review. The tool is designed to mirror how a SOC analyst reviews raw logs, identifies notable events, and assesses potential security concerns.

The project focuses on automation, clarity, and secure handling of log data rather than alert generation alone.

Features  
The tool processes log files and generates summaries highlighting key events, suspicious activity, severity levels, and recommended actions.  
It supports both structured and unstructured log formats.  
It can operate using either a locally hosted language model or an external API depending on configuration.

Tools and Technologies  
Python is used for log ingestion, preprocessing, and automation.  
The OpenAI API or a local LLM may be used for summarization.  
Example logs include Windows Event Logs, Sysmon output, and Apache access logs.

How to Use  
Place log files in the logs directory.  
Execute the summarization script from the project root.  
Review the generated report in the output directory.

Security Considerations  
This project includes defensive controls designed to reduce the risk of exposing sensitive information during log analysis and external processing.

Sensitive Data Redaction  
Log content is sanitized before analysis. IP addresses, email addresses, and user identifiers are removed using pattern based detection to prevent unintended disclosure.

Credential Handling  
API credentials are stored locally using environment variables and are excluded from version control. When credential exposure occurred during development, the affected key was revoked and rotated, and repository protections were enforced.

External Processing Safety  
Only redacted log data is transmitted to external services. This limits the exposure of operational or user related information outside the environment.

Secure Development Practices  
The project follows controlled Git workflows including branch isolation, clean history management, and explicit remediation of detected secrets. These practices align with standard SOC and application security procedures.

