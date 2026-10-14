# Phishing Email Analyzer

Offline email triage using parsed `From` and `Subject` headers, URLs and text from the plain-text and HTML body parts (including link targets), and simple evidence-based heuristics. No API key or URL browsing required.

## Run

From the repository root:

```bash
python phishing-email-analyzer/scripts/phishing_email_analyzer.py
python -m unittest discover -s tests -v
```

Custom input: `--input path/to/message.txt --output path/to/report.md`. [reports/phishing_detection_report.md](reports/phishing_detection_report.md) is the output of the default command against the synthetic sample. URLs in the report are defanged (`hxxp`, `[.]`) and header text is escaped so email content cannot add lines or links to it.

## Checks

- Unencrypted HTTP URLs.
- Urgent or verification language.
- Sender domain differing from URLs in the body (context needed: legitimate mail services also do this).

These are **heuristics, not confirmation of phishing**. Review authentication headers, domain context, and reputation through authorized tools before escalating. The tool does not follow links or upload email content. Synthetic email samples are used for demonstration.
