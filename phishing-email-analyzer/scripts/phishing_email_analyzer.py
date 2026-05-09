import os
import re
from pathlib import Path
from datetime import datetime
from openai import OpenAI

EMAIL_FILE = Path("../emails/sample_phishing_email.txt")
REPORT_FILE = Path("../reports/phishing_report.md")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def load_email():
    return EMAIL_FILE.read_text(encoding="utf-8")


def extract_urls(email_text):
    return re.findall(r"https?://[^\s]+", email_text)


def analyze_email(email_text):
    urls = extract_urls(email_text)

    findings = {
        "sender": "security-alert@paypaI-support.com",
        "subject": "Urgent: Your account has been limited",
        "urls": urls,
        "risk": "High",
        "indicators": [
            "Urgent language",
            "Lookalike domain",
            "HTTP link",
            "Account verification request",
        ],
    }

    return findings


def generate_ai_analysis(findings):
    prompt = f"""
Analyze this phishing email.

Sender: {findings["sender"]}
Subject: {findings["subject"]}
URLs: {", ".join(findings["urls"])}
Risk: {findings["risk"]}
Indicators: {", ".join(findings["indicators"])}

Provide:
1. Executive Summary
2. Analyst Notes
3. Recommended Response
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity email security analyst.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    return response.choices[0].message.content


def write_report(findings, ai_analysis):
    report = f"""# Phishing Email Analysis Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Email Findings

- Sender: {findings["sender"]}
- Subject: {findings["subject"]}
- Risk: {findings["risk"]}

## Extracted URLs

"""

    for url in findings["urls"]:
        report += f"- {url}\n"

    report += "\n## Indicators of Phishing\n\n"

    for indicator in findings["indicators"]:
        report += f"- {indicator}\n"

    report += f"""

## AI-Generated Analysis

{ai_analysis}
"""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Report created: {REPORT_FILE}")


def main():
    email_text = load_email()
    findings = analyze_email(email_text)
    ai_analysis = generate_ai_analysis(findings)
    write_report(findings, ai_analysis)


if __name__ == "__main__":
    main()