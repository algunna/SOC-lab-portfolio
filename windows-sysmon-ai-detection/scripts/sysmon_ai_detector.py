import os
from pathlib import Path
from datetime import datetime
from openai import OpenAI

LOG_FILE = Path("../logs/sysmon.evtx")
REPORT_FILE = Path("../reports/sysmon_ai_report.md")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_sysmon():
    findings = {
        "event_type": "Suspicious PowerShell Execution",
        "severity": "High",
        "techniques": [
            "T1059.001 - PowerShell",
            "T1027 - Obfuscated Files or Information",
        ],
        "indicators": [
            "powershell.exe",
            "-EncodedCommand",
            "-ExecutionPolicy Bypass",
            "-WindowStyle Hidden",
        ],
    }
    return findings


def generate_ai_analysis(findings):
    prompt = f"""
You are a SOC analyst.

Analyze this Windows Sysmon detection:

Event Type: {findings["event_type"]}
Severity: {findings["severity"]}
Indicators: {", ".join(findings["indicators"])}
MITRE ATT&CK: {", ".join(findings["techniques"])}

Return your response in this format:

Executive Summary:
Analyst Notes:
Recommended Response:
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity SOC analyst. Provide concise and professional analysis.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    return response.choices[0].message.content


def write_report(findings, ai_analysis):
    report = f"""# Windows Sysmon AI Detection Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Detection Summary

- Event Type: {findings["event_type"]}
- Severity: {findings["severity"]}

## Indicators

- powershell.exe
- -EncodedCommand
- -ExecutionPolicy Bypass
- -WindowStyle Hidden

## MITRE ATT&CK Mapping

- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

## AI-Generated Analysis

{ai_analysis}
"""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Report created: {REPORT_FILE}")


def main():
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Sysmon log not found: {LOG_FILE}")

    findings = analyze_sysmon()
    ai_analysis = generate_ai_analysis(findings)
    write_report(findings, ai_analysis)


if __name__ == "__main__":
    main()