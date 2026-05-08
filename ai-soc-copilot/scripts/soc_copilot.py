import os
from pathlib import Path
from datetime import datetime
from openai import OpenAI

LOG_FILE = Path("../logs/sample_bruteforce.log")
REPORT_FILE = Path("../reports/incident_report.md")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def read_log(file_path):
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    return file_path.read_text(encoding="utf-8")


def analyze_log(log_data):
    failed_attempts = log_data.count("Failed password")
    successful_logins = log_data.count("Accepted password")

    source_ips = []
    for line in log_data.splitlines():
        if "from " in line:
            ip = line.split("from ")[1].split(" ")[0]
            source_ips.append(ip)

    unique_ips = sorted(set(source_ips))

    severity = "Low"
    if failed_attempts >= 3:
        severity = "Medium"
    if failed_attempts >= 5:
        severity = "High"

    return {
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "unique_ips": unique_ips,
        "severity": severity,
    }


def generate_ai_analysis(results, log_data):
    prompt = f"""
You are acting as a SOC analyst. Analyze the following SSH authentication log and create a concise incident response analysis.

Findings:
Failed login attempts: {results["failed_attempts"]}
Successful logins: {results["successful_logins"]}
Source IPs: {", ".join(results["unique_ips"])}
Severity: {results["severity"]}

Raw log:
{log_data}

Return the response in this format:

Executive Summary:
Analyst Notes:
Recommended Response:
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity SOC analyst. Keep the response clear, professional, and practical.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    return response.choices[0].message.content


def write_report(results, log_data, ai_analysis):
    report = f"""# AI SOC Copilot Incident Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Key Findings

- Failed login attempts: {results["failed_attempts"]}
- Successful logins: {results["successful_logins"]}
- Source IPs observed: {", ".join(results["unique_ips"])}
- Severity: {results["severity"]}

## MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## AI-Generated SOC Analysis

{ai_analysis}

## Raw Log Sample

{log_data}
"""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"AI-powered report created: {REPORT_FILE}")


def main():
    log_data = read_log(LOG_FILE)
    results = analyze_log(log_data)
    ai_analysis = generate_ai_analysis(results, log_data)
    write_report(results, log_data, ai_analysis)


if __name__ == "__main__":
    main()