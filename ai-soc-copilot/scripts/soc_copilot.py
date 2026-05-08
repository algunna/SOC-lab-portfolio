from pathlib import Path
from datetime import datetime

LOG_FILE = Path("../logs/sample_bruteforce.log")
REPORT_FILE = Path("../reports/incident_report.md")


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


def write_report(results, log_data):
    report = f"""# AI SOC Copilot Incident Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

Possible SSH brute-force activity was detected based on repeated failed login attempts.

## Key Findings

- Failed login attempts: {results["failed_attempts"]}
- Successful logins: {results["successful_logins"]}
- Source IPs observed: {", ".join(results["unique_ips"])}
- Severity: {results["severity"]}

## MITRE ATT&CK Mapping

- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## Analyst Notes

The log shows multiple failed SSH login attempts against different usernames. A successful login was also observed from a separate internal IP address.

## Recommended Response

1. Review SSH access logs for additional activity.
2. Confirm whether the successful login was expected.
3. Block or investigate suspicious source IPs.
4. Enforce strong passwords and consider disabling root SSH login.
5. Enable MFA where possible.

## Raw Log Sample

{log_data}
"""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Report created: {REPORT_FILE}")


def main():
    log_data = read_log(LOG_FILE)
    results = analyze_log(log_data)
    write_report(results, log_data)


if __name__ == "__main__":
    main()