import os
from pathlib import Path
from datetime import datetime
from openai import OpenAI

IOC_FILE = Path("../iocs/sample_iocs.txt")
REPORT_FILE = Path("../reports/threat_intel_report.md")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def load_iocs():
    return [
        line.strip()
        for line in IOC_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def enrich_ioc(ioc):
    if ioc == "8.8.8.8":
        return {"ioc": ioc, "type": "IP Address", "reputation": "Benign", "risk": "Low"}
    elif ioc == "1.1.1.1":
        return {"ioc": ioc, "type": "IP Address", "reputation": "Benign", "risk": "Low"}
    elif "." in ioc and len(ioc) < 40:
        return {"ioc": ioc, "type": "Domain", "reputation": "Unknown", "risk": "Medium"}
    else:
        return {"ioc": ioc, "type": "File Hash", "reputation": "Suspicious", "risk": "High"}


def generate_ai_analysis(results):
    prompt = "Analyze the following threat intelligence findings:\n\n"

    for result in results:
        prompt += (
            f"IOC: {result['ioc']}\n"
            f"Type: {result['type']}\n"
            f"Reputation: {result['reputation']}\n"
            f"Risk: {result['risk']}\n\n"
        )

    prompt += """
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
                "content": "You are a cybersecurity threat intelligence analyst.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    return response.choices[0].message.content


def write_report(results, ai_analysis):
    report = f"""# Threat Intelligence Enrichment Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## IOC Findings

"""

    for result in results:
        report += f"""### {result['ioc']}

- Type: {result['type']}
- Reputation: {result['reputation']}
- Risk: {result['risk']}

"""

    report += f"""## AI-Generated Analysis

{ai_analysis}
"""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Report created: {REPORT_FILE}")


def main():
    iocs = load_iocs()
    results = [enrich_ioc(ioc) for ioc in iocs]
    ai_analysis = generate_ai_analysis(results)
    write_report(results, ai_analysis)


if __name__ == "__main__":
    main()