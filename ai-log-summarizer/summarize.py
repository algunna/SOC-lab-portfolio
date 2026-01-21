import os
import re
from dotenv import load_dotenv
from openai import OpenAI


# Load environment variables
load_dotenv()

# Initialize OpenAI client (uses key from .env automatically)
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
)
LOG_FOLDER = "logs"
OUTPUT_FILE = "output/summary_report.txt"
def redact_sensitive_data(log_text: str) -> str:
    # Redact IPv4 addresses
    log_text = re.sub(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        '[REDACTED_IP]',
        log_text
    )

    # Redact email addresses
    log_text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        '[REDACTED_EMAIL]',
        log_text
    )

    # Redact usernames (common patterns)
    log_text = re.sub(
        r'(user(name)?=)[^\s]+',
        r'\1[REDACTED_USER]',
        log_text,
        flags=re.IGNORECASE
    )

    return log_text

def read_logs(folder):
    logs = ""
    for filename in os.listdir(folder):
        path = os.path.join(folder, filename)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                logs += f"\n--- {filename} ---\n"
                logs += f.read()
    return logs

def summarize_logs(log_text):
    prompt = f"""
You are a SOC analyst assistant.
Analyze the following logs and return:
- Key events
- Suspicious activity
- Severity (Low / Medium / High)
- Suggested actions

Logs:
{log_text}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity SOC analyst."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content

def main():
    print("🔍 Reading logs...")
    logs = read_logs(LOG_FOLDER)
    logs = redact_sensitive_data(logs)

    if not logs.strip():
        print("⚠️ No logs found.")
        return

    print("🤖 Sending logs to GPT...")
    summary = summarize_logs(logs)

    print("💾 Saving summary...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(summary)

    print(f"✅ Summary saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

