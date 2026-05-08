import os
from dotenv import load_dotenv
from openai import OpenAI

# Load environment variables
load_dotenv()

# Initialize OpenAI client (uses key from .env automatically)
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    project=os.getenv("OPENAI_PROJECT_ID")
)
LOG_FOLDER = "logs"
OUTPUT_FILE = "output/summary_report.txt"

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

