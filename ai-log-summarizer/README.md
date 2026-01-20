# 🤖 AI Log Summarizer

## 📌 Overview
This tool uses an AI language model (LLM) to analyze system logs and produce human-readable summaries. It's built to simulate how a junior SOC analyst might review logs and report anomalies — automated with intelligence.

## ⚙️ Features
- Summarizes logs using GPT (or other LLMs)
- Supports JSON or plain text log files
- Returns summaries with severity levels
- Works offline (with a local LLM) or online (via OpenAI API)

## 🛠️ Tools & Technologies
- Python 3.x
- OpenAI API (or Ollama, local LLMs)
- Windows Event Logs / Sysmon / Apache Logs

## 🚀 How to Use

1. Drop your log files in the `/logs` folder  
2. Run the summarizer script:  
