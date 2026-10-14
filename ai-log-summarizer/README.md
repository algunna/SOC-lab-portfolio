# AI Log Summarizer

A Python training lab for reviewing security logs and preparing analyst-friendly summaries. It is a demonstration project, not a production SOC platform.

## Purpose

Practice ingesting example logs, reviewing suspicious events, and drafting investigation notes. See the nested project directory for the available Python script and sample outputs.

## Run locally

1. Review the source code and dependencies before running it.
2. Create a local environment file or set environment variables for any API credentials the script requires.
3. Run the script against **synthetic or authorized** logs only.
4. Validate AI-generated statements against the original events.

## Important security limitations

- Do not submit real credentials, patient information, employee data, or other confidential logs to an external AI provider.
- **Automatic redaction is not verified in this lab.** Review and sanitize all input yourself before transmitting it.
- No production-grade encryption, security controls, detection accuracy, or incident response automation is claimed.
- Keep secrets in local environment variables, never in Git. The repository now ignores `.env` files; historically committed credentials still require revocation because they remain in Git history.
- Outputs produced by language models may contain inaccurate or unsupported conclusions.

## Evidence

The repository includes sample log files and example output. Treat these as demonstrations rather than independently validated SOC alerts.
