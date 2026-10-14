# SOC Command Center — Read-Only Demo

A **local Python standard-library dashboard** displaying synthetic alerts, unverified incident candidates and investigation cases. This is a portfolio UI prototype, not a live SOC service.

## Run

```bash
python soc-command-center/src/dashboard.py
```

Then open http://127.0.0.1:8765/ in your browser. Stop with Ctrl+C.

## Scope and safeguards

- Fixed, synthetic JSON fixture loaded at startup. `--data` can point to another **trusted, sanitized** JSON fixture.
- All display fields are HTML-escaped. No JavaScript, frontend dependencies, write routes, background agents, or remote APIs.
- Bound to loopback (127.0.0.1) by default, with a restrictive Content Security Policy.
- GET / renders dashboard; other paths return 404; POST returns 405.
- Counts show demonstration fixture values, **not actual incidents, telemetry or response performance**.
- Do not expose this dev server to the Internet, use real sensitive data, or treat it as an authenticated production service.
- Source detector and case-manager integrations remain intentionally disabled while the Titans review them.

## Tests

```bash
python -m unittest discover -s soc-command-center/tests -v
```
