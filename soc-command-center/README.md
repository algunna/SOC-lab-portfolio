# SOC Command Center — Read-Only Demo

A **local Python standard-library dashboard** displaying synthetic alerts, unverified incident candidates and investigation cases. This is a portfolio UI prototype, not a live SOC service.

## Run

```bash
python soc-command-center/src/dashboard.py
```

Then open http://127.0.0.1:8765/ in your browser. Stop with Ctrl+C.

## Scope and safeguards

- Fixed, synthetic JSON fixture loaded at startup. `--data` can point to another **trusted, sanitized** JSON fixture.
- Data model: `alerts` follow [SOC Event Contract v1](../soc-event-contract) (the fixture is checked against it in the tests); `candidates` follow the [correlation](../soc-incident-correlation) report; `cases` follow the [case lab](../soc-incident-case-lab) database. Missing values show as `—`.
- On screens up to 580 px wide, each table row is shown as a labelled card so no field is hidden off-screen.
- All display fields are HTML-escaped. No JavaScript, frontend dependencies, write routes, background agents, or remote APIs.
- Bound to loopback (127.0.0.1), and only requests addressed to `127.0.0.1`, `localhost` or `[::1]` on the dashboard port are answered (others get 421), so a DNS-rebinding web page cannot read it.
- Every response, including error pages, carries a restrictive Content Security Policy (with `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff` and `no-referrer`.
- GET or HEAD `/` (query strings ignored) renders the dashboard; other paths return 404; POST returns 405.
- Counts show demonstration fixture values, **not actual incidents, telemetry or response performance**.
- Do not expose this dev server to the Internet, use real sensitive data, or treat it as an authenticated production service.
- Source detector and case-manager integrations remain intentionally disabled while the Titans review them.

## Tests

```bash
python -m unittest discover -s soc-command-center/tests -v
```

The tests start a real server on a free port and need `jsonschema` (`python -m pip install -r soc-event-contract/requirements.txt`). Review findings: [docs/TITAN_DASHBOARD_REVIEW.md](../docs/TITAN_DASHBOARD_REVIEW.md).
