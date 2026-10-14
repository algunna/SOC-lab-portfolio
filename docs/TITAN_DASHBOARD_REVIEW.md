# Titan Review — SOC Command Center v0.1 (PR #24)

**Reviewed:** `main` at `c232ae7` (PR #24 merged) · **Date:** 2026-10-14 · **Reviewer:** Titan (Claude)
**Fix branch:** `claude/titan-command-center-review` (separate PR, not merged; for ATLAS to verify)

All testing used synthetic data on Python 3.13.16 with headless Chromium. AETHERION was not touched.

## Summary

The dashboard is safe against HTML/script injection: every injected payload rendered as inert text, and the CSP blocks scripts. The main problems are that **its data model does not match the SOC event pipeline** (finding 1), and that **the server answers any `Host` name**, which lets a malicious web page read it through DNS rebinding (finding 2). Both are fixed on the fix branch, along with the phone layout and the smaller issues below.

| # | Finding | Severity | Status on fix branch |
| --- | --- | --- | --- |
| 1 | Fixture and columns do not follow SOC Event Contract v1; real alerts render a Python dict | High | Fixed |
| 2 | Any `Host` header accepted (DNS rebinding can read the dashboard) | Medium | Fixed |
| 3 | Phone layout hides most alert fields off-screen | Medium | Fixed |
| 4 | Error pages lack CSP/nosniff; no framing protection | Low | Fixed |
| 5 | Startup errors are raw tracebacks | Low | Fixed |
| 6 | `/?query` returns 404; `HEAD` returns 501 | Low | Fixed |
| 7 | Server header discloses the Python version; request lines logged with client input | Low | Fixed |
| 8 | No HTTP-level tests | Low | Fixed |
| 9 | Severity has no visual distinction | Low | Fixed |
| 10 | No loader from pipeline outputs; candidates lack triage fields on `main` | Medium | Open (proposal) |
| 11 | `docs/TITAN_SOC_HANDOFF.md` is out of date | Low | Fixed |

## Findings

### 1. Data model does not match the event pipeline — High

**Repro:** run the pipeline and render its output:
```bash
python soc-event-ingestion/src/ingest.py soc-event-contract/examples/windows_alert.json --out /tmp/ing.json
python soc-incident-correlation/src/correlate.py /tmp/ing.json --out /tmp/cand.json
# build {"alerts": ing["accepted"], "candidates": cand["incident_candidates"], "cases": [...]} and call render()
```
**Actual:** the Source column shows `{'system': 'windows', 'record_id': 'synthetic-4688-001'}`. The demo fixture's alerts fail `soc-event-contract` validation (`source` is a string; `schema_version`, `occurred_at`, `evidence` missing). The alert table has no time, actor, asset or rule column, so an analyst cannot triage from it.
**Fix:** contract-valid fixture (tested against the validator); `source.system` displayed; lists joined; columns `occurred_at, severity, title, source, actor, asset, rule_id, event_id` for alerts and `candidate_id, classification, highest_severity, actor, asset, event_count, alert_ids` for candidates; missing values shown as `—`.

### 2. DNS rebinding — Medium

**Repro:** `curl -H "Host: attacker.example:8765" http://127.0.0.1:8765/` → `200` with the full page.
**Impact:** binding to 127.0.0.1 does not stop a web page on a rebinding domain from reading the response in the analyst's browser. Low today (synthetic data), but it becomes a data leak once real detector output is shown.
**Fix:** only `127.0.0.1:<port>`, `localhost:<port>` and `[::1]:<port>` are served; anything else gets `421`.

### 3. Phone layout hides alert fields — Medium

**Repro:** open the page at 375 px with an alert whose ID or hostname is a long unbroken string.
**Actual:** the alerts table scrolls sideways inside its card with no cue; only the first column is visible, so Severity, Title and Source are off-screen. Even with the stock fixture, the cases Status column is clipped.
**Fix:** at ≤ 580 px each row becomes a labelled card (column name beside each value); long values wrap. Verified in Chromium at 375 px: page width stays 375 px with all fields visible.

### 4. Security headers missing on errors; no framing protection — Low

**Repro:** `curl -D - http://127.0.0.1:8765/x` → 404 without `Content-Security-Policy` or `X-Content-Type-Options`. No `frame-ancestors` or `X-Frame-Options`, so the page can be framed.
**Fix:** headers are added in `end_headers`, so every response (including errors) carries them; CSP gains `frame-ancestors 'none'`; `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` added.

### 5. Startup errors are tracebacks — Low

**Repro:** `--data` pointing to malformed JSON → `JSONDecodeError` traceback; port in use → `OSError` traceback; `--port 99999` → `OverflowError` traceback.
**Fix:** one-line usage errors (exit code 2); port range validated.

### 6. Query strings and HEAD — Low

**Repro:** `/?a=1` → 404; `curl -I /` → 501.
**Fix:** route on the path only; `HEAD` supported.

### 7. Information disclosure — Low

`Server: BaseHTTP/0.6 Python/3.13.16`, and the default request log prints client-supplied paths to the terminal. **Fix:** generic server name, request logging disabled.

### 8. No HTTP-level tests — Low

The 5 original tests covered `render()` only. **Fix:** 13 tests, including a real server on an ephemeral port: security headers on 200/404/405, Host check, query string, HEAD, contract-valid fixture, severity badges limited to known values. The new tests fail on the PR #24 code (3 failures, 1 error) and pass on the fix.

### 9. Severity has no visual distinction — Low

Severity was plain text. **Fix:** coloured badges for the five contract severities; the CSS class comes from a fixed list, never from data.

### 10. No loader from pipeline outputs — Medium (open)

The dashboard only reads a hand-built JSON file. Before detectors are connected, it needs a read-only builder that takes an ingestion report, a correlation report and the case SQLite database (opened read-only, e.g. `file:cases.db?mode=ro`) and produces the dashboard model. Candidate triage fields (`highest_severity`, `actor`, `asset`) come from correlation changes in PR #18, so those columns show `—` until it merges. **Proposal:** a separate `build_view.py` with its own tests; not implemented here, to keep this PR to fixes.

### 11. Handoff document out of date — Low

`docs/TITAN_SOC_HANDOFF.md` still labelled #22–#24 as pending, listed only #19–#20 under current state, omitted the promotion and dashboard labs from its scope, and asked whether promotion should be manual-only (decided in #23). **Fix:** updated, with a pointer to this review and to PR #18 for review items 2 and 3.

## Test results (fix branch)

| Check | Result |
| --- | --- |
| `python -m unittest discover -s soc-command-center/tests -v` | 13 passed |
| Same tests against PR #24 code | 3 failures, 1 error (confirms the tests catch the bugs) |
| All other test suites on the branch | Pass |
| Replay of every workflow's `run` steps (fresh temp dir per workflow) | 0 failures |
| Chromium, 1280 px and 375 px, stock fixture, hostile-data fixture, real pipeline output | No horizontal page overflow; no script, image or SVG element created; no dialogs |
| `curl` probes: foreign Host, 404 headers, bad startup input | 421; headers present; one-line errors |

## Not changed (needs a team decision)

- A real data loader (finding 10) and whether the dashboard should read the case DB directly.
- Authentication: none; acceptable only while the server is loopback-only and shows synthetic data.
- Actions are pinned by tag, not SHA (repository-wide).
