"""Read-only local dashboard for sanitized offline SOC health report summaries.

Only validated health.json counters and allowlisted status/stage values are used.
Never reads ingestion.json, quarantine.json, case notes or real event data.
"""
import argparse
import html
import importlib.util
import json
import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = Path(__file__).resolve().parent / "dashboard.py"
MAX_RUNS = 30
MAX_HEALTH_BYTES = 4096
MAX_COUNTER = 10_000_000
COUNTS = ("accepted", "rejected", "duplicates", "candidates")
STAGES = {"preflight", "ingestion", "correlation", "complete"}
STATUS = {"passed", "blocked"}


def object_without_duplicate_keys(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("Duplicate field in health report")
        value[name] = item
    return value


def invalid_constant(value):
    raise ValueError("Non-finite JSON number rejected")


def validate_health(record):
    if (not isinstance(record, dict) or
        set(record) != {"version", "mode", "status", "stage", "counts"} or
        record["version"] != "0.1" or record["mode"] != "offline_training" or
        type(record["status"]) is not str or record["status"] not in STATUS or
        type(record["stage"]) is not str or record["stage"] not in STAGES or
        (record["status"] == "passed") != (record["stage"] == "complete")):
        raise ValueError("Invalid or inconsistent offline health report")
    counts = record["counts"]
    if (not isinstance(counts, dict) or set(counts) != set(COUNTS) or
        any(type(counts[key]) is not int or not 0 <= counts[key] <= MAX_COUNTER for key in COUNTS)):
        raise ValueError("Invalid health counters")
    if record["status"] == "blocked" and counts["candidates"] != 0:
        raise ValueError("Blocked batches cannot have published candidates")
    if record["status"] == "passed" and counts["rejected"]:
        raise ValueError("Passed batch cannot have rejected records")
    if counts["candidates"] > counts["accepted"]:
        raise ValueError("Candidate count exceeds accepted records")
    return {"status": record["status"], "stage": record["stage"],
            "counts": {key: counts[key] for key in COUNTS}}


def load_reports(directories):
    if not 1 <= len(directories) <= MAX_RUNS:
        raise ValueError("Supply between 1 and 30 existing batch directories")
    seen = set()
    results = []
    for i, directory in enumerate(directories, 1):
        directory = Path(directory)
        # Reject aliases and symlinked parent paths. We never enumerate sibling files.
        if directory.is_symlink():
            raise ValueError("Symlink directory rejected")
        filename = directory / "health.json"
        if filename.is_symlink():
            raise ValueError("Symlink health report rejected")
        if not directory.is_dir():
            raise ValueError("Batch directory does not exist")
        canonical = directory.resolve(strict=True)
        if canonical in seen:
            raise ValueError("Batch directory repeated")
        seen.add(canonical)
        try:
            with filename.open("rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HEALTH_BYTES:
                    raise ValueError("Health report must be a bounded regular file")
                raw = handle.read(MAX_HEALTH_BYTES + 1)
            if len(raw) > MAX_HEALTH_BYTES:
                raise ValueError("Health report too large")
            record = json.loads(raw.decode("utf-8"),
                                object_pairs_hook=object_without_duplicate_keys,
                                parse_constant=invalid_constant)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Health report unavailable or malformed") from exc
        result = validate_health(record)
        result["run"] = i
        results.append(result)
    return results


def summarize(reports):
    counts = {key: 0 for key in COUNTS}
    for record in reports:
        for key in COUNTS:
            counts[key] += record["counts"][key]
    return {"runs": len(reports),
            "passed": sum(row["status"] == "passed" for row in reports),
            "blocked": sum(row["status"] == "blocked" for row in reports),
            "counts": counts}


def render(reports):
    summary = summarize(reports)
    def cell(value):
        # Values are validated constants or ints; HTML escaping stays defensive.
        return "<td>" + html.escape(str(value), quote=True) + "</td>"
    rows = []
    for record in reports:
        values = [record["run"], record["status"], record["stage"]]
        values += [record["counts"][key] for key in COUNTS]
        rows.append("<tr>" + "".join(cell(value) for value in values) + "</tr>")
    headings = ("Run", "Status", "Stage", "Accepted", "Rejected", "Duplicates", "Candidates")
    head = "".join("<th scope='col'>" + html.escape(name) + "</th>" for name in headings)
    metric = "".join("<li><strong>" + str(value) + "</strong><span>" + html.escape(name) + "</span></li>"
                     for name, value in (("Runs", summary["runs"]), ("Passed", summary["passed"]),
                                         ("Blocked", summary["blocked"]),
                                         ("Accepted", summary["counts"]["accepted"]),
                                         ("Rejected", summary["counts"]["rejected"]),
                                         ("Duplicates", summary["counts"]["duplicates"]),
                                         ("Candidates", summary["counts"]["candidates"])))
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Batch Health | Offline Training</title>
<style>
body{font:16px system-ui,sans-serif;background:#101927;color:#f0f5fb;margin:0}
main{max-width:1050px;padding:24px;margin:auto}
small,p{color:#b3c6dc}
h1{font-size:1.8rem}
ul{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;list-style:none;padding:0}
li,section{background:#1c2d43;padding:18px;border-radius:12px}
li strong{display:block;font-size:1.7rem}li span{color:#b3c6dc}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;text-align:left}
th,td{padding:12px;border-bottom:1px solid #41516a;white-space:nowrap}
th{color:#b3c6dc;font-size:.85rem}
footer{margin:22px 0;color:#b3c6dc}
</style>
<main><header><small>ATLAS / SOC LAB PORTFOLIO</small><h1>Offline Batch Health</h1>
<p>Sanitized counts only. No live SIEM connection, raw events, filenames, case data, or automatic retries.</p>
</header><ul>""" + metric + """</ul>
<section><h2>Batch History (supplied order)</h2>
<div class="scroll"><table><thead><tr>""" + head + "</tr></thead><tbody>" + "".join(rows) + """</tbody></table></div>
<p>Each run is independent. A later successful run does not establish recovery from an earlier failure.</p>
</section><footer>Static snapshot · Read-only · Synthetic training data</footer></main></html>"""


def main():
    parser = argparse.ArgumentParser(description="Local read-only SOC batch-health observability")
    parser.add_argument("--runs", nargs="+", required=True, type=Path,
                        help="Explicit, ordered offline batch directories containing health.json")
    parser.add_argument("--port", type=int, default=8766, help="Loopback port for a static snapshot")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    try:
        reports = load_reports(args.runs)
        page = render(reports).encode("utf-8")
        spec = importlib.util.spec_from_file_location("soc_health_server", DASHBOARD)
        dashboard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dashboard)
        with dashboard.make_server(page, port=args.port) as server:
            print("Offline batch health dashboard at http://127.0.0.1:{}".format(server.server_address[1]))
            server.serve_forever()
    except (OSError, ValueError) as exc:
        # Error text deliberately omits untrusted input paths and report bodies.
        parser.error("Could not render offline health reports (" + type(exc).__name__ + ")")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
