"""Local read-only SOC dashboard; synthetic JSON only, stdlib HTTP server."""
import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "fixtures" / "demo.json"
SEVERITIES = ("informational", "low", "medium", "high", "critical")
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

def display(key, value):
    """Text for one cell. Contract alerts carry source as an object, and candidates carry lists."""
    if value is None or value == "":
        return "—"
    if key == "source" and isinstance(value, dict):
        return str(value.get("system", "—"))
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)

def label(key):
    return key.replace("_", " ").title()

def cell(key, value):
    text = html.escape(display(key, value))
    # data-label comes from the fixed column name; the phone layout shows it beside the value
    attrs = f"data-label='{html.escape(label(key))}'"
    if key in ("severity", "highest_severity") and value in SEVERITIES:
        # The class comes from a fixed list, never from the data itself
        return f"<td {attrs}><span class='sev sev-{value}'>{text}</span></td>"
    return f"<td {attrs}>{text}</td>"

def render(data):
    if not isinstance(data, dict) or any(not isinstance(data.get(k), list) for k in ("alerts", "candidates", "cases")):
        raise ValueError("Expected lists: alerts, candidates, cases")
    def section(heading, records, columns):
        rows = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid row")
            cells = "".join(cell(key, record.get(key)) for key in columns)
            rows.append(f"<tr>{cells}</tr>")
        heads = "".join(f"<th scope='col'>{html.escape(label(key))}</th>" for key in columns)
        return f"<section><h2>{html.escape(heading)} ({len(records)})</h2><div class='scroll'><table><thead><tr>{heads}</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>"
    sections = [
        # Columns follow SOC Event Contract v1, the correlation report and the case database
        section("Alerts", data["alerts"], ("occurred_at", "severity", "title", "source", "actor", "asset", "rule_id", "event_id")),
        section("Unverified candidates", data["candidates"], ("candidate_id", "classification", "highest_severity", "actor", "asset", "event_count", "alert_ids")),
        section("Investigation cases", data["cases"], ("id", "title", "severity", "status")),
    ]
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Command Center | Demo</title><style>
body{margin:0;background:#0c1425;color:#eff6ff;font:16px system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:30px 20px}header{border-bottom:1px solid #283c54;padding-bottom:20px}
small{color:#9cb4d0}h1{font-size:2rem;margin:8px 0}h2{font-size:1.2rem}
.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:24px 0}
.metric,section{background:#14243b;border:1px solid #263c56;border-radius:12px;padding:20px}
.metric strong{display:block;font-size:2rem;color:#80caff}
section{margin:18px 0}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{padding:12px;border-bottom:1px solid #31445b;vertical-align:top}th{color:#9cb4d0;font-size:.8rem;text-transform:uppercase}
td{overflow-wrap:break-word}
.sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.85rem;border:1px solid}
.sev-informational,.sev-low{color:#9cb4d0;border-color:#4a6280}.sev-medium{color:#ffd479;border-color:#8a6d2b}
.sev-high{color:#ffad7a;border-color:#94532c}.sev-critical{color:#ff8a8a;border-color:#a33a3a;font-weight:600}
footer{color:#9cb4d0;padding:24px 0}
@media(max-width:580px){.metrics{grid-template-columns:1fr}main{padding:20px 12px}.metric,section{padding:14px}
thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
tr{display:block;border-bottom:1px solid #31445b;padding:8px 0}
td{display:grid;grid-template-columns:7.5em minmax(0,1fr);gap:8px;border:0;padding:4px 0;overflow-wrap:anywhere}
td::before{content:attr(data-label);color:#9cb4d0;font-size:.75rem;text-transform:uppercase;padding-top:2px}.sev{justify-self:start}}
</style><main><header><small>ATLAS / SOC LAB PORTFOLIO</small><h1>SOC Command Center</h1>
<p>Read-only synthetic training data. No live SIEM, detector or case connections.</p></header>
<div class="metrics">""" + "".join(
        f"<div class='metric'><small>{name}</small><strong>{len(data[key])}</strong></div>"
        for name, key in (("Alerts", "alerts"), ("Unverified candidates", "candidates"), ("Investigation cases", "cases"))
    ) + "</div>" + "".join(sections) + "<footer>Demo only · No write routes · Analyst validation required</footer></main></html>"

def make_server(page, host="127.0.0.1", port=8765):
    """port=0 picks a free port (used by the tests); allowed Host names follow the bound port."""
    server = ThreadingHTTPServer((host, port), None)
    bound = server.server_address[1]
    allowed_hosts = {f"127.0.0.1:{bound}", f"localhost:{bound}", f"[::1]:{bound}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SOC-Command-Center"
        sys_version = ""  # do not advertise the Python version

        def end_headers(self):
            # Applied to every response, including the default error pages
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            super().end_headers()

        def _page(self, include_body):
            # Refuse other Host names so a DNS-rebinding web page cannot read the dashboard
            if self.headers.get("Host", "") not in allowed_hosts:
                self.send_error(421, "Misdirected Request")
                return
            if urlsplit(self.path).path != "/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            if include_body:
                self.wfile.write(page)

        def do_GET(self):
            self._page(True)

        def do_HEAD(self):
            self._page(False)

        def do_POST(self):
            self.send_error(405)

        def log_message(self, format, *args):
            pass  # keep request lines (which echo client input) out of the terminal

    server.RequestHandlerClass = Handler
    return server

def serve(path, host="127.0.0.1", port=8765):
    # Fixed input is read at launch; do not serve arbitrary local filesystem paths.
    page = render(json.loads(Path(path).read_text(encoding="utf-8"))).encode("utf-8")
    with make_server(page, host, port) as server:
        print(f"Demo dashboard at http://{host}:{server.server_address[1]}")
        server.serve_forever()

def main():
    p = argparse.ArgumentParser(description="Local read-only synthetic SOC dashboard")
    p.add_argument("--data", type=Path, default=SAMPLE)
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    if not 1 <= args.port <= 65535:
        p.error("--port must be between 1 and 65535")
    try:
        serve(args.data, port=args.port)
    except (OSError, UnicodeDecodeError, ValueError) as exc:  # missing/bad data file, port in use
        p.error(str(exc))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
