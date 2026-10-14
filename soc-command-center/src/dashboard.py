"""Local read-only SOC dashboard; synthetic JSON only, stdlib HTTP server."""
import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "fixtures" / "demo.json"

def render(data):
    if not isinstance(data, dict) or any(not isinstance(data.get(k), list) for k in ("alerts", "candidates", "cases")):
        raise ValueError("Expected lists: alerts, candidates, cases")
    def section(label, records, columns):
        rows = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid row")
            cells = "".join(f"<td>{html.escape(str(record.get(key, '')))}</td>" for key in columns)
            rows.append(f"<tr>{cells}</tr>")
        heads = "".join(f"<th>{html.escape(key.replace('_', ' ').title())}</th>" for key in columns)
        return f"<section><h2>{html.escape(label)} ({len(records)})</h2><div class='scroll'><table><thead><tr>{heads}</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>"
    sections = [
        section("Alerts", data["alerts"], ("event_id", "severity", "title", "source")),
        section("Unverified candidates", data["candidates"], ("candidate_id", "classification", "event_count")),
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
th,td{padding:12px;border-bottom:1px solid #31445b}th{color:#9cb4d0;font-size:.8rem;text-transform:uppercase}
footer{color:#9cb4d0;padding:24px 0}@media(max-width:580px){.metrics{grid-template-columns:1fr}}
</style><main><header><small>ATLAS / SOC LAB PORTFOLIO</small><h1>SOC Command Center</h1>
<p>Read-only synthetic training data. No live SIEM, detector or case connections.</p></header>
<div class="metrics">""" + "".join(
        f"<div class='metric'><small>{label}</small><strong>{len(data[key])}</strong></div>"
        for label, key in (("Alerts", "alerts"), ("Unverified candidates", "candidates"), ("Investigation cases", "cases"))
    ) + "</div>" + "".join(sections) + "<footer>Demo only · No write routes · Analyst validation required</footer></main></html>"

def serve(path, host="127.0.0.1", port=8765):
    # Fixed input is read at launch; do not serve arbitrary local filesystem paths.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    page = render(data).encode("utf-8")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)
        def do_POST(self):
            self.send_error(405)
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Demo dashboard at http://{host}:{port}")
        server.serve_forever()

def main():
    p = argparse.ArgumentParser(description="Local read-only synthetic SOC dashboard")
    p.add_argument("--data", type=Path, default=SAMPLE)
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    serve(args.data, port=args.port)

if __name__ == "__main__":
    main()
