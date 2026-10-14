"""Opt-in, read-only Splunk REST search summary. Never export raw events."""
import argparse
import json
import os
import re
import ssl
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 256_000
MAX_BUCKETS = 25
INDEX = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
COUNT = re.compile(r"[0-9]{1,18}\Z")


class NoRedirect(HTTPRedirectHandler):
    """Do not forward Authorization headers to redirected hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(endpoint):
    if not isinstance(endpoint, str) or not endpoint or endpoint.strip() != endpoint:
        raise ValueError("Invalid Splunk endpoint")
    if any(ord(c) < 33 or ord(c) == 127 for c in endpoint):
        raise ValueError("Invalid endpoint control character")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.query or parsed.fragment or parsed.path not in ("", "/")
        or parsed.port is None
    ):
        raise ValueError("Endpoint must be an explicit HTTPS origin with port, no credentials or path")
    return endpoint.rstrip("/") + "/services/search/jobs/export"


def fetch_summary(endpoint, index, token, minutes=15, *, opener=None):
    """Return bounded source counts only. opener may be injected by unit tests."""
    url = validate_endpoint(endpoint)
    if not isinstance(index, str) or not INDEX.fullmatch(index):
        raise ValueError("Index must contain only letters, numbers, underscore or hyphen")
    if type(minutes) is not int or not 1 <= minutes <= 1440:
        raise ValueError("Time window must be an integer from 1 to 1440 minutes")
    if not isinstance(token, str) or not token.strip() or "\r" in token or "\n" in token:
        raise ValueError("Splunk token missing or malformed")
    # Fixed SPL pipeline: search + stats + sort + head. No arbitrary SPL or event payload export.
    query = f"search index={index} earliest=-{minutes}m latest=now | stats count by sourcetype | sort - count | head {MAX_BUCKETS}"
    request = Request(
        url,
        data=urlencode({"search": query, "output_mode": "json"}).encode("ascii"),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
        method="POST",
    )
    if opener is None:
        opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(request, timeout=15) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Splunk response exceeds safe size limit")
    buckets = []
    seen = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            frame = json.loads(line)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid Splunk JSONL response") from exc
        if not isinstance(frame, dict):
            raise ValueError("Invalid Splunk frame")
        result = frame.get("result")
        if result is None:
            continue
        if not isinstance(result, dict):
            raise ValueError("Invalid Splunk result row")
        source = result.get("sourcetype")
        count = result.get("count")
        if not isinstance(source, str) or not 1 <= len(source) <= 128 or any(ord(c) < 32 for c in source):
            raise ValueError("Invalid sourcetype")
        if not COUNT.fullmatch(str(count)):
            raise ValueError("Invalid event count")
        if source in seen or len(buckets) >= MAX_BUCKETS:
            raise ValueError("Duplicate or excess sourcetype")
        seen.add(source)
        buckets.append({"sourcetype": source, "count": int(count)})
    return {"version": "0.1", "source": "splunk_search_summary",
            "index": index, "window_minutes": minutes, "counts_by_sourcetype": buckets,
            "total_events": sum(row["count"] for row in buckets)}


def main():
    p = argparse.ArgumentParser(description="Opt-in read-only Splunk event-count summary")
    p.add_argument("--endpoint", required=True, help="HTTPS Splunk management origin, e.g. https://127.0.0.1:8089")
    p.add_argument("--index", required=True, help="Authorized index, e.g. soc_lab")
    p.add_argument("--minutes", type=int, default=15)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    if args.out.exists():
        p.error("Refusing to overwrite an existing output")
    token = os.environ.get("SOC_SPLUNK_TOKEN")
    if not token:
        p.error("Set SOC_SPLUNK_TOKEN in your environment (never commit the token)")
    try:
        report = fetch_summary(args.endpoint, args.index, token, args.minutes)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
    except (OSError, ValueError, URLError, ssl.SSLError) as exc:
        # Don't expose request/response bodies, token or untrusted server text in errors.
        p.error(f"Splunk query unsuccessful ({type(exc).__name__}); check HTTPS trust, permission, endpoint and index")
    print(f"Read-only summary written; event count: {report['total_events']}")


if __name__ == "__main__":
    main()
