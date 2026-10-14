"""No-network Splunk connector safety and output tests."""
import importlib.util
import io
import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("splunk_probe", ROOT / "src" / "probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class MockOpener:
    def __init__(self, content):
        self.content = content
        self.request = None
        self.timeout = None
    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return io.BytesIO(self.content)


class ProbeTests(unittest.TestCase):
    def get(self, content=None, **kwargs):
        if content is None:
            content = b'{"preview":false,"result":{"sourcetype":"WinEventLog:Security","count":"3","_raw":"DO_NOT_EXPORT"}}\n'
        opener = MockOpener(content)
        result = probe.fetch_summary("https://127.0.0.1:8089", "soc_lab", "fake-local-secret",
                                     opener=opener, **kwargs)
        return result, opener

    def test_summary_is_count_only(self):
        result, opener = self.get()
        self.assertEqual(result["total_events"], 3)
        self.assertEqual(result["counts_by_sourcetype"], [{"sourcetype":"WinEventLog:Security","count":3}])
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(result))
        self.assertNotIn("fake-local-secret", json.dumps(result))
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer fake-local-secret")

    def test_query_is_fixed_read_only(self):
        _, opener = self.get(minutes=30)
        fields = parse_qs(opener.request.data.decode("ascii"))
        query = fields["search"][0]
        self.assertEqual(query, "search index=soc_lab earliest=-30m latest=now | stats count by sourcetype | sort - count | head 25")
        self.assertNotIn("_raw", query)
        self.assertEqual(fields["output_mode"], ["json"])
        self.assertEqual(opener.timeout, 15)

    def test_reject_insecure_endpoint(self):
        for endpoint in ("http://127.0.0.1:8089", "https://foo:pass@localhost:8089",
                         "https://localhost:8089/private", "https://localhost:8089/?x=1",
                         "https://localhost", "https://localhost:8089/#hash"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                probe.fetch_summary(endpoint, "soc_lab", "token", opener=MockOpener(b""))

    def test_reject_injected_index(self):
        for index in ("main | delete", "main\n| collect", "", "foo/bar"):
            with self.subTest(index=index), self.assertRaises(ValueError):
                probe.fetch_summary("https://localhost:8089", index, "token", opener=MockOpener(b""))

    def test_reject_bad_window(self):
        for minutes in (0, 1441, -1, True, 1.5):
            with self.subTest(minutes=minutes), self.assertRaises(ValueError):
                probe.fetch_summary("https://localhost:8089", "main", "token", minutes, opener=MockOpener(b""))

    def test_reject_bad_token(self):
        for token in ("", " ", "bad\r\ntoken"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                probe.fetch_summary("https://localhost:8089", "main", token, opener=MockOpener(b""))

    def test_reject_malformed_response(self):
        with self.assertRaises(ValueError):
            self.get(content=b'{broken\n')

    def test_reject_duplicate_source(self):
        frame = b'{"result":{"sourcetype":"sysmon","count":"1"}}\n'
        with self.assertRaises(ValueError):
            self.get(content=frame + frame)

    def test_reject_invalid_count(self):
        with self.assertRaises(ValueError):
            self.get(content=b'{"result":{"sourcetype":"sysmon","count":"10; DROP"}}\n')

    def test_response_size_limit(self):
        with self.assertRaises(ValueError):
            self.get(content=b"x" * (probe.MAX_RESPONSE_BYTES + 1))

    def test_allow_empty_results(self):
        result, _ = self.get(content=b"")
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["counts_by_sourcetype"], [])


if __name__ == "__main__":
    unittest.main()
