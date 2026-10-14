import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pipeline", ROOT / "src" / "ingest.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)
SAMPLE = json.loads((ROOT.parent / "soc-event-contract" / "examples" / "windows_alert.json").read_text(encoding="utf-8"))

class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path
    def test_accept_valid_json(self):
        result = pipeline.ingest([self.write("a.json", json.dumps(SAMPLE))])
        self.assertEqual(result["counts"], {"accepted": 1, "rejected": 0, "duplicates": 0})
    def test_deduplicate_same_source_rule(self):
        second = copy.deepcopy(SAMPLE)
        second["event_id"] = "win-lab-002"
        result = pipeline.ingest([self.write("a.jsonl", json.dumps(SAMPLE) + "\n" + json.dumps(second))])
        self.assertEqual(result["counts"], {"accepted": 1, "rejected": 0, "duplicates": 1})
        self.assertEqual(result["duplicates"][0]["line"], 2)
    def test_different_rule_kept(self):
        second = copy.deepcopy(SAMPLE)
        second["rule_id"] = "other.rule"
        second["event_id"] = "win-lab-003"
        result = pipeline.ingest([self.write("a.jsonl", json.dumps(SAMPLE) + "\n" + json.dumps(second))])
        self.assertEqual(result["counts"]["accepted"], 2)
    def test_reused_event_id_rejected(self):
        second = copy.deepcopy(SAMPLE)
        second["source"]["record_id"] = "synthetic-4688-002"
        result = pipeline.ingest([self.write("a.json", json.dumps(SAMPLE)), self.write("b.json", json.dumps(second))])
        self.assertEqual(result["counts"], {"accepted": 1, "rejected": 1, "duplicates": 0})
        self.assertIn("event_id", result["rejected"][0]["errors"][0])
    def test_reject_malformed_and_wrong_schema(self):
        bad = copy.deepcopy(SAMPLE)
        bad["severity"] = "urgent"
        result = pipeline.ingest([self.write("a.jsonl", "{broken\n" + json.dumps(bad))])
        self.assertEqual(result["counts"]["rejected"], 2)
    def test_reject_invalid_timestamp(self):
        bad = copy.deepcopy(SAMPLE)
        bad["occurred_at"] = "yesterday"
        self.assertEqual(pipeline.ingest([self.write("a.json", json.dumps(bad))])["counts"]["rejected"], 1)
    def test_missing_file_recorded(self):
        self.assertEqual(pipeline.ingest([self.root / "missing.json"])["counts"]["rejected"], 1)
    def test_no_sensitive_raw_error_dump(self):
        result = pipeline.ingest([self.write("bad.json", "{secret!")])
        self.assertNotIn("secret!", json.dumps(result))

if __name__ == "__main__":
    unittest.main()
