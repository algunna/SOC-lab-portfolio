"""Acceptance checklist cannot promote synthetic claims to verified readiness."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / 'splunk-readonly-connector/src/acceptance_plan.py'
spec = importlib.util.spec_from_file_location('acceptance_tests', MODULE)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class AcceptancePlanTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(plan.TEMPLATE.read_text())

    def evaluate(self):
        return plan.evaluate(json.dumps(self.data).encode())

    def record(self, gate):
        self.data['gates'][gate] = {'status':'recorded', 'evidence':[
            {'kind':'operator_review' if gate in plan.REVIEW_GATES else 'authorized_live_lab',
             'sha256':'a'*64}]}

    def test_template_all_pending_and_never_verified(self):
        report = self.evaluate()
        self.assertEqual(report['pending_gates'], list(plan.GATES))
        self.assertEqual(report['recorded_gates'], [])
        self.assertFalse(report['live_splunk_verified'])
        self.assertFalse(report['collector_enablement_authorized'])

    def test_all_recorded_still_requires_manual_verification(self):
        for gate in plan.GATES:
            self.record(gate)
        report = self.evaluate()
        self.assertEqual(report['status'], 'claims_complete_manual_review_required')
        self.assertFalse(report['evidence_contents_verified'])
        self.assertFalse(report['live_splunk_verified'])
        self.assertFalse(report['collector_enablement_authorized'])

    def test_prerequisite_cannot_be_skipped(self):
        self.record('command_center')
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_blocked_gate_reported(self):
        self.data['gates']['authorized_lab']['status'] = 'blocked'
        report = self.evaluate()
        self.assertEqual(report['blocked_gates'], ['authorized_lab'])
        self.assertEqual(report['next_gate'], 'authorized_lab')

    def test_synthetic_evidence_refused(self):
        for gate in plan.GATES:
            self.record(gate)
        for kind in ('synthetic', 'ci', 'offline_training', 'synthetic_offline_only'):
            self.data['gates']['count_only_probe']['evidence'][0]['kind'] = kind
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.evaluate()

    def test_wrong_review_evidence_kind_refused(self):
        self.record('authorized_lab')
        self.data['gates']['authorized_lab']['evidence'][0]['kind'] = 'authorized_live_lab'
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_missing_unknown_gates_refused(self):
        for mode in ('missing', 'extra'):
            data = copy.deepcopy(self.data)
            if mode == 'missing':
                del data['gates']['collector_authentication']
            else:
                data['gates']['synthetic_ci'] = {'status':'recorded','evidence':[]}
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                plan.evaluate(json.dumps(data).encode())

    def test_secret_or_enablement_claim_fields_refused(self):
        for key in ('token', 'Authorization', 'live_splunk_verified', 'enable_collector'):
            data = dict(self.data, **{key: 'SECRET-CANARY'})
            with self.subTest(key=key), self.assertRaises(ValueError):
                plan.evaluate(json.dumps(data).encode())

    def test_recorded_without_evidence_refused(self):
        self.data['gates']['authorized_lab']['status'] = 'recorded'
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_pending_with_evidence_refused(self):
        self.record('authorized_lab')
        self.data['gates']['authorized_lab']['status'] = 'pending'
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_evidence_paths_urls_and_malformed_hash_refused(self):
        self.record('authorized_lab')
        for value in ('https://example.com', '/tmp/evidence', 'SECRET-CANARY', 'g'*64, None, []):
            self.data['gates']['authorized_lab']['evidence'][0]['sha256'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.evaluate()

    def test_duplicate_evidence_refused(self):
        self.record('authorized_lab')
        entry = self.data['gates']['authorized_lab']
        entry['evidence'] *= 2
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):
            plan.evaluate(b'{"version":"1.0","version":"1.0"}')

    def test_oversized_malformed_nonfinite_inputs_refused(self):
        for raw in (b'x'*32001, b'\xff', b'NaN', b'null', b'[]'):
            with self.subTest(size=len(raw)), self.assertRaises((ValueError, UnicodeError)):
                plan.evaluate(raw)

    def test_no_network_or_evidence_file_reads(self):
        for gate in plan.GATES:
            self.record(gate)
        with patch('socket.socket', side_effect=AssertionError('network')), patch(
                'pathlib.Path.open', side_effect=AssertionError('evidence read')):
            self.evaluate()

    def test_cli_errors_do_not_echo_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'checklist.json'
            path.write_text('{"token":"SECRET-CANARY"}')
            result = subprocess.run([sys.executable,str(MODULE),'--checklist',str(path)],
                                    capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn('SECRET-CANARY',result.stdout+result.stderr)

    def test_summary_omits_evidence_hashes(self):
        self.record('authorized_lab')
        self.assertNotIn('a'*64, json.dumps(self.evaluate()))


if __name__ == '__main__':
    unittest.main()
