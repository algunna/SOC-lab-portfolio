"""Adversarial policy simulations. No actual authentication is asserted."""
import copy
import importlib.util
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("trust_tests", ROOT / "controlled-telemetry-lab/src/collector_trust.py")
trust = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trust)
RAW = (ROOT / "controlled-telemetry-lab/fixtures/synthetic_sources.json").read_bytes()


class CollectorTrustTests(unittest.TestCase):
    def setUp(self):
        self.session = trust.OfflineTrustSession()
        self.assertion = {"mode": "synthetic_offline_only", "collector_id": "lab-collector-01",
                          "credential_status": "valid", "transport_status": "verified"}

    def accept(self, raw=RAW):
        return self.session.accept(self.assertion, raw)

    def test_valid_simulation_keeps_all_six_informational(self):
        result = self.accept()
        self.assertEqual(len(result['alerts']), 6)
        self.assertFalse(result['live_collector_authenticated'])
        self.assertFalse(result['live_source_verified'])
        self.assertTrue(all(a['severity'] == 'informational' for a in result['alerts']))

    def test_each_nonvalid_credential_fails_before_source_processing(self):
        for status in trust.STATUSES[1:]:
            with self.subTest(status=status), patch.object(trust.handoff, 'build') as build:
                self.assertion['credential_status'] = status
                with self.assertRaisesRegex(trust.Refused, '^authentication_refused$'):
                    self.accept()
                build.assert_not_called()

    def test_each_transport_failure_blocks_processing(self):
        for status in trust.TRANSPORTS[1:]:
            with self.subTest(status=status), patch.object(trust.handoff, 'build') as build:
                self.assertion['transport_status'] = status
                with self.assertRaisesRegex(trust.Refused, '^transport_refused$'):
                    self.accept()
                build.assert_not_called()

    def test_unknown_collector(self):
        self.assertion['collector_id'] = 'another-collector'
        with self.assertRaisesRegex(trust.Refused, '^unknown_collector$'):
            self.accept()

    def test_missing_fields(self):
        for key in tuple(self.assertion):
            candidate = dict(self.assertion)
            del candidate[key]
            with self.subTest(key=key), self.assertRaises(trust.Refused):
                self.session.accept(candidate, RAW)

    def test_extra_secret_or_source_claims_refused_without_echo(self):
        for key in ('token', 'authorization', 'authenticated', 'source_scope', 'password'):
            candidate = dict(self.assertion, **{key: 'SECRET-CANARY'})
            with self.subTest(key=key), self.assertRaises(trust.Refused) as caught:
                self.session.accept(candidate, RAW)
            self.assertNotIn('SECRET-CANARY', str(caught.exception))

    def test_wrong_types_and_unknown_statuses(self):
        for key in self.assertion:
            for value in (None, True, [], {}, 1, 'SECRET-CANARY'):
                candidate = dict(self.assertion, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(trust.Refused):
                    self.session.accept(candidate, RAW)

    def test_live_mode_refused(self):
        self.assertion['mode'] = 'live'
        with self.assertRaises(trust.Refused):
            self.accept()

    def test_exact_replay_rejected(self):
        self.accept()
        with self.assertRaisesRegex(trust.Refused, '^replay_refused$'):
            self.accept()

    def test_changed_payload_same_source_rejected(self):
        self.accept()
        data = json.loads(RAW)
        data['records'][0]['occurred_at'] = '2026-10-14T12:08:00Z'
        with self.assertRaisesRegex(trust.Refused, '^replay_refused$'):
            self.accept(json.dumps(data).encode())

    def test_failed_auth_does_not_reserve_records(self):
        self.assertion['credential_status'] = 'revoked'
        with self.assertRaises(trust.Refused):
            self.accept()
        self.assertion['credential_status'] = 'valid'
        self.assertEqual(len(self.accept()['alerts']), 6)

    def test_bad_record_rejects_whole_batch_without_reserving(self):
        data = json.loads(RAW)
        data['records'][-1]['occurred_at'] = 'SECRET-CANARY'
        with self.assertRaisesRegex(trust.Refused, '^source_validation_refused$'):
            self.accept(json.dumps(data).encode())
        self.assertEqual(len(self.accept()['alerts']), 6)

    def test_duplicate_record_refused(self):
        data = json.loads(RAW)
        data['records'].append(copy.deepcopy(data['records'][0]))
        with self.assertRaises(trust.Refused):
            self.accept(json.dumps(data).encode())

    def test_unknown_source_kind_refused(self):
        data = json.loads(RAW)
        data['records'][0]['kind'] = 'unapproved-source'
        with self.assertRaises(trust.Refused):
            self.accept(json.dumps(data).encode())

    def test_malformed_and_oversized_source(self):
        for raw in (b'not-json', b'\xff', b'x' * 100001, b'{"scope":1,"scope":2}'):
            with self.subTest(raw_length=len(raw)), self.assertRaisesRegex(
                    trust.Refused, '^source_validation_refused$'):
                self.accept(raw)

    def test_no_network_or_environment_access(self):
        with patch('socket.socket', side_effect=AssertionError('network accessed')), patch(
                'os.getenv', side_effect=AssertionError('environment accessed')):
            self.accept()

    def test_accepted_simulation_through_sealed_dashboard(self):
        def load(name, relative):
            spec = importlib.util.spec_from_file_location(name, ROOT / relative)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        batch = load('trust_batch', 'soc-event-ingestion/src/batch_health.py')
        integrity = load('trust_integrity', 'soc-event-ingestion/src/artifact_integrity.py')
        adapter = load('trust_adapter', 'soc-command-center/src/adapter.py')
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'observations.jsonl'
            source.write_text(''.join(json.dumps(a) + '\n' for a in self.accept()['alerts']))
            destination = Path(tmp) / 'batch'
            health = batch.process([source], destination)
            self.assertEqual(health['status'], 'passed')
            ingested, correlated = integrity.verified_reports(destination)
            view = adapter.build(ingested, correlated)
            self.assertEqual(len(view['alerts']), 6)
            self.assertEqual(len(view['candidates']), 6)
            self.assertEqual(view['cases'], [])
            self.assertTrue(all(c['classification'] == 'unverified' for c in view['candidates']))

    def test_session_restart_is_explicitly_not_durable(self):
        self.accept()
        self.assertEqual(len(trust.OfflineTrustSession().accept(self.assertion, RAW)['alerts']), 6)


if __name__ == '__main__':
    unittest.main()
