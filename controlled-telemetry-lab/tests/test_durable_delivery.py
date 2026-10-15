"""Offline queue recovery, atomicity, integrity and replay regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / 'controlled-telemetry-lab/src/durable_delivery.py'
spec = importlib.util.spec_from_file_location('delivery_tests', MODULE)
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)
RAW = delivery.trust.handoff.FIXTURE.read_bytes()
ASSERTION = {'mode': 'synthetic_offline_only', 'collector_id': 'lab-collector-01',
             'credential_status': 'valid', 'transport_status': 'verified'}


class DurableDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'queue'
        self.queue = delivery.Queue(self.directory)

    def enqueue(self, raw=RAW):
        return self.queue.enqueue(ASSERTION, raw)

    def sql(self, query, args=()):
        with sqlite3.connect(self.queue.path) as db:
            return db.execute(query, args).fetchall()

    def test_pending_survives_restart(self):
        self.assertEqual(self.enqueue(), {'queued': 6, 'duplicates': 0})
        restarted = delivery.Queue(self.directory)
        self.assertEqual(restarted.deliver_one()['acknowledged'], 6)
        self.assertEqual(restarted.deliver_one(), {'acknowledged': 0})

    def test_repeated_import_before_and_after_ack(self):
        self.enqueue()
        self.assertEqual(self.enqueue(), {'queued': 0, 'duplicates': 6})
        self.queue.deliver_one()
        self.assertEqual(delivery.Queue(self.directory).enqueue(ASSERTION, RAW),
                         {'queued': 0, 'duplicates': 6})
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(1,)])

    def test_conflicting_payload_rejects_whole_import(self):
        self.enqueue()
        data = json.loads(RAW)
        data['records'][0]['occurred_at'] = '2026-10-14T12:09:00Z'
        with self.assertRaisesRegex(delivery.Refused, 'conflicting_source_identity'):
            self.enqueue(json.dumps(data).encode())
        self.assertEqual(self.sql('SELECT count(*) FROM identities'), [(6,)])

    def test_overlapping_batches_only_queue_new_events(self):
        data = json.loads(RAW)
        data['records'] = data['records'][:3]
        self.assertEqual(self.enqueue(json.dumps(data).encode())['queued'], 3)
        self.assertEqual(self.enqueue(), {'queued': 3, 'duplicates': 3})
        self.assertEqual(self.queue.deliver_one()['acknowledged'], 3)
        self.assertEqual(self.queue.deliver_one()['acknowledged'], 3)
        self.assertEqual(self.queue.deliver_one()['acknowledged'], 0)

    def test_revoked_import_does_not_write(self):
        with self.assertRaises(ValueError):
            self.queue.enqueue(dict(ASSERTION, credential_status='revoked'), RAW)
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(0,)])

    def test_invalid_source_does_not_write(self):
        with self.assertRaises(ValueError):
            self.enqueue(b'not-json')
        self.assertEqual(self.sql('SELECT count(*) FROM identities'), [(0,)])

    def test_downstream_unavailable_leaves_pending_and_retry_works(self):
        self.enqueue()
        with patch.object(delivery.batch, 'process', side_effect=OSError('SECRET-CANARY')):
            with self.assertRaisesRegex(delivery.Refused, '^delivery_not_acknowledged$'):
                self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])
        self.assertEqual(delivery.Queue(self.directory).deliver_one()['acknowledged'], 6)

    def test_failed_verification_never_acknowledges(self):
        self.enqueue()
        with patch.object(delivery.integrity, 'verified_reports', side_effect=ValueError('bad seal')):
            with self.assertRaises(delivery.Refused):
                self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])

    def test_receipt_write_failure_rolls_back(self):
        self.enqueue()
        self.sql("CREATE TRIGGER fail_ack BEFORE UPDATE ON batches BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaisesRegex(delivery.Refused, '^queue_unavailable$'):
            self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])
        self.sql('DROP TRIGGER fail_ack')
        self.assertEqual(self.queue.deliver_one()['acknowledged'], 6)

    def test_killed_worker_after_processing_before_ack_recovers(self):
        self.enqueue()
        code = '''import importlib.util,os,sys
s=importlib.util.spec_from_file_location('crash_delivery',sys.argv[1])
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
original=m.batch.process
def crash(*args):
 original(*args)
 os._exit(73)
m.batch.process=crash
m.Queue(sys.argv[2]).deliver_one()
'''
        result = subprocess.run([sys.executable, '-c', code, str(MODULE), str(self.directory)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 73)
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])
        self.assertEqual(delivery.Queue(self.directory).deliver_one()['acknowledged'], 6)

    def test_killed_worker_after_commit_does_not_redeliver(self):
        self.enqueue()
        code = '''import importlib.util,os,sys
s=importlib.util.spec_from_file_location('crash_delivery',sys.argv[1])
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.Queue(sys.argv[2]).deliver_one()
os._exit(74)
'''
        result = subprocess.run([sys.executable, '-c', code, str(MODULE), str(self.directory)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 74)
        restarted = delivery.Queue(self.directory)
        self.assertEqual(restarted.deliver_one()['acknowledged'], 0)
        self.assertEqual(len(restarted.receipt(1)), 4)

    def test_simultaneous_workers_acknowledge_once(self):
        self.enqueue()
        command = [sys.executable, str(MODULE), '--queue-dir', str(self.directory), 'deliver-one']
        workers = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = [worker.communicate(timeout=30) for worker in workers]
        self.assertTrue(all(worker.returncode == 0 for worker in workers))
        self.assertEqual(sorted(json.loads(out)['acknowledged'] for out, _ in results), [0, 6])

    def test_corrupted_payload_refuses_delivery(self):
        self.enqueue()
        self.sql('UPDATE batches SET payload=?', ('SECRET-CANARY',))
        with self.assertRaisesRegex(delivery.Refused, '^invalid_queue_payload$'):
            self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status FROM batches'), [('pending',)])

    def test_modified_alert_semantics_even_with_new_digest_refused(self):
        self.enqueue()
        alerts = json.loads(self.sql('SELECT payload FROM batches')[0][0])
        alerts[0]['severity'] = 'critical'
        self.sql('UPDATE batches SET payload=?,payload_hash=?',
                 (delivery.canonical(alerts), delivery.replay.digest(alerts)))
        with self.assertRaises(delivery.Refused):
            self.queue.deliver_one()

    def test_missing_identity_binding_refused(self):
        self.enqueue()
        self.sql('DELETE FROM identities WHERE rowid=1')
        with self.assertRaises(delivery.Refused):
            self.queue.deliver_one()

    def test_receipt_corruption_refused_after_ack(self):
        self.enqueue()
        self.queue.deliver_one()
        self.sql('UPDATE batches SET receipt=?', ('{}',))
        with self.assertRaisesRegex(delivery.Refused, '^receipt_verification_failed$'):
            self.queue.receipt(1)

    def test_receipt_unavailable_before_ack(self):
        self.enqueue()
        with self.assertRaisesRegex(delivery.Refused, '^receipt_not_available$'):
            self.queue.receipt(1)

    def test_receipt_to_readonly_dashboard_has_no_cases(self):
        self.enqueue()
        self.queue.deliver_one()
        receipt = self.queue.receipt(1)
        adapter = delivery.load('delivery_dashboard', 'soc-command-center/src/adapter.py')
        view = adapter.build(json.loads(receipt['ingestion.json']), json.loads(receipt['correlation.json']))
        self.assertEqual(len(view['alerts']), 6)
        self.assertEqual(len(view['candidates']), 6)
        self.assertEqual(view['cases'], [])
        self.assertTrue(all(c['classification'] == 'unverified' for c in view['candidates']))

    def test_enqueue_write_failure_rolls_back_batch_and_identities(self):
        self.sql("CREATE TRIGGER fail_identity BEFORE INSERT ON identities BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(delivery.Refused):
            self.enqueue()
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(0,)])
        self.assertEqual(self.sql('SELECT count(*) FROM identities'), [(0,)])

    def test_simultaneous_imports_queue_once(self):
        command = [sys.executable, str(MODULE), '--queue-dir', str(self.directory), 'enqueue-fixture']
        workers = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = [worker.communicate(timeout=30) for worker in workers]
        self.assertTrue(all(worker.returncode == 0 for worker in workers))
        self.assertEqual(sorted(json.loads(out)['queued'] for out, _ in results), [0, 6])
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(1,)])

    def test_blocked_downstream_never_acknowledges(self):
        self.enqueue()
        with patch.object(delivery.batch, 'process', return_value={'status': 'blocked'}):
            with self.assertRaises(delivery.Refused):
                self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])

    def test_receipt_must_match_queued_alerts(self):
        self.enqueue()
        self.queue.deliver_one()
        receipt = self.queue.receipt(1)
        alerts = json.loads(self.sql('SELECT payload FROM batches')[0][0])
        with self.assertRaisesRegex(delivery.Refused, 'receipt_source_mismatch'):
            delivery.verify_receipt(receipt, alerts[:3])

    def test_capacity_rejects_new_import_without_partial_state(self):
        with patch.object(delivery, 'MAX_BATCHES', 0):
            with self.assertRaisesRegex(delivery.Refused, '^queue_capacity_reached$'):
                self.enqueue()
        self.assertEqual(self.sql('SELECT count(*) FROM identities'), [(0,)])

    def test_unrecognized_schema_refused(self):
        self.sql('PRAGMA user_version=99')
        with self.assertRaisesRegex(delivery.Refused, '^unsupported_queue_schema$'):
            self.enqueue()

    def test_corrupt_database_not_recreated(self):
        self.queue.path.write_bytes(b'broken database')
        with self.assertRaises(delivery.Refused):
            delivery.Queue(self.directory).deliver_one()
        self.assertEqual(self.queue.path.read_bytes(), b'broken database')

    def test_symlink_database_refused(self):
        other = Path(self.tmp.name) / 'other'
        other.write_text('untouched')
        self.queue.path.unlink()
        self.queue.path.symlink_to(other)
        with self.assertRaises(delivery.Refused):
            delivery.Queue(self.directory)
        self.assertEqual(other.read_text(), 'untouched')

    def test_symlink_sidecar_refused(self):
        Path(str(self.queue.path)+'-journal').symlink_to(Path(self.tmp.name)/'absent')
        with self.assertRaises(delivery.Refused):
            self.enqueue()

    def test_no_network_or_environment_needed(self):
        with patch('socket.socket', side_effect=AssertionError('network')), patch(
                'os.getenv', side_effect=AssertionError('environment')):
            self.enqueue()
            self.queue.deliver_one()


if __name__ == '__main__':
    unittest.main()
