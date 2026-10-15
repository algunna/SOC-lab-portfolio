"""Read-only queue health, append-only audit and migration safety tests."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / 'controlled-telemetry-lab/src/collector_health.py'
spec = importlib.util.spec_from_file_location('collector_health_tests', MODULE)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
delivery = health.delivery
RAW = delivery.trust.handoff.FIXTURE.read_bytes()
ASSERTION = {'mode': 'synthetic_offline_only', 'collector_id': 'lab-collector-01',
             'credential_status': 'valid', 'transport_status': 'verified'}


class CollectorHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'queue'
        self.queue = delivery.Queue(self.directory)

    def sql(self, query, args=()):
        with sqlite3.connect(self.queue.path) as db:
            return db.execute(query, args).fetchall()

    def enqueue(self):
        return self.queue.enqueue(ASSERTION, RAW)

    def inspect(self):
        return health.inspect(self.directory)

    def test_missing_queue_never_created(self):
        missing = Path(self.tmp.name) / 'missing'
        self.assertEqual(health.inspect(missing)['status'], 'unavailable')
        self.assertFalse(missing.exists())

    def test_legacy_queue_reported_without_migration(self):
        before = self.queue.path.read_bytes()
        self.assertEqual(self.inspect()['status'], 'uninstrumented')
        self.assertEqual(self.sql('PRAGMA user_version'), [(18,)])
        self.assertEqual(before, self.queue.path.read_bytes())

    def test_existing_legacy_receipt_survives_upgrade_without_invented_history(self):
        self.enqueue()
        self.queue.deliver_one()
        before = self.sql('SELECT * FROM batches')
        identities = self.sql('SELECT * FROM identities')
        self.sql('DROP TABLE audit')
        self.sql('PRAGMA user_version=18')
        self.assertEqual(self.inspect()['status'], 'uninstrumented')
        self.enqueue()
        self.assertEqual(self.sql('SELECT * FROM batches'), before)
        self.assertEqual(self.sql('SELECT * FROM identities'), identities)
        result = self.inspect()
        self.assertEqual(result['status'], 'idle')
        self.assertEqual(result['acknowledged_batches'], 1)
        self.assertEqual([r['action'] for r in result['recent_activity']], ['duplicates_skipped'])

    def test_write_migrates_and_records_enqueue(self):
        self.enqueue()
        self.assertEqual(self.sql('PRAGMA user_version'), [(19,)])
        result = self.inspect()
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['pending_batches'], 1)
        self.assertEqual(result['audit_entries'], 1)
        self.assertEqual(result['recent_activity'][0]['action'], 'enqueued')

    def test_successful_delivery_records_bound_ack(self):
        self.enqueue()
        self.queue.deliver_one()
        result = self.inspect()
        self.assertEqual(result['status'], 'idle')
        self.assertEqual(result['acknowledged_batches'], 1)
        self.assertEqual(result['unresolved_attempts'], 0)
        self.assertEqual([r['action'] for r in result['recent_activity']],
                         ['enqueued', 'delivery_started', 'delivery_acknowledged'])

    def test_empty_delivery_recorded(self):
        self.queue.deliver_one()
        result = self.inspect()
        self.assertEqual(result['status'], 'idle')
        self.assertEqual(result['recent_activity'][-1]['action'], 'delivery_empty')

    def test_duplicate_import_recorded_without_second_batch(self):
        self.enqueue()
        self.enqueue()
        result = self.inspect()
        self.assertEqual(result['observations'], 6)
        self.assertEqual(result['recent_activity'][-1]['action'], 'duplicates_skipped')

    def test_downstream_failure_visible_and_retry_retains_history(self):
        self.enqueue()
        with patch.object(delivery.batch, 'process', side_effect=OSError('SECRET-CANARY')):
            with self.assertRaises(ValueError):
                self.queue.deliver_one()
        result = self.inspect()
        self.assertEqual(result['status'], 'attention')
        self.assertEqual(result['recorded_failures'], 1)
        self.assertEqual(result['unresolved_attempts'], 0)
        self.queue.deliver_one()
        self.assertEqual(self.inspect()['acknowledged_batches'], 1)
        self.assertEqual(self.inspect()['recorded_failures'], 1)

    def test_process_crash_leaves_unresolved_attempt(self):
        self.enqueue()
        code = '''import importlib.util,os,sys
s=importlib.util.spec_from_file_location('crashing_queue',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def crash(*args): os._exit(75)
m.batch.process=crash
m.Queue(sys.argv[2]).deliver_one()
'''
        result = subprocess.run([sys.executable, '-c', code,
                                 str(ROOT/'controlled-telemetry-lab/src/durable_delivery.py'), str(self.directory)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 75)
        report = self.inspect()
        self.assertEqual(report['status'], 'attention')
        self.assertEqual(report['unresolved_attempts'], 1)
        self.assertEqual(report['pending_batches'], 1)
        self.queue.deliver_one()
        self.assertEqual(self.inspect()['unresolved_attempts'], 1)

    def test_audit_update_and_delete_refused(self):
        self.enqueue()
        for command in ('UPDATE audit SET count=0', 'DELETE FROM audit'):
            with self.subTest(command=command), self.assertRaises(sqlite3.IntegrityError):
                self.sql(command)
        self.assertEqual(self.inspect()['audit_entries'], 1)

    def test_enqueue_audit_failure_rolls_back_queue(self):
        with self.queue.transaction():
            pass
        self.sql("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(ValueError):
            self.enqueue()
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(0,)])
        self.assertEqual(self.sql('SELECT count(*) FROM identities'), [(0,)])

    def test_ack_audit_failure_rolls_back_receipt(self):
        self.enqueue()
        self.sql("CREATE TRIGGER fail_ack_audit BEFORE INSERT ON audit WHEN NEW.action='delivery_acknowledged' BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(ValueError):
            self.queue.deliver_one()
        self.assertEqual(self.sql('SELECT status,receipt FROM batches'), [('pending', None)])
        self.assertEqual(self.inspect()['recorded_failures'], 1)

    def test_start_audit_failure_prevents_processing(self):
        self.enqueue()
        with patch.object(delivery, 'MAX_AUDIT', 2), patch.object(delivery.batch, 'process') as process:
            with self.assertRaisesRegex(delivery.Refused, 'audit_capacity_reached'):
                self.queue.deliver_one()
            process.assert_not_called()

    def test_migration_failure_is_atomic(self):
        self.sql('CREATE TABLE audit (existing TEXT)')
        with self.assertRaises(ValueError):
            self.enqueue()
        self.assertEqual(self.sql('PRAGMA user_version'), [(18,)])
        self.assertEqual(self.sql('SELECT count(*) FROM batches'), [(0,)])

    def test_health_is_readonly_including_after_ack(self):
        self.enqueue()
        self.queue.deliver_one()
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.assertEqual(self.inspect()['status'], 'idle')
        after = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.assertEqual(before, after)

    def test_corrupt_pending_blocks_instead_of_healthy_counts(self):
        self.enqueue()
        self.sql('UPDATE batches SET payload=?', ('SECRET-CANARY',))
        self.assertEqual(self.inspect()['status'], 'blocked')
        self.assertNotIn('SECRET-CANARY', json.dumps(self.inspect()))

    def test_corrupt_receipt_blocks(self):
        self.enqueue()
        self.queue.deliver_one()
        self.sql('UPDATE batches SET receipt=?', ('{}',))
        self.assertEqual(self.inspect()['status'], 'blocked')

    def test_orphan_identity_blocks(self):
        self.enqueue()
        self.sql("INSERT INTO identities VALUES ('a','b','c',999)")
        self.assertEqual(self.inspect()['status'], 'blocked')

    def test_forged_audit_action_not_echoed(self):
        self.enqueue()
        self.sql('INSERT INTO audit(timestamp,action,count) VALUES (1,?,0)', ('SECRET-CANARY',))
        result = self.inspect()
        self.assertEqual(result['status'], 'blocked')
        self.assertNotIn('SECRET-CANARY', json.dumps(result))

    def test_ack_without_attempt_refused(self):
        self.enqueue()
        self.sql("INSERT INTO audit(timestamp,action,batch_id,count,attempt) VALUES (1,'delivery_acknowledged',1,6,999)")
        self.assertEqual(self.inspect()['status'], 'blocked')

    def test_recent_activity_bounded(self):
        self.enqueue()
        for _ in range(25):
            self.enqueue()
        result = self.inspect()
        self.assertEqual(result['audit_entries'], 26)
        self.assertEqual(len(result['recent_activity']), 20)

    def test_metadata_output_does_not_expose_sources_or_paths(self):
        self.enqueue()
        self.queue.deliver_one()
        report = json.dumps(self.inspect())
        for text in ('LAB-WS01', '123456789012', 'lab-src-', 'synthetic-source:',
                     str(self.directory), 'payload', 'Authorization'):
            self.assertNotIn(text, report)

    def test_cli_blocked_exit_and_sanitized_output(self):
        self.enqueue()
        self.sql('UPDATE batches SET payload=?', ('SECRET-CANARY',))
        result = subprocess.run([sys.executable, str(MODULE), '--queue-dir', str(self.directory)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
        self.assertNotIn('SECRET-CANARY', result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
