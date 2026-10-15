"""Bounded offline synthetic queue with atomic local verified receipts.

No remote transport or exactly-once external delivery claim. Authentication is
simulated. Queue payloads, replay identities and receipts share one SQLite DB.
"""
import argparse
from contextlib import closing, contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trust = load('delivery_trust', 'controlled-telemetry-lab/src/collector_trust.py')
replay = load('delivery_replay', 'soc-event-ingestion/src/replay_guard.py')
batch = load('delivery_batch', 'soc-event-ingestion/src/batch_health.py')
integrity = batch.integrity
MAX_BATCHES = 100
MAX_RECEIPT = 1_000_000
MAX_AUDIT = 10000
AUDIT_ACTIONS = ("enqueued", "duplicates_skipped", "delivery_started",
                 "delivery_acknowledged", "delivery_empty", "delivery_refused")
SCHEMA = '''
CREATE TABLE batches (
 id INTEGER PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('pending','acknowledged')),
 payload TEXT NOT NULL, payload_hash TEXT NOT NULL, receipt TEXT
);
CREATE TABLE identities (
 observation TEXT PRIMARY KEY, event TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL,
 batch_id INTEGER NOT NULL REFERENCES batches(id)
);
PRAGMA user_version=18;
'''


class Refused(ValueError):
    """Sanitized failure code; underlying payloads and paths are never echoed."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def synthetic_alerts(alerts):
    if type(alerts) is not list or not 1 <= len(alerts) <= 40:
        raise Refused('invalid_queue_payload')
    for alert in alerts:
        # Rebuild fixed informational semantics, not just a generic alert schema.
        projected = {'source': alert['source'], 'occurred_at': alert['occurred_at'],
                     'evidence_reference': alert['evidence'][0]['reference'],
                     'clock_review': 'within_lab_window',
                     'provenance': 'unauthenticated_synthetic_fixture'}
        if trust.handoff.observation_alert(projected) != alert:
            raise Refused('invalid_queue_payload')
    report = {'schema_version': '1.0', 'accepted': alerts, 'rejected': [],
              'duplicates': [], 'counts': {'accepted': len(alerts), 'rejected': 0, 'duplicates': 0}}
    replay.validate_report(report)


def verify_receipt(receipt, alerts):
    if type(receipt) is not dict or set(receipt) != integrity.FILE_SETS['passed'] | {'integrity.json'}:
        raise Refused('invalid_receipt')
    if any(type(value) is not str for value in receipt.values()):
        raise Refused('invalid_receipt')
    with tempfile.TemporaryDirectory(prefix='soc-receipt-check-') as tmp:
        directory = Path(tmp)
        for name, content in receipt.items():
            (directory / name).write_text(content, encoding='utf-8')
        ingested, _ = integrity.verified_reports(directory)
        if ingested['accepted'] != alerts or ingested['duplicates']:
            raise Refused('receipt_source_mismatch')


class Queue:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        if any(p.is_symlink() for p in (self.root, *self.root.parents)):
            raise Refused('unsafe_queue_path')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise Refused('unsafe_queue_path')
        if os.name == 'posix' and self.root.stat().st_mode & 0o077:
            raise Refused('queue_directory_must_be_private')
        self.path = self.root / 'delivery.sqlite3'
        # Initial creation is exclusive. Do not silently repair existing bad DBs.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            with closing(sqlite3.connect(self.path)) as db:
                db.executescript(SCHEMA)
        self._check_paths()

    def _check_paths(self):
        for path in (self.path, Path(str(self.path)+'-journal'),
                     Path(str(self.path)+'-wal'), Path(str(self.path)+'-shm')):
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise Refused('unsafe_queue_path')
        if os.name == 'posix' and self.path.stat().st_mode & 0o077:
            raise Refused('queue_database_must_be_private')

    @contextmanager
    def transaction(self):
        self._check_paths()
        try:
            with closing(sqlite3.connect(self.path, timeout=1, isolation_level=None)) as db:
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                try:
                    version = db.execute('PRAGMA user_version').fetchone()[0]
                    if version == 18:
                        # Transactional migration; historical operations are not invented.
                        db.execute('CREATE TABLE audit (seq INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, '
                                   'action TEXT NOT NULL, batch_id INTEGER, count INTEGER NOT NULL, attempt INTEGER)')
                        db.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append_only'); END")
                        db.execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append_only'); END")
                        db.execute('PRAGMA user_version=19')
                    elif version != 19:
                        raise Refused('unsupported_queue_schema')
                    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                        raise Refused('queue_corrupt')
                    yield db
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        except (sqlite3.Error, OSError):
            raise Refused('queue_unavailable') from None

    def _audit(self, db, action, *, batch_id=None, count=0, attempt=None):
        if action not in AUDIT_ACTIONS:
            raise Refused('invalid_audit_action')
        if db.execute('SELECT count(*) FROM audit').fetchone()[0] >= MAX_AUDIT:
            raise Refused('audit_capacity_reached')
        return db.execute('INSERT INTO audit(timestamp,action,batch_id,count,attempt) VALUES (?,?,?,?,?)',
                          (int(time.time()), action, batch_id, count, attempt)).lastrowid

    def enqueue(self, assertion, raw):
        # Pipeline 17 remains explicitly simulated; every import rechecks policy.
        alerts = trust.OfflineTrustSession().accept(assertion, raw)['alerts']
        with self.transaction() as db:
            fresh = []
            for alert in alerts:
                obs, event, fingerprint = replay.keys(alert)
                previous = db.execute('SELECT observation,event,fingerprint FROM identities '
                                      'WHERE observation=? OR event=?', (obs, event)).fetchall()
                if previous and previous != [(obs, event, fingerprint)]:
                    raise Refused('conflicting_source_identity')
                if not previous:
                    fresh.append(alert)
            if not fresh:
                self._audit(db, 'duplicates_skipped', count=len(alerts))
                return {'queued': 0, 'duplicates': len(alerts)}
            if db.execute('SELECT count(*) FROM batches').fetchone()[0] >= MAX_BATCHES:
                raise Refused('queue_capacity_reached')
            payload = canonical(fresh)
            cursor = db.execute('INSERT INTO batches(status,payload,payload_hash) VALUES (?,?,?)',
                                ('pending', payload, replay.digest(fresh)))
            for alert in fresh:
                db.execute('INSERT INTO identities VALUES (?,?,?,?)',
                           (*replay.keys(alert), cursor.lastrowid))
            self._audit(db, 'enqueued', batch_id=cursor.lastrowid, count=len(fresh))
            return {'queued': len(fresh), 'duplicates': len(alerts)-len(fresh)}

    def _payload(self, db, row):
        batch_id, _, payload, fingerprint, _ = row
        if type(payload) is not str or len(payload) > 100_000:
            raise Refused('invalid_queue_payload')
        try:
            alerts = integrity.read_json(payload.encode('utf-8'))
            synthetic_alerts(alerts)
            if replay.digest(alerts) != fingerprint:
                raise Refused('queue_payload_changed')
            actual = set(db.execute('SELECT observation,event,fingerprint FROM identities WHERE batch_id=?',
                                    (batch_id,)).fetchall())
            if actual != {replay.keys(a) for a in alerts}:
                raise Refused('queue_identity_mismatch')
            return alerts
        except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
            raise Refused('invalid_queue_payload') from None

    def deliver_one(self):
        # Start is durable before processing; abrupt death leaves an explicitly
        # unresolved attempt. It does not imply a worker is currently running.
        with self.transaction() as db:
            if db.execute('SELECT count(*) FROM audit').fetchone()[0] > MAX_AUDIT - 2:
                raise Refused('audit_capacity_reached')
            attempt = self._audit(db, 'delivery_started')
        try:
            return self._deliver_one(attempt)
        except (ValueError, OSError, sqlite3.Error):
            try:
                with self.transaction() as db:
                    self._audit(db, 'delivery_refused', attempt=attempt)
            except (ValueError, OSError, sqlite3.Error):
                raise Refused('delivery_and_audit_unavailable') from None
            raise

    def _deliver_one(self, attempt):
        # Hold the writer lock through bounded local processing. Other workers
        # wait or fail safely; crash rollback leaves the batch pending.
        with self.transaction() as db:
            row = db.execute('SELECT * FROM batches WHERE status=? ORDER BY id LIMIT 1', ('pending',)).fetchone()
            if row is None:
                self._audit(db, 'delivery_empty', attempt=attempt)
                return {'acknowledged': 0}
            alerts = self._payload(db, row)
            try:
                with tempfile.TemporaryDirectory(prefix='soc-delivery-') as tmp:
                    source = Path(tmp) / 'observations.jsonl'
                    source.write_text(''.join(canonical(a)+'\n' for a in alerts), encoding='utf-8')
                    destination = Path(tmp) / 'batch'
                    if batch.process([source], destination)['status'] != 'passed':
                        raise Refused('downstream_refused')
                    integrity.verified_reports(destination)
                    receipt = {name: (destination/name).read_text(encoding='utf-8')
                               for name in integrity.FILE_SETS['passed'] | {'integrity.json'}}
                verify_receipt(receipt, alerts)
                encoded = canonical(receipt)
                if len(encoded) > MAX_RECEIPT:
                    raise Refused('receipt_too_large')
                db.execute('UPDATE batches SET status=?,receipt=? WHERE id=?',
                           ('acknowledged', encoded, row[0]))
                self._audit(db, 'delivery_acknowledged', batch_id=row[0], count=len(alerts), attempt=attempt)
            except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError):
                raise Refused('delivery_not_acknowledged') from None
            return {'acknowledged': len(alerts), 'batch_id': row[0]}

    def receipt(self, batch_id):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM batches WHERE id=?', (batch_id,)).fetchone()
            if row is None or row[1] != 'acknowledged':
                raise Refused('receipt_not_available')
            alerts = self._payload(db, row)
            try:
                if type(row[4]) is not str or len(row[4]) > MAX_RECEIPT:
                    raise Refused('invalid_receipt')
                receipt = integrity.read_json(row[4].encode('utf-8'))
                verify_receipt(receipt, alerts)
            except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError):
                raise Refused('receipt_verification_failed') from None
            return receipt


def main():
    parser = argparse.ArgumentParser(description='Offline synthetic durable delivery rehearsal')
    parser.add_argument('--queue-dir', required=True, type=Path)
    parser.add_argument('action', choices=('enqueue-fixture', 'deliver-one', 'verify-receipt'))
    parser.add_argument('--batch-id', type=int, default=1)
    args = parser.parse_args()
    try:
        queue = Queue(args.queue_dir)
        if args.action == 'enqueue-fixture':
            assertion = {'mode': 'synthetic_offline_only', 'collector_id': 'lab-collector-01',
                         'credential_status': 'valid', 'transport_status': 'verified'}
            result = queue.enqueue(assertion, trust.handoff.FIXTURE.read_bytes())
        elif args.action == 'deliver-one':
            result = queue.deliver_one()
        else:
            queue.receipt(args.batch_id)
            result = {'receipt_verified': True}
    except (OSError, sqlite3.Error, ValueError, TypeError):
        parser.error('Offline queue operation refused; inspect trusted local state')
    print(canonical({'mode': 'synthetic_offline_only', 'live_delivery_verified': False, **result}))


if __name__ == '__main__':
    main()
