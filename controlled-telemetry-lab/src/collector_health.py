"""Read-only, metadata-only verification of the offline synthetic delivery queue.

Never initializes/migrates state. No network, automatic recovery or liveness claim.
"""
import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3

spec = importlib.util.spec_from_file_location('health_delivery', Path(__file__).with_name('durable_delivery.py'))
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)


def inspect(directory):
    base = {'mode': 'synthetic_offline_only', 'live_collector_verified': False,
            'audit_authenticated': False, 'audit_scope': 'operations_since_schema_19'}
    try:
        # Do not call Queue.__init__: even a missing DB must remain missing.
        queue = object.__new__(delivery.Queue)
        queue.root = Path(directory).absolute()
        queue.path = queue.root / 'delivery.sqlite3'
        if any(p.is_symlink() for p in (queue.root, *queue.root.parents)):
            raise ValueError('unsafe_path')
        if not queue.root.is_dir() or not queue.path.is_file():
            return {**base, 'status': 'unavailable', 'reason': 'queue_unavailable'}
        if os.name == 'posix' and queue.root.stat().st_mode & 0o077:
            raise ValueError('unsafe_path')
        queue._check_paths()
        with closing(sqlite3.connect(queue.path.as_uri()+'?mode=ro', uri=True,
                                     timeout=1, isolation_level=None)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (18, 19):
                raise ValueError('unsupported_schema')
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('invalid_database')
            count = db.execute('SELECT count(*) FROM batches').fetchone()[0]
            if count > delivery.MAX_BATCHES:
                raise ValueError('capacity_exceeded')
            pending = acknowledged = observations = 0
            batches = {}
            for row in db.execute('SELECT id,status,payload,payload_hash,receipt FROM batches ORDER BY id'):
                if row[1] not in ('pending', 'acknowledged'):
                    raise ValueError('invalid_status')
                alerts = queue._payload(db, row)
                observations += len(alerts)
                batches[row[0]] = (row[1], len(alerts))
                if row[1] == 'pending':
                    if row[4] is not None:
                        raise ValueError('pending_receipt')
                    pending += 1
                else:
                    if type(row[4]) is not str or len(row[4]) > delivery.MAX_RECEIPT:
                        raise ValueError('invalid_receipt')
                    receipt = delivery.integrity.read_json(row[4].encode())
                    delivery.verify_receipt(receipt, alerts)
                    acknowledged += 1
            if db.execute('SELECT count(*) FROM identities').fetchone()[0] != observations:
                raise ValueError('orphan_identity')
            if version == 18:
                return {**base, 'status': 'uninstrumented', 'reason': 'legacy_audit_unavailable',
                        'pending_batches': pending, 'acknowledged_batches': acknowledged}
            audit_count = db.execute('SELECT count(*) FROM audit').fetchone()[0]
            if audit_count > delivery.MAX_AUDIT:
                raise ValueError('audit_capacity_exceeded')
            starts, ended, ack_batches = set(), set(), set()
            failures = 0
            recent = []
            for seq, timestamp, action, batch_id, amount, attempt in db.execute('SELECT * FROM audit ORDER BY seq'):
                if (type(seq) is not int or seq < 1 or type(timestamp) is not int or timestamp < 0 or
                    action not in delivery.AUDIT_ACTIONS or type(amount) is not int or not 0 <= amount <= 40):
                    raise ValueError('invalid_audit')
                if action == 'delivery_started':
                    if attempt is not None or batch_id is not None or amount != 0:
                        raise ValueError('invalid_start')
                    starts.add(seq)
                elif action in ('delivery_acknowledged', 'delivery_empty', 'delivery_refused'):
                    if type(attempt) is not int or attempt not in starts or attempt in ended:
                        raise ValueError('invalid_attempt_binding')
                    ended.add(attempt)
                    if action == 'delivery_acknowledged':
                        if batch_id in ack_batches or batches.get(batch_id) != ('acknowledged', amount):
                            raise ValueError('invalid_ack_binding')
                        ack_batches.add(batch_id)
                    elif batch_id is not None or amount != 0:
                        raise ValueError('invalid_terminal')
                    failures += int(action == 'delivery_refused')
                elif action == 'enqueued':
                    if attempt is not None or batch_id not in batches or batches[batch_id][1] != amount or amount == 0:
                        raise ValueError('invalid_enqueue_binding')
                elif action == 'duplicates_skipped':
                    if attempt is not None or batch_id is not None or amount == 0:
                        raise ValueError('invalid_duplicate_audit')
                recent.append({'sequence': seq, 'timestamp': timestamp, 'action': action, 'count': amount})
            unresolved = len(starts - ended)
            warnings = []
            if unresolved:
                warnings.append('unresolved_delivery_attempts')
            if failures:
                warnings.append('recorded_delivery_failures')
            if count >= delivery.MAX_BATCHES:
                warnings.append('queue_capacity_reached')
            if audit_count > delivery.MAX_AUDIT - 2:
                warnings.append('audit_capacity_reached')
            return {**base, 'status': 'attention' if warnings else 'pending' if pending else 'idle',
                    'pending_batches': pending, 'acknowledged_batches': acknowledged,
                    'observations': observations, 'audit_entries': audit_count,
                    'unresolved_attempts': unresolved, 'recorded_failures': failures,
                    'warnings': warnings, 'recent_activity': recent[-20:]}
    except (OSError, sqlite3.Error):
        return {**base, 'status': 'unavailable', 'reason': 'queue_unavailable'}
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        return {**base, 'status': 'blocked', 'reason': 'queue_verification_refused'}


def main():
    parser = argparse.ArgumentParser(description='Read-only offline collector health verification')
    parser.add_argument('--queue-dir', required=True, type=Path)
    args = parser.parse_args()
    report = inspect(args.queue_dir)
    print(json.dumps(report, sort_keys=True))
    if report['status'] in ('blocked', 'unavailable', 'uninstrumented'):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
