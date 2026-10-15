"""Synthetic consecutive-authentication sequence policy regression."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth = load('burst_auth', 'excessive-failed-auth/scripts/detect_failed_auth.py')
windows = load('burst_windows', 'windows-threat-hunting-lab/src/hunt.py')


def row(result, second, user='admin', ip='192.0.2.1', event='ConsoleLogin'):
    return f'Time: 2026-01-21T12:00:{second:02d}Z | Event: {event} | Result: {result} | User: {user} | SourceIP: {ip}'


def win(events):
    result = []
    for text in events:
        event = auth.parse_line(text)
        result.append({'event_id':4625 if event['Result']=='Failure' else 4624,
                       'timestamp':event['Time'], 'user':event['User'],
                       'source_ip':event['SourceIP'], 'host':'lab'})
    return windows.hunt(result)


class BurstBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.failures = [row('Failure', i) for i in range(5)]

    def critical(self, rows):
        return [a for a in auth.detect_failed_auth(rows) if a.startswith('[CRITICAL]')]

    def test_success_of_different_account_not_linked(self):
        self.assertEqual(self.critical(self.failures+[row('Success',9,user='other')]), [])

    def test_account_case_not_silently_collapsed_in_generic_logs(self):
        self.assertEqual(self.critical(self.failures+[row('Success',9,user='ADMIN')]), [])

    def test_event_types_not_linked(self):
        self.assertEqual(self.critical(self.failures+[row('Success',9,event='OtherLogin')]), [])

    def test_source_separation(self):
        self.assertEqual(self.critical(self.failures+[row('Success',9,ip='192.0.2.2')]), [])

    def test_stale_failures_expire(self):
        success = row('Success',9).replace('12:00:09','13:00:09')
        self.assertEqual(self.critical(self.failures+[success]), [])

    def test_repeated_success_only_uses_burst_once_both_detectors(self):
        rows = self.failures+[row('Success',8),row('Success',9)]
        self.assertEqual(len(self.critical(rows)),1)
        self.assertEqual(len(win(rows)),1)

    def test_below_threshold_success_resets_both_detectors(self):
        rows = self.failures[:3]+[row('Success',3),row('Failure',4),row('Failure',5),row('Success',6)]
        self.assertEqual(self.critical(rows),[])
        self.assertEqual(win(rows),[])

    def test_new_burst_after_success_both_detectors(self):
        rows = self.failures+[row('Success',5)]+[row('Failure',i) for i in range(6,11)]+[row('Success',11)]
        self.assertEqual(len(self.critical(rows)),2)
        self.assertEqual(len(win(rows)),2)

    def test_other_account_success_does_not_reset_target(self):
        rows = self.failures[:3]+[row('Success',3,user='other')]+self.failures[3:]+[row('Success',9)]
        self.assertEqual(len(self.critical(rows)),1)
        self.assertEqual(len(win(rows)),1)

    def test_out_of_order_events_sorted(self):
        rows = self.failures+[row('Success',9)]
        self.assertEqual(self.critical(rows),self.critical(list(reversed(rows))))

    def test_inclusive_five_minute_boundary_both_detectors(self):
        rows = self.failures+[row('Success',0).replace('12:00:00','12:05:00')]
        self.assertEqual(len(self.critical(rows)),1)
        self.assertEqual(len(win(rows)),1)
        rows[-1] = rows[-1].replace('12:05:00','12:05:01')
        self.assertEqual(self.critical(rows),[])
        self.assertEqual(win(rows),[])

    def test_mixed_offsets_normalized(self):
        rows = [r.replace('12:00:','14:00:').replace('Z |','+02:00 |') for r in self.failures]+[row('Success',9)]
        self.assertEqual(len(self.critical(rows)),1)

    def test_unknown_or_missing_identity_skipped(self):
        for field in ('User','Event','SourceIP'):
            for value in ('unknown','-',''):
                rows = []
                for text in self.failures+[row('Success',9)]:
                    event = auth.parse_line(text);event[field]=value
                    rows.append(' | '.join(f'{k}: {v}' for k,v in event.items()))
                with self.subTest(field=field,value=value):
                    self.assertEqual(auth.detect_failed_auth(rows),[])

    def test_naive_invalid_or_missing_times_skipped(self):
        for value in ('2026-01-21T12:00:00','not-a-time','2026-02-30T12:00:00Z',''):
            rows = [r.replace(auth.parse_line(r)['Time'],value) for r in self.failures]
            self.assertEqual(auth.detect_failed_auth(rows+[row('Success',9)]),[])

    def test_duplicate_fields_ambiguous(self):
        rows = [r+' | User: other' for r in self.failures]
        self.assertEqual(auth.detect_failed_auth(rows+[row('Success',9)]),[])

    def test_invalid_source_address_skipped(self):
        rows = [r.replace('192.0.2.1','not-an-ip') for r in self.failures+[row('Success',9)]]
        self.assertEqual(auth.detect_failed_auth(rows),[])

    def test_ipv6_spellings_same_source(self):
        rows = [r.replace('192.0.2.1','2001:0db8:0:0:0:0:0:1') for r in self.failures]
        rows.append(row('Success',9,ip='2001:db8::1'))
        self.assertEqual(len(self.critical(rows)),1)

    def test_invalid_configuration(self):
        for value in (0,-1,True,1.5,'5'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                auth.detect_failed_auth([],threshold=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                auth.detect_failed_auth([],window_seconds=value)

    def test_equal_timestamps_preserve_input_order(self):
        failures = [row('Failure',0) for _ in range(5)]
        self.assertEqual(self.critical([row('Success',0)]+failures),[])
        self.assertEqual(len(self.critical(failures+[row('Success',0)])),1)

    def test_second_high_burst_after_window_expiry(self):
        later = [r.replace('12:00:','12:10:') for r in self.failures]
        alerts = auth.detect_failed_auth(self.failures+later)
        self.assertEqual(sum(a.startswith('[HIGH]') for a in alerts),2)


if __name__ == '__main__':
    unittest.main()
