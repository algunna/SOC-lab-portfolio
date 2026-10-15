"""Validate a human-maintained live-lab evidence checklist, never certify it.

No network, evidence-file access, credentials, collector enablement or case writes.
Even a fully populated checklist remains unverified and requires manual review.
"""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / 'splunk-readonly-connector/fixtures/live_acceptance_checklist.json'
MAX_BYTES = 32_000
# Ordered prerequisites, not evidence that any implementation is deployed.
GATES = (
    'authorized_lab', 'splunk_installation', 'tls_and_permissions', 'count_only_probe',
    'source_mapping', 'detector_validation', 'independent_security_review',
    'collector_authentication', 'delivery_recovery', 'analyst_case', 'command_center',
)
REVIEW_GATES = {'authorized_lab', 'independent_security_review'}
HASH = re.compile(r'[0-9a-f]{64}\Z')


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate checklist field')
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError('Invalid JSON constant')


def evaluate(raw):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError('Invalid checklist size')
    data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_keys, parse_constant=reject_constant)
    if (type(data) is not dict or set(data) != {'version', 'scope', 'gates'} or
        data['version'] != '1.0' or data['scope'] != 'live_acceptance_preparation' or
        type(data['gates']) is not dict or set(data['gates']) != set(GATES)):
        raise ValueError('Invalid acceptance checklist')
    recorded, pending, blocked, unmet = [], [], [], []
    for gate in GATES:
        entry = data['gates'][gate]
        if (type(entry) is not dict or set(entry) != {'status', 'evidence'} or
            type(entry['status']) is not str or entry['status'] not in ('pending', 'blocked', 'recorded') or
            type(entry['evidence']) is not list or len(entry['evidence']) > 4):
            raise ValueError('Invalid gate entry')
        if entry['status'] != 'recorded':
            if entry['evidence']:
                raise ValueError('Unrecorded gate cannot claim evidence')
            (pending if entry['status'] == 'pending' else blocked).append(gate)
            unmet.append(gate)
            continue
        if not entry['evidence']:
            raise ValueError('Recorded gate requires evidence reference')
        # Synthetic CI/demo evidence cannot satisfy a declared live gate.
        expected_kind = 'operator_review' if gate in REVIEW_GATES else 'authorized_live_lab'
        seen = set()
        for evidence in entry['evidence']:
            if (type(evidence) is not dict or set(evidence) != {'kind', 'sha256'} or
                evidence['kind'] != expected_kind or type(evidence['sha256']) is not str or
                HASH.fullmatch(evidence['sha256']) is None or evidence['sha256'] in seen):
                raise ValueError('Invalid live evidence reference')
            seen.add(evidence['sha256'])
        if unmet:
            raise ValueError('Recorded gate has incomplete prerequisites')
        recorded.append(gate)
    return {'version': '1.0', 'scope': 'live_acceptance_preparation',
            'status': 'claims_complete_manual_review_required' if not unmet else 'incomplete',
            'recorded_gates': recorded, 'pending_gates': pending, 'blocked_gates': blocked,
            'next_gate': unmet[0] if unmet else None,
            'evidence_contents_verified': False, 'live_splunk_verified': False,
            'collector_enablement_authorized': False}


def main():
    parser = argparse.ArgumentParser(description='Validate offline acceptance checklist structure, not live readiness')
    parser.add_argument('--checklist', type=Path, default=TEMPLATE)
    args = parser.parse_args()
    try:
        # Bounded reads; do not consume arbitrary evidence files or URLs.
        if args.checklist.is_symlink() or not args.checklist.is_file():
            raise ValueError('Invalid checklist file')
        with args.checklist.open('rb') as stream:
            report = evaluate(stream.read(MAX_BYTES + 1))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        parser.error('Acceptance checklist refused; no live verification performed')
    print(json.dumps(report, indent=2))
    # Exit 0 means structurally valid, including an honestly pending template.
    # No exit status authorizes live operation; inspect the explicit false flags.


if __name__ == '__main__':
    main()
