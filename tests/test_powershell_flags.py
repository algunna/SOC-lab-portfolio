"""Curated flag-policy regression; not real-world maliciousness accuracy."""
import importlib.util
import json
from pathlib import Path
import unittest
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flags = load('flags_test', 'scripts/powershell_flags.py')
windows = load('flags_windows', 'windows-threat-hunting-lab/src/hunt.py')
sysmon = load('flags_sysmon', 'windows-sysmon-ai-detection/scripts/sysmon_ai_detector.py')
CASES = json.loads((ROOT / 'tests/fixtures/powershell_host_flags.json').read_text())


class PowerShellFlagTests(unittest.TestCase):
    def test_curated_matrix_both_detectors(self):
        for case in CASES:
            for name, detector in (('windows', windows), ('sysmon', sysmon)):
                with self.subTest(case=case['id'], detector=name):
                    result = detector.powershell_indicators(case['command'])
                    self.assertEqual(sorted(x.lower() for x in result), sorted(case['expected']))

    def test_matrix_through_real_event_entrypoints(self):
        for case in CASES:
            with self.subTest(case=case['id']):
                event = {'event_id':4688, 'image':'powershell.exe', 'command_line':case['command']}
                self.assertEqual(bool(windows.hunt([event])), bool(case['expected']))
                xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                       '<System><EventID>1</EventID></System><EventData>'
                       '<Data Name="Image">powershell.exe</Data><Data Name="CommandLine">'
                       + escape(case['command']) + '</Data></EventData></Event>')
                self.assertEqual(bool(sysmon.analyze_xml(xml)), bool(case['expected']))

    def test_quoted_path_and_empty_arguments(self):
        self.assertEqual(flags.tokens('"C:\\Program Files\\pwsh.exe" "" -enc AAAA'),
                         ['C:\\Program Files\\pwsh.exe', '', '-enc', 'AAAA'])

    def test_backslash_escaped_quote_stays_literal(self):
        self.assertEqual(flags.tokens(r'pwsh.exe \"-enc\" AAAA'), ['pwsh.exe','"-enc"','AAAA'])
        self.assertEqual(flags.indicators(r'pwsh.exe \"-enc\" AAAA'), [])

    def test_backslash_before_closing_quote(self):
        self.assertEqual(flags.tokens(r'pwsh.exe "C:\\lab\\" -enc AAAA'),
                         ['pwsh.exe', 'C:\\\\lab\\', '-enc', 'AAAA'])

    def test_single_quotes_not_native_grouping(self):
        self.assertEqual(flags.indicators("powershell.exe '-enc' AAAA"), [])

    def test_empty_and_nonstring(self):
        for value in ('', '   ', None, [], 42):
            self.assertEqual(flags.indicators(value), [])

    def test_boundaries_with_prefixes_case_and_abbreviations(self):
        for prefix in flags.SWITCH_PREFIXES:
            for name in ('c', 'com', 'COMMAND', 'f', 'fi', 'FILE', 'cwa', 'CommandWithArgs'):
                with self.subTest(prefix=prefix,name=name):
                    self.assertEqual(flags.indicators(f'pwsh.exe {prefix}{name} script -enc AAAA'), [])

    def test_preboundary_flags_preserved(self):
        self.assertEqual(flags.indicators('pwsh.exe -enc AAAA -File script.ps1 -w hidden'), ['encoded command'])

    def test_missing_encoded_payload_still_investigation_lead(self):
        self.assertEqual(flags.indicators('pwsh.exe -enc'), ['encoded command'])

    def test_benign_encoded_content_not_silently_allowlisted(self):
        self.assertEqual(flags.indicators('pwsh.exe -enc RwBlAHQALQBEAGEAdABlAA=='), ['encoded command'])

    def test_nonpowershell_process_not_promoted(self):
        self.assertEqual(windows.hunt([{'event_id':4688,'image':'example.exe',
                                       'command_line':'example.exe -enc AAAA'}]), [])


if __name__ == '__main__':
    unittest.main()
