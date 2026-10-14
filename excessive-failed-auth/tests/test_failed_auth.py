import importlib.util
import unittest
from pathlib import Path
script = Path(__file__).resolve().parents[1] / "scripts" / "detect_failed_auth.py"
spec = importlib.util.spec_from_file_location("failed_auth", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def line(n, outcome='Failure', ip='192.0.2.4', user='test', hour=10):
    return f'Time: 2026-01-21T{hour:02d}:00:{n:02d}Z | Event: ConsoleLogin | Result: {outcome} | User: {user} | SourceIP: {ip}'
class DetectionTests(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(len(module.detect('\n'.join(line(i) for i in range(5)))), 1)
    def test_success_after_failures(self):
        data='\n'.join([*(line(i) for i in range(5)),line(6,'Success')])
        self.assertEqual(len(module.detect(data)),2)
    def test_different_accounts(self):
        data='\n'.join([*(line(i,user='a') for i in range(3)),*(line(i+4,user='b') for i in range(3))])
        self.assertEqual(module.detect(data),[])
    def test_window(self):
        data='\n'.join([*(line(i) for i in range(3)),*(line(i+4,hour=11) for i in range(3))])
        self.assertEqual(module.detect(data),[])
    def test_malformed(self):
        self.assertEqual(module.detect('SourceIP: totally_invalid'),[])
if __name__=='__main__': unittest.main()
