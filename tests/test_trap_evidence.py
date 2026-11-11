from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from trap_evidence import confirm_trap


class EvidenceTests(unittest.TestCase):
    def test_exact_pc_and_binary_hash_are_required(self):
        observed = {'invalid_reason': 'unattributed_crash', 'attack_triggered': True,
                    'stderr': '[!] PC_OFFSET: 0x1234\n', 'signal': 'SIGILL',
                    'effect_occurred': False, 'valid': False, 'detected': False}
        evidence = {'test': {'sha256': 'a'*64, 'sites': [
            {'pc_offset': '0x1234', 'signal': 'SIGILL', 'mechanism': 'CFI',
             'review_note': 'Reviewed test fixture'}]}}
        confirmed = confirm_trap(observed, 'test', 'a'*64, evidence)
        self.assertTrue(confirmed['detected'])
        self.assertEqual(confirmed['mechanism'], 'CFI')
        self.assertFalse(confirm_trap(observed, 'test', 'b'*64, evidence)['detected'])
        mismatch = {**observed, 'stderr': '[!] PC_OFFSET: 0x1238\n'}
        self.assertFalse(confirm_trap(mismatch, 'test', 'a'*64, evidence)['detected'])
        startup = {**observed, 'invalid_reason': 'initialization_or_runtime_failure'}
        self.assertFalse(confirm_trap(startup, 'test', 'a'*64, evidence)['detected'])


if __name__ == '__main__':
    unittest.main()
