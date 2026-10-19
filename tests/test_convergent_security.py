import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'impl/python'))
import n2qc as q
import n2qc_modes as m


class ConvergentSecurity(unittest.TestCase):
    def test_old_ambiguous_boundary_is_rejected(self):
        key, content = b'A' * 16, b'Bpayload'
        # Historical derivation collided for these different tuples.
        self.assertEqual(key + content, (key + b'B') + b'payload')
        for wrong in (b'', key[:-1], key + b'B', bytes(32)):
            with self.assertRaises(ValueError):
                m.conv_seal(wrong, b'payload')
        for profile in (q.SECURE, q.FAST):
            dek, ct = m.conv_seal(key, content, profile)
            self.assertEqual(dek, q.hash(128, q.SECURE, key + content, 16))
            self.assertEqual(m.conv_open(dek, ct, profile), content)
            self.assertEqual(m.conv_seal(key, content, profile), (dek, ct))

    def test_committing_every_commitment_bit(self):
        key, nonce = bytes(16), bytes(16)
        ct = m.seal_committing(key, nonce, b'ad', b'payload')
        self.assertEqual(m.open_committing(key, nonce, b'ad', ct), b'payload')
        for bit in range(256):
            bad = bytearray(ct)
            bad[bit // 8] ^= 1 << (bit % 8)
            self.assertIsNone(m.open_committing(key, nonce, b'ad', bytes(bad)))
