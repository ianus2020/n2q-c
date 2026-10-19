"""FireLine framing regressions and deterministic mutation smoke (not a proof)."""
import random
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "impl/python"))
import n2qc_fireline as fl

class FireLineSecurity(unittest.TestCase):
    def setUp(self):
        self.me = {"id": b"node-001", "trunk": bytes(range(16))}
        self.other = {"id": b"node-002", "trunk": bytes(range(16, 32))}
        self.dek, self.nonce = bytes(reversed(range(16))), bytes(16)
    def parcel(self, fast=False, payload=b"payload"):
        return fl.seal_parcel([self.me, self.other], self.dek, self.nonce, b"ctx", payload, fast=fast)
    def test_round_trip_profiles_and_empty(self):
        for fast in (False, True):
            for payload in (b"", b"payload", "привет".encode()):
                packet = self.parcel(fast, payload)
                for who in (self.me, self.other):
                    self.assertEqual(fl.open_parcel(who, packet, b"ctx"), (fl.OK, payload))
                self.assertEqual(fl.open_parcel(self.me, packet, b"wrong"), (fl.AUTH, None))
    def test_truncation_and_trailers(self):
        packet = self.parcel()
        for end in range(len(packet)):
            self.assertNotEqual(fl.open_parcel(self.me, packet[:end], b"ctx")[0], fl.OK)
        for trailer in (b"\0", b"trailing"):
            self.assertEqual(fl.open_parcel(self.me, packet + trailer, b"ctx"), (fl.FORMAT, None))
    def test_headers_and_lengths(self):
        packet = self.parcel()
        for suite in (0, 2, 0x11, 0x41, 0x81, 0xff):
            bad = bytearray(packet); bad[5] = suite
            self.assertEqual(fl.open_parcel(self.me, bad, b"ctx"), (fl.FORMAT, None))
        for count in (0, 33, 65535):
            bad = bytearray(packet); bad[6:8] = struct.pack("<H", count)
            self.assertEqual(fl.open_parcel(self.me, bad, b"ctx"), (fl.FORMAT, None))
        hlen = fl._header_len(2)
        for length in (0, 15, 16, 24, 0xffffffff):
            bad = bytearray(packet); bad[hlen+16:hlen+20] = struct.pack("<I", length)
            self.assertEqual(fl.open_parcel(self.me, bad, b"ctx"), (fl.FORMAT, None))
        bad = bytearray(packet); bad[48:56] = bad[8:16]
        self.assertEqual(fl.open_parcel(self.me, bad, b"ctx"), (fl.FORMAT, None))
    def test_invalid_sender_and_recipient(self):
        for peers in ([], [self.me]*2, [self.me]*33, [{"id": b"x", "trunk": bytes(16)}]):
            with self.assertRaises(ValueError):
                fl.seal_parcel(peers, self.dek, self.nonce, b"", b"x")
        self.assertEqual(fl.open_parcel({}, self.parcel(), b"ctx"), (fl.ARG, None))
        for flag in (0, 1, "fast"):
            with self.assertRaises(ValueError):
                fl.seal_parcel([self.me], self.dek, self.nonce, b"", b"x", fast=flag)
    def test_deterministic_mutation_smoke(self):
        packet = self.parcel()
        for offset in range(len(packet)):
            bad = bytearray(packet); bad[offset] ^= 1
            self.assertNotEqual(fl.open_parcel(self.me, bad, b"ctx")[0], fl.OK)
        rng = random.Random(20261019)
        for _ in range(300):
            malformed = bytes(rng.randrange(256) for _ in range(rng.randrange(200)))
            self.assertNotEqual(fl.open_parcel(self.me, malformed, b"ctx")[0], fl.OK)

if __name__ == "__main__":
    unittest.main()
