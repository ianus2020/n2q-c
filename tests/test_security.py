"""Regression cases for malformed inputs, whole-file authentication and atomic output."""
import base64
import io
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'impl/python'))
import n2qc as q
import n2qc_modes as modes

class Security(unittest.TestCase):
    def test_canonical_vectors(self):
        path = Path(__file__).resolve().parents[1] / 'impl/conformance/vectors.txt'
        vectors = dict(line.split(None,1) for line in path.read_text().splitlines() if line and not line.startswith('#'))
        for bits in (128,256):
            self.assertEqual(q.hash(bits,q.SECURE,b'').hex(),vectors['hash%d_secure_empty'%bits])
        self.assertEqual(q.seal(256,q.SECURE,bytes(range(32)),bytes([0xa5])*16,b'header',b'hello n2q-c').hex(),vectors['seal256_secure'])

    def test_parameters_fail_closed(self):
        for bits in (128, 256):
            key = bytes(bits // 8)
            for profile in (0, 12, -1, 17):
                with self.assertRaises(ValueError):
                    q.seal(bits, profile, key, bytes(16), b'', b'secret')
            for wrong in (b'', key[:-1], key+b'x'):
                with self.assertRaises(ValueError):
                    q.seal(bits, q.SECURE, wrong, bytes(16), b'', b'secret')
        self.assertEqual(q.hash(128, q.SECURE, b'', 0), b'')

    def test_strict_tokens(self):
        key = bytes(16)
        token = q.seal_token(128, q.SECURE, key, bytes(16), b'ad', b'hi')
        raw = bytearray(base64.urlsafe_b64decode(token[4:]+'='*(-len(token[4:])%4)))
        variants = ['', 'n', token+'\n', token+'=', 'xxxx'+token[4:]]
        for offset,value in [(0,2),(1,0x81),(1,2),(1,0x11)]:
            bad = bytearray(raw); bad[offset] = value
            variants.append('nqc.'+base64.urlsafe_b64encode(bad).rstrip(b'=').decode())
        for bad in variants:
            self.assertIsNone(q.open_token(128,key,b'ad',bad), bad)
        self.assertIsNone(q.open_token(128,key,b'wrong',token))
        self.assertEqual(q.open_token(128,key,b'ad',token),b'hi')

    def test_v2_authenticates_end_identity_and_framing(self):
        for bits in (128,256):
            for profile in (q.SECURE,q.FAST):
                key = bytes(bits//8)
                chunks = [b'first', b'second']
                buf = b''.join(q._encrypt_chunks(bits,profile,key,chunks))
                other = b''.join(q._encrypt_chunks(bits,profile,key,[b'other',b'second']))
                tag = bits//8
                boundary = 22+5+tag+len(chunks[0])
                cases = [buf[:22], buf[:boundary], buf[:-1], buf+b'x', buf[:22]+other[22:],
                         buf[:boundary]+other[boundary:], b'N2QF\1'+buf[5:]]
                for length in (0, tag-1, 65536+tag+1, 0xffffffff):
                    cases.append(buf[:23]+length.to_bytes(4,'little')+buf[27:])
                bad = bytearray(buf); bad[22] = 7; cases.append(bad)
                bad = bytearray(buf); bad[5] |= 0x80; cases.append(bad)
                for attack in cases:
                    with self.assertRaises(ValueError):
                        list(q._decrypt_chunks(bits,key,io.BytesIO(attack)))
                self.assertEqual(list(q._decrypt_chunks(bits,key,io.BytesIO(buf))),chunks)
                empty = b''.join(q._encrypt_chunks(bits,profile,key,[]))
                self.assertEqual(list(q._decrypt_chunks(bits,key,io.BytesIO(empty))),[])

    def test_output_is_preserved_and_temps_removed(self):
        with tempfile.TemporaryDirectory() as d:
            source,out = Path(d)/'bad',Path(d)/'out'
            source.write_bytes(b'N2QF\1\1');out.write_bytes(b'keep')
            with self.assertRaises(ValueError): q.decrypt_file(128,bytes(16),source,out)
            self.assertEqual(out.read_bytes(),b'keep')
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()),['bad','out'])
            source.write_bytes(b'hello');q.encrypt_file(128,q.SECURE,bytes(16),source,source)
            q.decrypt_file(128,bytes(16),source,source)
            self.assertEqual(source.read_bytes(),b'hello')

    def test_malformed_extended_inputs(self):
        for value in ('', '1', 'жж', '1a', '1234567890123456789'):
            with self.assertRaises(ValueError): modes.fpe_encrypt(bytes(16),b'',value)
            with self.assertRaises(ValueError): modes.fpe_decrypt(bytes(16),b'',value)
        self.assertIsNone(modes.StreamRx(bytes(16)).open(b'',b''))
        self.assertIsNone(modes.RatchetRx(bytes(16)).open(b'',b''))

    def test_seek_rejects_tampering_outside_selected_chunk(self):
        buf = modes.n2qf_build(bytes(16),[b'zero',b'one'])
        self.assertEqual(modes.seek_chunk(bytes(16),buf,1),b'one')
        bad = bytearray(buf);bad[28] ^= 1
        for attack in (buf[:-21],bad,b'N2QF\1\1',buf[:23]+b'\xff'*4):
            self.assertIsNone(modes.seek_chunk(bytes(16),attack,1))

if __name__=='__main__': unittest.main()
