"""
n2qc_modes — extended modes in pure Python, built ONLY on the native n2qc core
(seal / open / hash). No C library, no FFI. Byte-compatible with the C reference,
so a blob made here opens in the Go / Rust ports and vice versa.

Modes: envelope (+rotation), key-committing AEAD, convergent (dedup),
length-hiding, stego framing.
"""
import struct
import n2qc

S, F = n2qc.SECURE, n2qc.FAST
ZERO = b"\x00" * 16
ENV_AD, CONV_AD = b"n2q-envelope-v1", b"n2q-conv"


# ---- envelope encryption + key rotation ----
def wrap(kek, dek):
    return n2qc.seal(128, S, kek, ZERO, ENV_AD, dek)


def unwrap(kek, blob):
    return n2qc.open(128, S, kek, ZERO, ENV_AD, blob)


def rewrap(old_kek, new_kek, blob):
    return wrap(new_kek, unwrap(old_kek, blob))


# ---- key-committing AEAD:  token = KC(32) | sealed ----
def _commit(key, tag):
    return n2qc.hash(128, S, bytes([0x07]) + key + tag, 32)


def seal_committing(key, nonce, ad, pt, profile=F):
    sealed = n2qc.seal(128, profile, key, nonce, ad, pt)
    return _commit(key, sealed[:16]) + sealed


def open_committing(key, nonce, ad, token, profile=F):
    kc, sealed = token[:32], token[32:]
    if _commit(key, sealed[:16]) != kc:
        return None
    return n2qc.open(128, profile, key, nonce, ad, sealed)


# ---- convergent (dedup-friendly) encryption ----
def conv_seal(mk, content, profile=F):
    dek = n2qc.hash(128, S, mk + content, 16)
    return dek, n2qc.seal(128, profile, dek, ZERO, CONV_AD, content)


def conv_open(dek, ct, profile=F):
    return n2qc.open(128, profile, dek, ZERO, CONV_AD, ct)


# ---- length-hiding:  padded = le32(len) | pt | zeros to bucket ----
def seal_padded(key, nonce, ad, pt, profile=F, bucket=256):
    need = 4 + len(pt)
    padded = ((need + bucket - 1) // bucket) * bucket
    buf = struct.pack("<I", len(pt)) + pt + b"\x00" * (padded - need)
    return n2qc.seal(128, profile, key, nonce, ad, buf)


def open_padded(key, nonce, ad, token, profile=F):
    buf = n2qc.open(128, profile, key, nonce, ad, token)
    n = struct.unpack("<I", buf[:4])[0]
    return buf[4 : 4 + n]


# ---- stego framing:  out = nonce(16) | sealed  (no header) ----
def stego_seal(key, nonce, ad, pt, profile=F):
    return nonce + n2qc.seal(128, profile, key, nonce, ad, pt)


def stego_open(key, ad, blob, profile=F):
    return n2qc.open(128, profile, key, blob[:16], ad, blob[16:])


# ---- fixed test inputs (shared by the Go / Rust cross-check) ----
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
NONCE = b"\xa5" * 16
KEK1 = bytes(range(0x10, 0x20))
KEK2 = bytes(0xF0 - i for i in range(16))
DEK = bytes((0x55 ^ (i * 7)) & 0xFF for i in range(16))
MK = b"\x11" * 16
PT = b"hello n2q-c modes"
CONTENT = b"the same backup blob"

if __name__ == "__main__":
    import os

    # self round-trip
    assert unwrap(KEK1, wrap(KEK1, DEK)) == DEK
    assert unwrap(KEK2, rewrap(KEK1, KEK2, wrap(KEK1, DEK))) == DEK
    assert open_committing(KEY, NONCE, b"ad", seal_committing(KEY, NONCE, b"ad", PT)) == PT
    d, c = conv_seal(MK, CONTENT)
    assert conv_open(d, c) == CONTENT
    assert open_padded(KEY, NONCE, b"", seal_padded(KEY, NONCE, b"", PT)) == PT
    assert stego_open(KEY, b"", stego_seal(KEY, NONCE, b"", PT)) == PT
    print("python n2qc_modes: round-trip ALL PASS")

    # emit shared vectors for the Go / Rust cross-check
    vec = {
        "envelope": wrap(KEK1, DEK).hex(),
        "committing": seal_committing(KEY, NONCE, b"ad", PT).hex(),
        "conv_dek": conv_seal(MK, CONTENT)[0].hex(),
        "conv_ct": conv_seal(MK, CONTENT)[1].hex(),
        "padded": seal_padded(KEY, NONCE, b"", PT).hex(),
        "stego": stego_seal(KEY, NONCE, b"", PT).hex(),
    }
    os.makedirs("/tmp/modes", exist_ok=True)
    with open("/tmp/modes/vectors.txt", "w") as fh:
        for k, v in vec.items():
            fh.write("%s=%s\n" % (k, v))
    print("wrote /tmp/modes/vectors.txt (%d vectors)" % len(vec))
