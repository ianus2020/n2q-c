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


# ---- append-only, tamper-evident log (hash chain) ----
LOG_AD = b"n2q-log"


def log_genesis():
    return n2qc.hash(128, S, b"n2q-log-genesis", 32)


def log_append(head, seq, key, entry):
    nonce = struct.pack("<Q", seq) + b"\x00" * 8
    record = struct.pack("<Q", seq) + n2qc.seal(128, S, key, nonce, LOG_AD, entry)
    return record, n2qc.hash(128, S, head + record, 32)


def log_verify(key, records, expected_head):
    head = log_genesis()
    for i, rec in enumerate(records):
        if len(rec) < 8 + 16 or struct.unpack("<Q", rec[:8])[0] != i:
            return False
        nonce = rec[:8] + b"\x00" * 8
        try:
            n2qc.open(128, S, key, nonce, LOG_AD, rec[8:])
        except Exception:
            return False
        head = n2qc.hash(128, S, head + rec, 32)
    return head == expected_head


# ---- message franking (verifiable abuse reporting) ----
def _frank_opening(key, nonce):
    return n2qc.hash(128, S, bytes([0x08]) + key + nonce, 16)


def _frank_commit(opening, msg):
    return n2qc.hash(128, S, bytes([0x09]) + opening + msg, 32)


def frank_seal(key, nonce, msg):
    opening = _frank_opening(key, nonce)
    cf = _frank_commit(opening, msg)
    return cf + n2qc.seal(128, S, key, nonce, cf, msg)


def frank_open(key, nonce, token):
    cf, sealed = token[:32], token[32:]
    msg = n2qc.open(128, S, key, nonce, cf, sealed)
    opening = _frank_opening(key, nonce)
    if _frank_commit(opening, msg) != cf:
        return None
    return msg, cf, opening


def frank_report_verify(cf, opening, msg):
    return _frank_commit(opening, msg) == cf


# ---- seekable N2QF: build a container and decrypt one chunk ----
def n2qf_build(key, chunks, profile=F):
    suite = 0x01 | (0x20 if profile == F else 0)
    out = b"N2QF" + bytes([1, suite])
    for i, ch in enumerate(chunks):
        nonce = struct.pack("<Q", i) + b"\x00" * 8
        sealed = n2qc.seal(128, profile, key, nonce, b"", ch)
        out += struct.pack("<I", len(sealed)) + sealed
    return out


def seek_chunk(key, buf, index):
    if buf[:4] != b"N2QF":
        return None
    profile = F if (buf[5] & 0x20) else S
    p, i = 6, 0
    while p + 4 <= len(buf):
        (l,) = struct.unpack("<I", buf[p : p + 4])
        p += 4
        if i == index:
            nonce = struct.pack("<Q", index) + b"\x00" * 8
            return n2qc.open(128, profile, key, nonce, b"", buf[p : p + l])
        p += l
        i += 1
    return None


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
    entries = [b"login alice", b"config change", b"logout bob"]
    _head, _recs = log_genesis(), []
    for _i, _e in enumerate(entries):
        _r, _head = log_append(_head, _i, KEY, _e)
        _recs.append(_r)
    assert log_verify(KEY, _recs, _head)
    _bad = list(_recs)
    _bad[1] = _bad[1][:9] + bytes([_bad[1][9] ^ 1]) + _bad[1][10:]
    assert not log_verify(KEY, _bad, _head)
    _ftok = frank_seal(KEY, NONCE, b"the abusive message")
    _fmsg, _fcf, _fop = frank_open(KEY, NONCE, _ftok)
    assert _fmsg == b"the abusive message" and frank_report_verify(_fcf, _fop, _fmsg)
    _cont = n2qf_build(KEY, [b"chunk zero", b"chunk one data", b"third chunk!!"])
    assert seek_chunk(KEY, _cont, 1) == b"chunk one data"
    print("python n2qc_modes: round-trip ALL PASS")

    # emit shared vectors for the Go / Rust cross-check
    vec = {
        "envelope": wrap(KEK1, DEK).hex(),
        "committing": seal_committing(KEY, NONCE, b"ad", PT).hex(),
        "conv_dek": conv_seal(MK, CONTENT)[0].hex(),
        "conv_ct": conv_seal(MK, CONTENT)[1].hex(),
        "padded": seal_padded(KEY, NONCE, b"", PT).hex(),
        "stego": stego_seal(KEY, NONCE, b"", PT).hex(),
        "log0": _recs[0].hex(),
        "log1": _recs[1].hex(),
        "log2": _recs[2].hex(),
        "log_head": _head.hex(),
        "franking": _ftok.hex(),
        "seek": _cont.hex(),
    }
    os.makedirs("/tmp/modes", exist_ok=True)
    with open("/tmp/modes/vectors.txt", "w") as fh:
        for k, v in vec.items():
            fh.write("%s=%s\n" % (k, v))
    print("wrote /tmp/modes/vectors.txt (%d vectors)" % len(vec))
