"""
n2qc_modes — extended modes in pure Python, built ONLY on the native n2qc core
(seal / open / hash). No C library, no FFI. Byte-compatible with the C reference,
so a blob made here opens in the Go / Rust ports and vice versa.

Modes: envelope (+rotation), key-committing AEAD, convergent (dedup),
length-hiding, stego framing.
"""
import struct
import hmac
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
    if not hmac.compare_digest(_commit(key, sealed[:16]), kc):
        return None
    return n2qc.open(128, profile, key, nonce, ad, sealed)


# ---- convergent (dedup-friendly) encryption ----
def conv_seal(mk, content, profile=F):
    if len(mk) != 16:
        raise ValueError("convergent master key must be exactly 16 bytes")
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
    if buf is None or len(buf) < 4:
        return None
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
        if n2qc.open(128, S, key, nonce, LOG_AD, rec[8:]) is None:
            return False   # record does not authenticate
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
    if msg is None:
        return None
    opening = _frank_opening(key, nonce)
    if _frank_commit(opening, msg) != cf:
        return None
    return msg, cf, opening


def frank_report_verify(cf, opening, msg):
    return _frank_commit(opening, msg) == cf


# ---- seekable N2QF: build a container and decrypt one chunk ----
def n2qf_build(key, chunks, profile=S):
    return b"".join(n2qc._encrypt_chunks(128, profile, key, chunks))


def seek_chunk(key, buf, index):
    import io
    try:
        chunks = list(n2qc._decrypt_chunks(128, key, io.BytesIO(buf)))
        return chunks[index] if 0 <= index < len(chunks) else None
    except ValueError:
        return None


# ---- streaming AEAD (seq -> nonce, sliding replay window) ----
class StreamTx:
    def __init__(self, key, profile=F):
        self.key, self.p, self.seq = key, profile, 0

    def seal(self, aad, pt):
        nonce = struct.pack("<Q", self.seq) + b"\x00" * 8
        out = struct.pack("<Q", self.seq) + n2qc.seal(128, self.p, self.key, nonce, aad, pt)
        self.seq += 1
        return out


class StreamRx:
    def __init__(self, key, profile=F):
        self.key, self.p, self.max, self.win, self.started = key, profile, 0, 0, False

    def open(self, aad, pkt):
        if len(pkt) < 24:
            return None
        seq = struct.unpack("<Q", pkt[:8])[0]
        if self.started and seq <= self.max:
            diff = self.max - seq
            if diff >= 64 or (self.win >> diff) & 1:
                return None
        nonce = pkt[:8] + b"\x00" * 8
        pt = n2qc.open(128, self.p, self.key, nonce, aad, pkt[8:])
        if pt is None:
            return None   # forged: leave the replay window untouched
        if not self.started:
            self.max, self.win, self.started = seq, 1, True
        elif seq > self.max:
            shift = seq - self.max
            self.win = 1 if shift >= 64 else ((self.win << shift) | 1) & ((1 << 64) - 1)
            self.max = seq
        else:
            self.win |= 1 << (self.max - seq)
        return pt


# ---- forward-secret ratchet ----
def _rkdf(ck, dom):
    return n2qc.hash(128, S, bytes([dom]) + ck, 16)


class RatchetTx:
    def __init__(self, root):
        self.ck, self.seq = root, 0

    def seal(self, aad, pt):
        mk, ck2 = _rkdf(self.ck, 0x01), _rkdf(self.ck, 0x02)
        nonce = struct.pack("<Q", self.seq) + b"\x00" * 8
        out = struct.pack("<Q", self.seq) + n2qc.seal(128, F, mk, nonce, aad, pt)
        self.ck, self.seq = ck2, self.seq + 1
        return out


class RatchetRx:
    def __init__(self, root):
        self.ck, self.next, self.skip = root, 0, {}

    def open(self, aad, pkt):
        if len(pkt) < 24:
            return None
        seq = struct.unpack("<Q", pkt[:8])[0]
        nonce = pkt[:8] + b"\x00" * 8
        if seq < self.next:
            mk = self.skip.get(seq)
            if mk is None:
                return None
            pt = n2qc.open(128, F, mk, nonce, aad, pkt[8:])
            if pt is None:
                return None   # forged: keep the cached key
            del self.skip[seq]
            return pt
        if seq - self.next > 64:
            return None
        ck, skipped = self.ck, {}
        for i in range(self.next, seq):
            skipped[i] = _rkdf(ck, 0x01)
            ck = _rkdf(ck, 0x02)
        mk, cn = _rkdf(ck, 0x01), _rkdf(ck, 0x02)
        pt = n2qc.open(128, F, mk, nonce, aad, pkt[8:])
        if pt is None:
            return None   # forged: do NOT advance the chain (no DoS)
        self.skip.update(skipped)
        while len(self.skip) > 64:
            del self.skip[min(self.skip)]
        self.ck, self.next = cn, seq + 1
        return pt


# ---- format-preserving encryption (FF1 Feistel, PRF = blind_index) ----
# NOTE: uses the native blind_index MAC domain, so it is consistent across the
# Python/Go/Rust ports but NOT byte-identical to the C n2q_fpe.c (which uses a
# distinct MAC domain). Small domains (e.g. a 4-digit PIN) are tokenisation.
def _fpe_round(key, tw, i, n, m, bval):
    buf = bytes([i, n, m, len(tw)]) + tw + struct.pack(">Q", bval)
    mac = n2qc.blind_index(128, S, key, buf)
    mod, y = 10 ** m, 0
    for b in mac:
        y = (y * 256 + b) % mod
    return y


def _fpe_validate(key, tw, value):
    n2qc._validate(128, S, key)
    if not 2 <= len(value) <= 18 or not value.isascii() or not value.isdigit() or len(tw) > 255:
        raise ValueError("FPE requires 2–18 ASCII digits and a tweak of at most 255 bytes")


def fpe_encrypt(key, tw, s):
    _fpe_validate(key, tw, s)
    n = len(s)
    u, v = n // 2, n - n // 2
    a, b, al, bl = int(s[:u]), int(s[u:]), u, v
    for i in range(10):
        m = u if i % 2 == 0 else v
        c = (a + _fpe_round(key, tw, i, n, m, b)) % (10 ** m)
        a, al, b, bl = b, bl, c, m
    return str(a).zfill(al) + str(b).zfill(bl)


def fpe_decrypt(key, tw, s):
    _fpe_validate(key, tw, s)
    n = len(s)
    u, v = n // 2, n - n // 2
    a, b, al, bl = int(s[:u]), int(s[u:]), u, v
    for i in range(9, -1, -1):
        m = u if i % 2 == 0 else v
        c, b, bl = b, a, al
        p = 10 ** m
        a, al = (c - _fpe_round(key, tw, i, n, m, b) % p) % p, m
    return str(a).zfill(al) + str(b).zfill(bl)


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
    _tx, _rx = StreamTx(KEY), StreamRx(KEY)
    _sp = [_tx.seal(b"rtp", p) for p in [b"frame0", b"frame1 longer", b"f2"]]
    assert [_rx.open(b"rtp", p) for p in _sp] == [b"frame0", b"frame1 longer", b"f2"]
    _ROOT = bytes(0x40 + i for i in range(16))
    _rtx, _rrx = RatchetTx(_ROOT), RatchetRx(_ROOT)
    _rp = [_rtx.seal(b"hdr", p) for p in [b"r0", b"r1 data", b"r2!"]]
    assert [_rrx.open(b"hdr", p) for p in _rp] == [b"r0", b"r1 data", b"r2!"]
    _CARD, _TW = "4111111111111111", b"acct-42"
    _fct = fpe_encrypt(KEY, _TW, _CARD)
    assert len(_fct) == 16 and _fct.isdigit() and fpe_decrypt(KEY, _TW, _fct) == _CARD
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
        "strm0": _sp[0].hex(),
        "strm1": _sp[1].hex(),
        "strm2": _sp[2].hex(),
        "rtc0": _rp[0].hex(),
        "rtc1": _rp[1].hex(),
        "rtc2": _rp[2].hex(),
        "fpe_card": _CARD,
        "fpe_ct": _fct,
    }
    os.makedirs("/tmp/modes", exist_ok=True)
    with open("/tmp/modes/vectors.txt", "w") as fh:
        for k, v in vec.items():
            fh.write("%s=%s\n" % (k, v))
    print("wrote /tmp/modes/vectors.txt (%d vectors)" % len(vec))
