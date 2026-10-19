"""
Audit status: see STATUS.md in the repository root.
N2Q reference implementation (Python).

A pure-Python port of the N2Q cipher: the QP permutation, the N2Q-128 / N2Q-256
modes (hash, SIV-AEAD, streaming AEAD, blind index), the Secure/Fast profiles,
the self-describing token frame, and a chunked file helper. Byte-exact with the
Rust and C references (see self_test()).

"""
# ---- fixed constants (Appendix A) ----
SBOX = [
    0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
    0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09,
]
ROTS = {
    64: [(38, 55), (1, 23), (23, 36), (16, 14), (20, 46)],
    128: [(75, 7), (89, 21), (56, 111), (30, 54), (25, 52)],
}
RC = [0x15, 0xe3, 0x2d, 0xa2, 0x5e, 0x5c, 0xab, 0xae,
      0xc8, 0x9b, 0xb6, 0xb3, 0xeb, 0xbf, 0xd9, 0xf2]

SECURE, FAST = 16, 8
DOM_HASH, DOM_MAC, DOM_ENC, DOM_BI, DOM_STREAM = 1, 2, 3, 4, 5

def _validate(bits, profile, key=None, nonce=None):
    if bits not in (128, 256) or profile not in (SECURE, FAST):
        raise ValueError("unsupported size or profile")
    if key is not None and len(key) != bits // 8:
        raise ValueError("wrong key length")
    if nonce is not None and len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")

# Public ANF coefficients: no state-dependent S-box table access.
def _anf():
    out = []
    for k in range(5):
        a = [(v >> k) & 1 for v in SBOX]
        for bit in (1, 2, 4, 8, 16):
            for m in range(32):
                if m & bit:
                    a[m] ^= a[m ^ bit]
        out.append([m for m in range(32) if a[m]])
    return out
ANF = _anf()

def _rotr(x, r, w):
    mask = (1 << w) - 1
    r %= w
    return ((x >> r) | (x << (w - r))) & mask

def permute(s, rounds, w):
    """QP permutation on 5 lanes of w bits, `rounds` rounds. Mutates and returns s."""
    mask = (1 << w) - 1
    rots = ROTS[w]
    for i in range(rounds):
        s[2] ^= RC[i]                                   # pC
        out = [0, 0, 0, 0, 0]                           # pS (S-box per column)
        for k, monomials in enumerate(ANF):
            for m in monomials:
                term = mask
                for lane in range(5):
                    if m & (1 << lane):
                        term &= s[lane]
                out[k] ^= term
        s = out
        for k in range(5):                              # pL
            s[k] ^= _rotr(s[k], rots[k][0], w) ^ _rotr(s[k], rots[k][1], w)
            s[k] &= mask
    return s

# ---- sponge helpers, generic over byte-rate B (8 for QP-320, 16 for QP-640) ----
def _rd(b):
    return int.from_bytes(b, "little")

def _wr(x, B):
    return x.to_bytes(B, "little")

def _pad(msg, rate):
    m = bytearray(msg) + b"\x01"
    while len(m) % rate:
        m.append(0)
    m[-1] |= 0x80
    return bytes(m)

def _absorb(s, msg, B, w, r):
    padded = _pad(msg, B)
    for o in range(0, len(padded), B):
        s[0] ^= _rd(padded[o:o + B])
        s = permute(s, r, w)
    return s

def _squeeze(s, n, B, w, r):
    out = bytearray()
    while len(out) < n:
        out += _wr(s[0] & ((1 << w) - 1), B)
        s = permute(s, r, w)
    return bytes(out[:n])

def _params(bits):
    return (64, 8) if bits == 128 else (128, 16)

def hash(bits, r, msg, outlen=None):
    w, B = _params(bits)
    _validate(bits, r)
    outlen = (32 if bits == 128 else 64) if outlen is None else outlen
    if not isinstance(outlen, int) or outlen < 0:
        raise ValueError("invalid output length")
    s = [0, 0, 0, 0, 0]
    s[4] ^= DOM_HASH
    s = permute(s, r, w)
    s = _absorb(s, msg, B, w, r)
    return _squeeze(s, outlen, B, w, r)

def _mac(bits, r, key, data, dom):
    _validate(bits, r, key)
    w, B = _params(bits)
    s = [0, 0, 0, 0, 0]
    s[1] = _rd(key[0:B]); s[2] = _rd(key[B:2 * B]); s[4] ^= dom
    s = permute(s, r, w)
    s = _absorb(s, data, B, w, r)
    return _squeeze(s, 2 * B, B, w, r)

def _keystream(bits, r, key, v, n):
    _validate(bits, r, key)
    w, B = _params(bits)
    s = [0, 0, 0, 0, 0]
    s[1] = _rd(key[0:B]); s[2] = _rd(key[B:2 * B])
    s[3] = _rd(v[0:B]); s[4] = _rd(v[B:2 * B]) ^ DOM_ENC
    s = permute(s, r, w)
    return _squeeze(s, n, B, w, r)

def _siv_input(nonce, ad, pt):
    return nonce + len(ad).to_bytes(8, "little") + ad + len(pt).to_bytes(8, "little") + pt

def seal(bits, profile, key, nonce, ad, pt):
    _validate(bits, profile, key, nonce)
    v = _mac(bits, profile, key, _siv_input(nonce, ad, pt), DOM_MAC)
    ks = _keystream(bits, profile, key, v, len(pt))
    return v + bytes(a ^ b for a, b in zip(pt, ks))

def open(bits, profile, key, nonce, ad, sealed):
    _validate(bits, profile, key, nonce)
    _, B = _params(bits)
    tag = 2 * B
    if len(sealed) < tag:
        return None
    v, ct = sealed[:tag], sealed[tag:]
    ks = _keystream(bits, profile, key, v, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    if _ct_eq(v, _mac(bits, profile, key, _siv_input(nonce, ad, pt), DOM_MAC)):
        return pt
    return None

def blind_index(bits, profile, key, value):
    return _mac(bits, profile, key, value, DOM_BI)

def _ct_eq(a, b):
    import hmac
    return hmac.compare_digest(a, b)

# ---- self-describing token frame (base64url) ----
import base64

def encode_token(suite, nonce, sealed):
    raw = bytes([1, suite]) + nonce + sealed
    return "nqc." + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def decode_token(token):
    import re
    if not isinstance(token, str) or len(token) > 24 * 1024 * 1024 or not re.fullmatch(r"nqc\.[A-Za-z0-9_-]+", token):
        raise ValueError("invalid token")
    body = token[4:]
    raw = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != body:
        raise ValueError("noncanonical token")
    if len(raw) < 18 or raw[0] != 1 or raw[1] not in (1, 2, 0x21, 0x22, 0x11, 0x12, 0x31, 0x32):
        raise ValueError("unsupported frame")
    return raw[1], raw[2:18], raw[18:]

def seal_token(bits, profile, key, nonce, ad, pt):
    suite = (0x01 if bits == 128 else 0x02) | (0x20 if profile == FAST else 0)
    return encode_token(suite, nonce, seal(bits, profile, key, nonce, ad, pt))

def open_token(bits, key, ad, token):
    try:
        suite, nonce, sealed = decode_token(token)
        if suite not in ((1, 0x21) if bits == 128 else (2, 0x22)):
            return None
        return open(bits, FAST if suite & 0x20 else SECURE, key, nonce, ad, sealed)
    except (ValueError, TypeError):
        return None

# N2QF v2: header + bounded records + authenticated final record. See docs/n2qf.md.
import builtins
import os
import tempfile
builtins_open = builtins.open
CHUNK = 65536

def _file_ad(header, kind, index, total):
    return b"N2QF/v2" + header + bytes([kind]) + index.to_bytes(8, "little") + total.to_bytes(8, "little")

def _encrypt_chunks(bits, profile, key, chunks):
    _validate(bits, profile, key)
    header = b"N2QF" + bytes([2, (1 if bits == 128 else 2) | (0x20 if profile == FAST else 0)]) + os.urandom(16)
    yield header
    index = total = 0
    for data in chunks:
        if not 0 < len(data) <= CHUNK:
            raise ValueError("invalid chunk length")
        sealed = seal(bits, profile, key, index.to_bytes(16, "little"), _file_ad(header, 0, index, total), data)
        yield b"\0" + len(sealed).to_bytes(4, "little") + sealed
        total += len(data)
        index += 1
    sealed = seal(bits, profile, key, index.to_bytes(16, "little"), _file_ad(header, 1, index, total), b"")
    yield b"\1" + len(sealed).to_bytes(4, "little") + sealed

def _decrypt_chunks(bits, key, fi):
    header = fi.read(22)
    suites = (1, 0x21) if bits == 128 else (2, 0x22) if bits == 256 else ()
    if len(header) != 22 or header[:5] != b"N2QF\2" or header[5] not in suites:
        raise ValueError("unsupported N2QF header (v2 required)")
    profile = FAST if header[5] & 0x20 else SECURE
    _validate(bits, profile, key)
    tag = bits // 8
    index = total = 0
    while True:
        record = fi.read(5)
        if len(record) != 5:
            raise ValueError("missing final record")
        kind, length = record[0], int.from_bytes(record[1:], "little")
        if not ((kind == 0 and tag < length <= CHUNK + tag) or (kind == 1 and length == tag)):
            raise ValueError("invalid record length/type")
        sealed = fi.read(length)
        if len(sealed) != length:
            raise ValueError("truncated record")
        pt = open(bits, profile, key, index.to_bytes(16, "little"), _file_ad(header, kind, index, total), sealed)
        if pt is None:
            raise ValueError("authentication failed")
        if kind == 1:
            if fi.read(1):
                raise ValueError("trailing data")
            return
        yield pt
        index += 1
        total += len(pt)

def _atomic_file(out_path, writer):
    out_path = os.path.abspath(out_path)
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(out_path), prefix=".n2q-", delete=False) as fo:
            name = fo.name
            writer(fo)
            fo.flush()
            os.fsync(fo.fileno())
        os.replace(name, out_path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)

def encrypt_file(bits, profile, key, in_path, out_path, chunk=CHUNK):
    _validate(bits, profile, key)
    if not 0 < chunk <= CHUNK:
        raise ValueError("chunk must be between 1 and 65536")
    with builtins_open(in_path, "rb") as fi:
        def write(fo):
            for record in _encrypt_chunks(bits, profile, key, iter(lambda: fi.read(chunk), b"")):
                fo.write(record)
        _atomic_file(out_path, write)

def decrypt_file(bits, key, in_path, out_path):
    with builtins_open(in_path, "rb") as fi:
        def write(fo):
            for pt in _decrypt_chunks(bits, key, fi):
                fo.write(pt)
        _atomic_file(out_path, write)
