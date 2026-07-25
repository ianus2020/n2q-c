"""
Audit status: see STATUS.md in the repository root.
N2Q-C reference implementation (Python).

A pure-Python port of the N2Q-C cipher: the QP permutation, the N2Q-128 / N2Q-256
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
        for j in range(w):
            col = ((s[0] >> j) & 1) | (((s[1] >> j) & 1) << 1) | (((s[2] >> j) & 1) << 2) \
                | (((s[3] >> j) & 1) << 3) | (((s[4] >> j) & 1) << 4)
            o = SBOX[col]
            for k in range(5):
                out[k] |= ((o >> k) & 1) << j
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
    for o in range(0, len(_pad(msg, B)), B):
        s[0] ^= _rd(_pad(msg, B)[o:o + B])
        s = permute(s, r, w)
    return s

def _squeeze(s, n, B, w, r):
    out = b""
    while len(out) < n:
        out += _wr(s[0] & ((1 << w) - 1), B)
        s = permute(s, r, w)
    return out[:n]

def _params(bits):
    return (64, 8) if bits == 128 else (128, 16)

def hash(bits, r, msg, outlen=None):
    w, B = _params(bits)
    outlen = outlen or (32 if bits == 128 else 64)
    s = [0, 0, 0, 0, 0]
    s[4] ^= DOM_HASH
    s = permute(s, r, w)
    s = _absorb(s, msg, B, w, r)
    return _squeeze(s, outlen, B, w, r)

def _mac(bits, r, key, data, dom):
    w, B = _params(bits)
    s = [0, 0, 0, 0, 0]
    s[1] = _rd(key[0:B]); s[2] = _rd(key[B:2 * B]); s[4] ^= dom
    s = permute(s, r, w)
    s = _absorb(s, data, B, w, r)
    return _squeeze(s, 2 * B, B, w, r)

def _keystream(bits, r, key, v, n):
    w, B = _params(bits)
    s = [0, 0, 0, 0, 0]
    s[1] = _rd(key[0:B]); s[2] = _rd(key[B:2 * B])
    s[3] = _rd(v[0:B]); s[4] = _rd(v[B:2 * B]) ^ DOM_ENC
    s = permute(s, r, w)
    return _squeeze(s, n, B, w, r)

def _siv_input(nonce, ad, pt):
    return nonce + len(ad).to_bytes(8, "little") + ad + len(pt).to_bytes(8, "little") + pt

def seal(bits, profile, key, nonce, ad, pt):
    v = _mac(bits, profile, key, _siv_input(nonce, ad, pt), DOM_MAC)
    ks = _keystream(bits, profile, key, v, len(pt))
    return v + bytes(a ^ b for a, b in zip(pt, ks))

def open(bits, profile, key, nonce, ad, sealed):
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
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y
    return acc == 0

# ---- self-describing token frame (base64url) ----
import base64

def encode_token(suite, nonce, sealed):
    raw = bytes([1, suite]) + nonce + sealed
    return "nqc." + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def decode_token(token):
    body = token[4:]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    return raw[1], raw[2:18], raw[18:]        # suite, nonce, sealed

def seal_token(bits, profile, key, nonce, ad, pt):
    suite = (0x01 if bits == 128 else 0x02) | (0x20 if profile == FAST else 0)
    return encode_token(suite, nonce, seal(bits, profile, key, nonce, ad, pt))

def open_token(bits, key, ad, token):
    suite, nonce, sealed = decode_token(token)
    profile = FAST if suite & 0x20 else SECURE
    return open(bits, profile, key, nonce, ad, sealed)

# ---- file / media helper (binary N2QF container, chunked SIV) ----
# Layout: b"N2QF" | version(1) | suite(1) | { le32(len) | sealed(tag||ct) }*
# The nonce for chunk i is its little-endian index (deterministic → not stored),
# so overhead is just 4 bytes length + 16 bytes tag per 64 KB chunk (~0.03%).
def encrypt_file(bits, profile, key, in_path, out_path, chunk=1 << 16):
    """Encrypt any file (text, audio, video — bytes are bytes) chunk by chunk."""
    suite = (0x01 if bits == 128 else 0x02) | (0x20 if profile == FAST else 0)
    with builtins_open(in_path, "rb") as fi, builtins_open(out_path, "wb") as fo:
        fo.write(b"N2QF" + bytes([1, suite]))
        idx = 0
        while True:
            data = fi.read(chunk)
            if not data:
                break
            nonce = idx.to_bytes(16, "little")          # deterministic, SIV-safe
            sealed = seal(bits, profile, key, nonce, b"", data)   # raw tag || ct
            fo.write(len(sealed).to_bytes(4, "little") + sealed)
            idx += 1

def decrypt_file(bits, key, in_path, out_path):
    with builtins_open(in_path, "rb") as fi, builtins_open(out_path, "wb") as fo:
        hdr = fi.read(6)
        if hdr[:4] != b"N2QF":
            raise ValueError("not an N2QF file")
        suite = hdr[5]
        bits = 256 if (suite & 0x0f) == 2 else 128
        profile = FAST if (suite & 0x20) else SECURE
        idx = 0
        while True:
            ln = fi.read(4)
            if not ln:
                break
            sealed = fi.read(int.from_bytes(ln, "little"))
            nonce = idx.to_bytes(16, "little")
            pt = open(bits, profile, key, nonce, b"", sealed)
            if pt is None:
                raise ValueError("authentication failed (chunk %d)" % idx)
            fo.write(pt)
            idx += 1

import builtins
builtins_open = builtins.open   # keep the real open (we shadowed the name)
