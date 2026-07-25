"""
Audit status: see STATUS.md in the repository root.
N2Q-FireLine — federation between independent N2Q nodes, in pure Python.

Built only on the native n2qc core (seal / open / hash) — no C library, no FFI —
and byte-compatible with impl/c/n2q_fireline.c: a parcel built by either side
opens on the other.

Wire format (see the C reference for the rationale):

    parcel = "N2QL" | ver | suite | le16(n)
             { rcpt_id(8) | wrap(trunk_i, DEK)(32) } * n          <- header
             nonce(16) | le32(len) | sealed(DEK, hdrhash|ad, payload)

    wrap AD    = "n2q-fireline-v1" | rcpt_id
    payload AD = H(0x0a | header) | caller AD

No master/trunk key ever travels: only a wrap of a single-use data key.
"""
import struct

import n2qc

S, F = n2qc.SECURE, n2qc.FAST
RID, WRAP = 8, 32
FL_AD = b"n2q-fireline-v1"
ZERO = b"\x00" * 16

OK, FORMAT, NOT_FOR_ME, AUTH = 0, -1, -2, -3

def peer(name, seed):
    """A partner: public routing label + the pairwise trunk key (never sent)."""
    rid = name.encode()[:RID].ljust(RID, b"\x00")
    trunk = bytes((seed + i * 7) & 0xFF for i in range(16))
    return {"id": rid, "trunk": trunk}

def _wrap(trunk, rid, dek):
    return n2qc.seal(128, S, trunk, ZERO, FL_AD + rid, dek)

def _unwrap(trunk, rid, wrap):
    return n2qc.open(128, S, trunk, ZERO, FL_AD + rid, wrap)

def _header_len(n):
    return 4 + 1 + 1 + 2 + n * (RID + WRAP)

def _payload_ad(header, ad):
    return n2qc.hash(128, S, b"\x0a" + header, 32) + (ad or b"")

def seal_parcel(rcpts, dek, nonce, ad, pt, fast=True):
    """Build a parcel for `rcpts` (list of peer dicts). Returns bytes."""
    suite = 0x01 | (0x20 if fast else 0)
    hdr = b"N2QL" + bytes([1, suite]) + struct.pack("<H", len(rcpts))
    for r in rcpts:
        hdr += r["id"] + _wrap(r["trunk"], r["id"], dek)
    body = n2qc.seal(128, F if fast else S, dek, nonce, _payload_ad(hdr, ad), pt)
    return hdr + nonce + struct.pack("<I", len(body)) + body

def open_parcel(me, parcel, ad):
    """Open a parcel addressed to `me`. Returns (code, payload_or_None)."""
    if len(parcel) < 8 or parcel[:4] != b"N2QL" or parcel[4] != 1:
        return FORMAT, None
    if parcel[5] & 0x0F != 0x01:
        return FORMAT, None
    fast = bool(parcel[5] & 0x20)
    (n,) = struct.unpack("<H", parcel[6:8])
    hlen = _header_len(n)
    if len(parcel) < hlen + 20:
        return FORMAT, None

    dek = None
    for i in range(n):
        off = 8 + i * (RID + WRAP)
        rid, wrap = parcel[off : off + RID], parcel[off + RID : off + RID + WRAP]
        if rid != me["id"]:
            continue
        dek = _unwrap(me["trunk"], rid, wrap)
        if dek is None:
            return AUTH, None  # our block, but it does not authenticate
        break
    if dek is None:
        return NOT_FOR_ME, None

    nonce = parcel[hlen : hlen + 16]
    (blen,) = struct.unpack("<I", parcel[hlen + 16 : hlen + 20])
    body = parcel[hlen + 20 : hlen + 20 + blen]
    if len(body) != blen:
        return FORMAT, None
    pt = n2qc.open(128, F if fast else S, dek, nonce, _payload_ad(parcel[:hlen], ad), body)
    return (OK, pt) if pt is not None else (AUTH, None)

if __name__ == "__main__":
    import os

    fails = 0

    def ex(name, cond):
        global fails
        print("  [%s] %s" % ("PASS" if cond else "FAIL", name))
        if not cond:
            fails += 1

    print("N2Q-FireLine (Python) self-test")
    B, C, D = peer("bank-b", 0x11), peer("corp-c", 0x55), peer("other-d", 0x99)
    dek = bytes(0xA0 + i for i in range(16))
    nonce = bytes(0x30 + i for i in range(16))
    msg = b"quarterly settlement report"

    parcel = seal_parcel([B, C], dek, nonce, b"ctx", msg)
    ex("B reads the payload", open_parcel(B, parcel, b"ctx") == (OK, msg))
    ex("C reads the same parcel", open_parcel(C, parcel, b"ctx") == (OK, msg))
    ex("outsider D cannot read it", open_parcel(D, parcel, b"ctx")[0] == NOT_FOR_ME)
    ex("wrong context rejected", open_parcel(B, parcel, b"other")[0] == AUTH)

    tampered = bytearray(parcel)
    tampered[-1] ^= 0x40
    ex("tampered payload rejected", open_parcel(B, bytes(tampered), b"ctx")[0] == AUTH)

    edited = bytearray(parcel)
    edited[8 + RID + WRAP + 3] ^= 0x40  # touch C's block
    ex("editing the header invalidates it", open_parcel(B, bytes(edited), b"ctx")[0] == AUTH)

    ex("no trunk key appears in the parcel",
       B["trunk"] not in parcel and C["trunk"] not in parcel and dek not in parcel)

    # cross-check against the C reference, if it ran first
    path = "/tmp/fireline_parcel.bin"
    if os.path.exists(path):
        cparcel = open(path, "rb").read()
        ex("byte-identical to the C reference parcel", seal_parcel([B, C], dek, nonce, b"ctx", msg) == cparcel)
        ex("opens the C-built parcel (C -> Python)", open_parcel(B, cparcel, b"ctx") == (OK, msg))
    else:
        print("  (skipped C cross-check: %s not present)" % path)

    print("ALL PASS (0 failures)" if fails == 0 else "FAILURES (%d)" % fails)
    raise SystemExit(1 if fails else 0)
