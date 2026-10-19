"""Generate deterministic NON-SECRET test corpora; never use these keys for data."""
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "impl/python"))
import n2qc as q
import n2qc_fireline as fl
root = Path(__file__).resolve().parents[1] / "fuzz/corpus"
for name in ("frames", "n2qf", "fireline", "siv", "modes_roundtrip", "convergent"):
    (root/name).mkdir(parents=True, exist_ok=True)
peer = {"id": bytes(8), "trunk": bytes(16)}
for profile in (q.SECURE, q.FAST):
    fast = profile == q.FAST
    for bits in (128, 256):
        token = q.seal_token(bits, profile, bytes(bits//8), bytes(16), b"ctx", b"sample")
        (root/"frames"/("%d-%d"%(bits,profile))).write_text(token)
        sealed = q.seal(bits, profile, bytes(bits//8), bytes(16), b"ctx", b"sample")
        flag = (1 if bits==256 else 0) | (2 if fast else 0)
        (root/"siv"/("%d-%d"%(bits,profile))).write_bytes(bytes([flag])+sealed)
    for label, chunks in (("empty", []), ("chunks", [b"first", b"second"])):
        with patch("n2qc.os.urandom", return_value=bytes(range(16))):
            container = b"".join(q._encrypt_chunks(128, profile, bytes(16), chunks))
        (root/"n2qf"/("%s-%d"%(label,profile))).write_bytes(container)
    parcel = fl.seal_parcel([peer],bytes(16),bytes(16),b"ctx",b"sample",fast=fast)
    (root/"fireline"/str(profile)).write_bytes(parcel)
(root/"frames"/"short").write_text("nqc.A")
(root/"n2qf"/"huge-length").write_bytes(b"N2QF\x02\x01"+bytes(16)+b"\x00"+b"\xff"*4)
(root/"fireline"/"short").write_bytes(b"N2QL\x01\x01\xff\xff")
# These targets generate authenticated records inside the harness on every
# mutation, so successful verification and logical buffer capacities are covered.
for size in (0,1,15,16,17,31,32,33,255,256,257,2048,4046):
    message=bytes(i%251 for i in range(size))
    for flags in range(8):  # both widths, both profiles, SIV and stream
        (root/"modes_roundtrip"/('%d-%d'%(flags,size))).write_bytes(bytes([flags,0])+bytes(48)+message)
    for fast in (0,1):
        (root/"convergent"/('%d-%d'%(fast,size))).write_bytes(bytes([fast,size%256])+bytes(16)+message)
    if size <= 3983:
        for flags in range(8):
            (root/"modes_roundtrip"/('aad-%d-%d'%(flags,size))).write_bytes(bytes([flags,63])+bytes(48)+bytes(range(63))+message)
print("Generated deterministic test corpora")
