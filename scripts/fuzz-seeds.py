"""Generate deterministic NON-SECRET test corpora; never use these keys for data."""
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "impl/python"))
import n2qc as q
import n2qc_fireline as fl
root = Path(__file__).resolve().parents[1] / "fuzz/corpus"
for name in ("frames", "n2qf", "fireline", "siv"):
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
print("Generated deterministic test corpora")
