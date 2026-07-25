# N2Q-FireLine — federation between independent nodes

*Stage 1 of [federation.md](federation.md), implemented.*

Every organisation runs its own N2Q node with its own master keys, and nobody
will hand those to a partner. **FireLine** lets nodes exchange data so that **no
master key ever leaves its node** — only a wrap of a single-use data key travels.

## How it works

Each pair of partners establishes one long-term **trunk key** once, out of band
(QR code at a meeting, paper, courier, or an existing secure channel). After that
every parcel carries a fresh data key (DEK), wrapped once per recipient:

```
parcel = "N2QL" | ver | suite | le16(n)
         { rcpt_id(8) | wrap(trunk_i, DEK)(32) } * n          ← header
         nonce(16) | le32(len) | sealed(DEK, hdrhash|ad, payload)

wrap AD    = "n2q-fireline-v1" | rcpt_id     ← binds a wrap to ONE recipient
payload AD = H(0x0a | header) | caller AD    ← binds the payload to the header
```

The bulk payload is encrypted **once**, no matter how many recipients — each
extra recipient costs only 40 bytes (8-byte routing label + 32-byte wrap).

## Verified properties

The self-tests (C and Python) exercise each of these:

| Property | Test result |
|---|---|
| Two recipients read the same parcel | ✅ |
| An outsider holding the parcel learns nothing | ✅ |
| A recipient **cannot** use another recipient's wrap (rcpt_id is bound in) | ✅ |
| Editing any recipient block invalidates the payload (header is bound in) | ✅ |
| Tampered payload / wrong context rejected | ✅ |
| Revocation: next parcel with a fresh DEK and no wrap → the ex-partner is locked out | ✅ |
| **No trunk key — nor the raw data key — appears anywhere in the parcel** | ✅ |

## Implementations

| Port | File | Status |
|---|---|---|
| C reference | [`impl/c/n2q_fireline.c`](../impl/c/n2q_fireline.c) | self-test passes |
| Python (native, no C) | [`impl/python/n2qc_fireline.py`](../impl/python/n2qc_fireline.py) | self-test passes |

The two are **byte-identical**: Python reproduces the C reference parcel exactly
and opens a parcel built by C.

```bash
cc -O2 -Wno-unused-function -DN2Q_FIRELINE_DEMO impl/c/n2q_fireline.c -o fl && ./fl
cd impl/python && python3 n2qc_fireline.py     # includes the C cross-check
```

## Operational notes

- **Randomness.** The reference takes the DEK and nonce as parameters so tests
  are reproducible. In production both MUST come from a CSPRNG, and a DEK must
  never be reused across parcels.
- **Routing labels are public.** `rcpt_id` is metadata, not a secret — it says
  who a parcel is for. If that matters, pad the recipient list or use per-epoch
  pseudonymous labels.
- **Trunk-key ceremony is the weak point.** Compromise of a trunk key exposes
  that one relationship (not the node's archive). Protect the one-time exchange
  and rotate trunk keys periodically — `rewrap` makes rotation cheap.
- **Scale.** `N(N−1)/2` trunk keys: excellent for tens or hundreds of contracted
  partners, unworkable for millions of strangers. For the open network see stage
  3 (hybrid ML-KEM) in [federation.md](federation.md).

## Scope

FireLine inherits the security of the underlying envelope/AEAD construction — see
[threat-model.md](threat-model.md).

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.
