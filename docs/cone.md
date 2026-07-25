# N2Q-CoNe — Certificate Network

*Stage 4 of [federation.md](federation.md): identity for a federation, built from
a hash function and nothing else.*

[FireLine](fireline.md) answers *how* two nodes exchange data. It does not answer
*whose* trunk key that is — and a substituted key is exactly how a man in the
middle wins. Answering it needs a **signature**.

Ordinary signatures (RSA, ECDSA) are asymmetric number theory: foreign to our
design and broken by a quantum computer. **CoNe takes the other road:
signatures built only from a hash function** — the WOTS+ / Merkle construction
behind XMSS (RFC 8391) and SLH-DSA (FIPS 205), instantiated on the N2Q hash.

Result: a certificate system with **no number theory** and post-quantum security
by construction — Grover only halves a hash margin, and there is nothing for
Shor to exploit.

## Construction

```
WOTS+    one-time signature: 67 chains of a 32-byte hash, Winternitz w = 16
Merkle   a tree over 2^h one-time keys → ONE 32-byte root = the public identity
sign     index | WOTS+ signature | authentication path
verify   recompute the WOTS+ public key → leaf → walk the path → compare the root
```

| Quantity | Value (h = 4) |
|---|---|
| Public key (an identity) | **32 bytes** |
| Certificate (a signature) | **2276 bytes** |
| Certificates per identity key | 2^h = **16** |
| Assumption | second-preimage / collision resistance of the N2Q hash |

Raising `h` multiplies capacity (h = 10 → 1024 certificates) and adds only
`32 × h` bytes to a signature.

## Verified properties

| Property | Test result |
|---|---|
| Certificate verifies against the 32-byte public root alone | ✅ |
| Substituted trunk-key fingerprint rejected (**anti-MITM**) | ✅ |
| Tampered certificate rejected | ✅ |
| Certificate rejected under a different authority | ✅ |
| A certificate for one partner does not certify another | ✅ |
| Leaf reuse demonstrably yields two signatures from one one-time key (hazard shown) | ✅ |

```bash
cc -O2 -Wno-unused-function -DN2Q_CONE_DEMO impl/c/n2q_cone.c -o cone && ./cone
```

## How it fits with FireLine

```
CoNe   signs  "bank-b : trunk fingerprint 9f3a…c17"      ← who a key belongs to
FireLine uses  that trunk key to wrap a one-time data key ← how data moves
```

A node ships with the authority's 32-byte root. Any partner's trunk-key
fingerprint can then be verified offline, so an attacker cannot slip in a key of
their own. Certificates and revocations can additionally be published into an
[`n2q_log`](../impl/c/n2q_log.c) transparency chain, making substitution not just
detectable but *publicly* detectable.

## Two honest warnings

**1. It is stateful — this is the real operational risk.** Every leaf index is a
**one-time** key. Signing two different messages under the same index leaks extra
chain links and enables forgery. A deployment MUST persist the last used index
durably (and survive backups/restores and VM snapshots, which is exactly where
stateful schemes go wrong in practice). The reference takes the index as an
explicit parameter so misuse is visible in the API, and the self-test
demonstrates what happens if you ignore it.

**2. It is simplified against the standards.** No bitmask / tweakable-hash
addressing as in RFC 8391 and FIPS 205, so multi-target attack resistance is
weaker than those schemes. That is acceptable for a reference implementation and
must be fixed before any production use — either by adding the addressing scheme
or by moving to a stateless SLH-DSA-style design (larger signatures, ~8–30 KB, no
state to lose).

## Scope

A signature proves **whose** key it
is; it does not by itself establish a shared secret — for confidentiality between
strangers see stage 3 (hybrid ML-KEM) in [federation.md](federation.md).

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.
