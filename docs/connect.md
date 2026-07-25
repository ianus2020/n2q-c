# N2Q-Connect — exchanging data between independent encryption centres

**Status: design document. Nothing here is implemented yet.** It defines how two
parties that each run their own N2Q deployment ("encryption centres") can
exchange data **without ever sharing a secret key**, and what a registry — a
blockchain contract or a lighter transparency log — does and does not add.

---

## 1. The problem

Today each centre installs N2Q and holds its own secret key. Two centres that
never met cannot read each other's ciphertext, and nobody wants to hand over a
master key to do it.

**This is not a gap in our implementation — it is the definition of symmetric
cryptography.** A symmetric cipher requires both sides to hold the *same* key.
No amount of engineering on N2Q alone can remove that requirement.

Therefore inter-centre exchange needs one genuinely new ingredient: **public-key
key agreement**. That ingredient is well studied, and we will **use standard,
vetted primitives — we will not invent our own asymmetric scheme.**

## 2. The construction: hybrid KEM/DEM

The standard, proven answer is a **KEM/DEM hybrid** — the same shape as our
existing `envelope` mode, except the wrapping key comes from a *public* key
instead of a shared KEK.

Each centre generates a key pair. The **private key never leaves the device**;
the public key is meant to be published.

Sending from centre A to centre B:

```
1. K            = random data key                       (per message/object)
2. encapsulated = KEM.encap(pub_B, K)                   ← only priv_B can open it
3. ciphertext   = N2Q.seal(K, data)                   ← our cipher does the bulk
4. wire         = encapsulated ‖ ciphertext
```

B receives it, runs `K = KEM.decap(priv_B, encapsulated)`, then
`N2Q.open(K, ciphertext)`.

**No shared secret is ever transmitted, and no private key ever moves.** N2Q
stays the workhorse (the DEM); the KEM only agrees the key.

### Primitive choice

| Layer | Choice | Why |
|---|---|---|
| KEM | **X25519 + ML-KEM (Kyber) hybrid** | X25519 is battle-tested; ML-KEM adds post-quantum security. A hybrid is safe if either one holds. |
| DEM | **N2Q SIV-AEAD** (`envelope`, `committing`) | Misuse-resistant, key-committing — exactly what a multi-party setting needs. |
| Identity | Signature over the published keys | So a centre's public key can be attributed and revoked. |

This also keeps our post-quantum story coherent: ML-KEM for the handshake,
N2Q-256 for the data (see [post-quantum.md](post-quantum.md)).

## 3. The registry: what a blockchain actually buys

A registry answers one question: *"is this really centre B's public key?"*

**On-chain (or in a transparency log) we publish only:**

- centre identity → its **public** keys, validity period,
- **revocation** entries (a compromised key must die publicly and verifiably),
- optionally, a smart-contract **access policy** (who may exchange with whom) and
  an audit trail of grants.

**Never on-chain:** private keys, session keys, or the data itself — not even
encrypted payloads. The chain is a *trust* layer, not a storage or secrecy layer.

> **The division of labour, stated plainly: the KEM provides confidentiality; the
> registry provides trust in public keys.** A blockchain cannot make data secret;
> mathematics does that. Conversely, a KEM cannot tell you whose key you hold;
> the registry does that.

### Registry options, honestly compared

| Option | Pros | Cons |
|---|---|---|
| **Classic PKI / CA** | cheap, instant, familiar to enterprises | central trust root; the CA can lie |
| **Transparency log** (CT-style, no chain) | tamper-evident, cheap, fast, no gas | needs log operators + auditors |
| **Blockchain contract** | decentralised, no single trust root, programmable policy, public revocation | cost/gas, latency, **metadata is public** (who exists, who talks to whom), governance burden |

**Recommendation:** design the protocol so the registry is *pluggable*. Ship with
a transparency-log/federated registry first (fast, free, sufficient for pilots),
and offer the on-chain contract for customers who specifically need trustless
decentralisation. The cryptography is identical either way.

## 4. What still leaks (be honest with customers)

- **Metadata.** Even with perfect encryption, a public registry plus network
  traffic can reveal *who talks to whom, when, and how much*. Mitigations:
  sealed-sender style addressing, our `length-hiding` mode, batching/mixing — a
  separate design task, not solved by KEM.
- **Endpoint compromise.** If a centre's device is owned, its private key and its
  plaintext are owned. Forward secrecy (our ratchet) limits the damage to
  *future* traffic; it cannot protect data the attacker can already read.
- **Revocation latency.** Between compromise and a published revocation there is
  a window. Short key validity narrows it.
- **Trust in the registry.** Whoever controls the registry can attempt to publish
  a wrong key. That is exactly why the log must be tamper-evident and auditable
  (or on-chain), and why identities should be independently verifiable.

## 5. Beyond two parties (later phases)

- **Groups of centres** — pairwise KEM is O(n²). The right answer is a group key
  agreement in the **MLS/TreeKEM** style: add/remove members cheaply, with forward
  secrecy. Our ratchet is the natural per-member layer underneath it.
- **Proxy re-encryption** — a semi-trusted node re-encrypts A's ciphertext for B
  *without decrypting it*, using a re-encryption key A delegates. Powerful for
  "share without sharing keys", but a much stronger cryptographic assumption —
  research phase only.

## 6. Proposed milestones

| Stage | Deliverable |
|---|---|
| **C1** | KEM-envelope prototype: X25519 → N2Q; two centres exchange a message with no shared secret; KATs + cross-language check |
| **C2** | Add ML-KEM (Kyber) as a hybrid; wire format with algorithm agility |
| **C3** | Pluggable registry: signed key bundles + transparency log; revocation |
| **C4** | Optional on-chain contract (identity, revocation, access policy) |
| **C5** | Group exchange (MLS-style) |

**Dependency:** C1 introduces the project's first asymmetric primitive. It must
come from an audited library (e.g. a vetted X25519/ML-KEM implementation) — this
is deliberately *not* a place for an original design, unlike the symmetric core.

---

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.
