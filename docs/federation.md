# Federating independent N2Q deployments

*How two organisations that each run their own encryption node can exchange data
without ever handing over their secret keys.*

Today every user installs N2Q on their own device or server — an **encryption
node** — and holds its own key material. Two such nodes cannot read each other's
ciphertext, and their owners will (rightly) refuse to swap master keys. This
document lays out the architectures that solve that, what each costs, and what a
blockchain can and cannot contribute.

---

## 1. Name the problem correctly

This is the **key distribution problem** — the oldest problem in cryptography and
the reason asymmetric cryptography was invented in 1976.

### The constraint we must state up front

N2Q is a **purely symmetric** primitive (a sponge over a permutation). Two
nodes that have **never shared a secret** cannot agree on one over a public
channel using symmetric cryptography alone. This is not a shortcoming of our
design — it is a mathematical fact. (The one symmetric attempt, Merkle puzzles,
buys only quadratic security: an attacker's work is the square of the honest
parties', which is far too weak to deploy.)

Therefore exactly **three** escapes exist, and no others:

| # | Escape | Cost |
|---|---|---|
| A | Share a key **once, out of band** | A one-time manual step per partner |
| B | Introduce a **trusted party** | Someone else is in the trust path |
| C | Add an **asymmetric key exchange** | A dependency outside N2Q |

Everything below is a concrete instance of A, B or C.

---

## 2. Architecture A — pairwise federation with envelopes

**Available today. No new cryptography.**

Two administrators exchange one trunk key `K_AB` a single time out of band (a QR
code at a meeting, paper, courier, or an existing secure channel). After that:

```
Node A:  DEK      = fresh random data key
         data     = seal(DEK, …)          ← the bulk is encrypted ONCE
         envelope = wrap(K_AB, DEK)       ← a tiny blob, 16-byte overhead
Node B:  DEK      = unwrap(K_AB, envelope) → reads the data
```

This is literally the shipped [`n2q_envelope`](../impl/c/n2q_envelope.c) module
(also native in Python, Go and Rust — see `n2qc_modes` / `modes.go` /
`modes_ext.rs`).

**Properties**

- Neither node's long-term key ever leaves it; only a wrap of a **single-use**
  data key travels.
- **Multi-recipient**: one DEK wrapped N times under N trunk keys (fan-out). The
  bulk ciphertext is stored once.
- **Revocation is cheap**: stop wrapping for that partner and `rewrap` the DEK —
  the bulk data is never re-encrypted.
- **Compromise is contained**: a stolen `K_AB` exposes that one relationship, not
  the node's whole archive.

**Threat model**

| Adversary | Outcome |
|---|---|
| Network attacker | Sees only ciphertext + envelopes; learns nothing |
| Malicious partner B | Reads only what A wrapped for B — nothing else |
| Compromise of the out-of-band step | That single relationship is compromised — this is the step to protect |

**Limits.** Requires a one-time human step and `N(N−1)/2` trunk keys. Excellent
for a federation of tens or hundreds of known business partners (who already sign
contracts anyway); unworkable for millions of strangers.

---

## 3. Architecture B — hub with symmetric tickets (Kerberos model)

**Available today. No new cryptography.**

Each node shares one long-term key with a hub. The hub issues a **ticket** — in
effect a *symmetric certificate*, a token authenticated with our keyed MAC:

```
A → Hub:  "I want to talk to B"
Hub → A:  ticket = { wrap(K_A, S), wrap(K_B, S) }     ← S = session key
A → B:    forwards the second half of the ticket
```

**Properties**

- Scales **linearly** (N keys, not N²); partners need no prior relationship.
- Discovery, expiry and revocation are centralised and easy.

**Threat model — read this carefully**

| Adversary | Outcome |
|---|---|
| Network attacker | Learns nothing |
| **The hub** | **Can mint session keys and read everything** |
| Hub outage | Federation stalls (single point of failure) |

**The blind-hub variant.** Keep pairwise trunk keys from Architecture A and let
the hub only **route and index**. It then provides discovery and revocation
convenience while being cryptographically unable to read anything. This is the
recommended compromise when a hub is wanted at all.

---

## 4. Architecture C — hybrid key exchange (open network)

**Needs one primitive that is not N2Q.**

For strangers with no trusted party, an asymmetric key agreement is unavoidable:

```
handshake:  X25519  or  ML-KEM (post-quantum, FIPS 203)  → shared secret
                     ↓ through the N2Q KDF
bulk:       everything else is N2Q — AEAD, ratchet, search, files, streaming
```

This is how TLS, Signal, WireGuard and age are all built: asymmetric only for the
handshake (a fraction of a percent of the work), symmetric for all data.

**Honesty note for positioning.** This introduces a dependency outside our own
primitive. That is not a weakness — it is the correct architecture — but it must
be described as **"N2Q + ML-KEM"**, never as "all ours". Choosing ML-KEM keeps
the post-quantum posture consistent with [post-quantum.md](post-quantum.md).

---

## 5. What a blockchain can and cannot do here

The proposal to use a blockchain / smart contract deserves a precise answer.

> **A blockchain cannot carry secrets.** It is a public append-only ledger:
> everything written to it is visible to everyone, forever. It therefore cannot
> perform the key exchange itself.

What it *can* do is supply **trust**, which is a genuinely valuable and separate
layer:

| A public ledger **can** | It **cannot** |
|---|---|
| Publish a **key directory** of nodes (who is who) | Transport a secret |
| Make key substitution **publicly visible** → anti-MITM | Replace the key exchange |
| Record **revocations** and validity periods | Hide **who talks to whom** — metadata is exposed |
| Provide an **audit trail** of exchanges | Work offline / at low latency |

This is precisely the role of **Certificate Transparency**. Note that our
[`n2q_log`](../impl/c/n2q_log.c) module — append-only with a hash chain where any
edit, reorder or deletion is detectable — already is a miniature transparency
log. For most federations a signed public log is sufficient, cheaper and, unlike
a public chain, does not broadcast the metadata of every relationship. That
metadata leak is a real argument **against** putting a crypto federation on a
public chain.

---

## 6. What "one global certificate" would mean

A certificate is a **signature**, and signatures are asymmetric. One option fits
our philosophy unusually well:

**Hash-based signatures (SPHINCS+ / SLH-DSA, FIPS 205)** are built from a hash
function and nothing else — they could be instantiated on the *N2Q hash*. That
would give a certificate system with no number theory and post-quantum security
by construction. The honest costs: signatures are large (roughly 8–30 KB) and the
scheme is intricate to implement correctly.

Remember the division of labour: **a signature proves whose key it is; it does
not establish a shared secret.** Even with a perfect PKI you still need A, B or C
above for confidentiality.

---

## 7. Recommendation

A layered path, cheapest and most honest first:

| Stage | What | Cost | Status |
|---|---|---|---|
| 1 | **Pairwise federation** — envelopes + `n2q_log` transparency + `franking` receipts | Days, from shipped modules | Ready to build |
| 2 | **Blind hub** — routing, discovery, revocation; cryptographically unable to read | Small service | Design |
| 3 | **Hybrid handshake** — ML-KEM → N2Q session key, for the open network | One external primitive | Design |
| 4 | **Hash-based PKI** — SLH-DSA-style signatures on the N2Q hash | Large, research-grade | Long term |

Stage 1 already covers the realistic near-term market: business partners who
exchange data under a contract and can afford one out-of-band key ceremony. It
uses only code that exists and is cross-checked today, and it never puts a
partner's master key at risk.

---

## 8. Scope and honesty

Nothing in this document is audited or deployed. Stage 1 relies on the shipped
envelope/log/franking modules, whose security rests on the same unproven design
targets as the rest of N2Q (see [threat-model.md](threat-model.md)). Stages 2–4
are designs, not implementations. As everywhere else in this project: **a
