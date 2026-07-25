# N2Q-C and post-quantum security

**Short version:** use the **N2Q-256** suite and N2Q-C carries a **128-bit
post-quantum security level** — the same posture as AES-256, SHA-256 and Ascon-128a.
This needs no new algorithm: it follows from how quantum computers do (and do not)
help against symmetric, permutation-based cryptography.

## Why symmetric crypto is the easy case for "post-quantum"

The headline quantum threat — Shor's algorithm — breaks **public-key** crypto
(RSA, Diffie-Hellman, ECC) because those rest on structured problems (factoring,
discrete logs). N2Q-C has **no such structure**: it is a keyed sponge over a
bit-sliced SPN permutation. There is nothing for Shor to factor or invert.

The only generic quantum tool that applies is **Grover's algorithm**, a brute-force
search that turns a `2^n` key search into `~2^(n/2)` quantum operations — a
*quadratic* speedup, not an exponential one. The defence is simply a bigger key:

| Suite | Key | Classical security | Post-quantum (Grover) |
|---|---|---|---|
| N2Q-128 | 128-bit | 128-bit | ~64-bit *(not recommended vs a quantum adversary)* |
| **N2Q-256** | **256-bit** | **256-bit** | **~128-bit** ✅ |

So **N2Q-256 keeps a 128-bit margin even against a full-scale quantum computer** —
and 128-bit is the level NIST treats as adequate for the post-quantum era. In
practice Grover is far weaker than the table suggests: it is inherently sequential
and does not parallelise well, so the real-world cost of a `2^128`-operation Grover
search is astronomically beyond the classical `2^128` figure it nominally matches.

## Hashing, MAC, KDF and search

- **Hash / KDF** output 256 bits. The best quantum collision search (Brassard–
  Høyer–Tapp) needs `~2^85` work *and* comparable quantum memory, which is not a
  practical attack; NIST considers a 256-bit hash post-quantum-adequate. Preimage
  resistance under Grover is `~2^128`.
- **MAC / blind index** rest on the same keyed permutation as the AEAD, so they
  inherit the same Grover-only posture — use the 256-bit suite.

## What this claim is, and is not

- **It is:** the standard, well-understood argument that symmetric primitives with
  256-bit keys are quantum-resistant. N2Q-C inherits exactly the post-quantum
  posture of AES-256 / SHA-256 / Ascon by using the same key sizes and a
  structure with no Shor-exploitable algebra.
- **It is not:** a proof that N2Q-C is secure. The post-quantum margin is only as
  real as the *classical* security of the permutation, which is still a design
  target pending external cryptanalysis (see the roadmap, milestone M6). "Quantum
  security 128-bit" assumes the permutation is close to ideal — the same
  assumption the classical claims rest on.

## Recommendation

For any deployment that must survive a future quantum adversary (long-lived
secrets, "harvest-now-decrypt-later" data), select the **N2Q-256** suite. It is
byte-interoperable with the rest of the library and costs only the wider state;
no protocol change is required.
