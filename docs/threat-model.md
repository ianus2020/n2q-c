# N2Q — Threat model

Scope of this document: what N2Q is meant to protect, against whom, under what
assumptions, and what is explicitly out of scope. It frames the target for
external review (SPEC §12-M6).

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.

## 1. Assets

- **Plaintext confidentiality** — message contents given to the AEAD.
- **Plaintext/associated-data integrity** — detection of any modification.
- **Keys** — the 128/256-bit symmetric keys, and passwords behind N2Q-PW.
- **Searchable-column privacy** — values behind blind indexes.

## 2. Adversary model

We consider a probabilistic polynomial-time adversary who can:

- observe any number of ciphertexts / tokens / hashes / blind indexes (**public
  outputs**);
- submit chosen plaintexts and associated data to be encrypted
  (**chosen-plaintext**), nonce-respecting for the streaming mode;
- submit chosen ciphertexts / forgeries for decryption (**chosen-ciphertext**);
- for the SIV mode, additionally **reuse or repeat nonces** (nonce-misuse);
- observe **wall-clock timing** of operations (remote timing side channel).

The adversary does **not** have: the key; physical access to the device (power,
EM, fault injection); the ability to run code in the same address space with a
cache side channel *that the design does not already defeat by being
constant-time*.

## 3. Security goals (targets, not yet proven — SPEC §0)

| Primitive | Goal | Level (128 / 256) |
|---|---|---|
| AEAD (SIV, streaming) | IND-CPA confidentiality | 128 / 256 bit |
| AEAD | INT-CTXT integrity (forgery ≈ 2⁻ᵗᵃᵍ) | 128 / 256 bit |
| SIV mode | Nonce-misuse resistance (repeat leaks only equality of `(N,A,P)`) | — |
| Hash | Collision / preimage | 128,256 / 256,512 bit |
| Blind index | Keyed, deterministic; unlinkable without the key | 128 / 256 bit |
| N2Q-PW | Argon2id v19; bounded cost and memory | per cost params |
| QP core | Data-independent bitsliced operations; platform timing still needs review | — |

Reduction (SPEC §5.4): the N2Q modes depend on QP behaving as a random
permutation, evidenced (not proven) by the M4 measurements
([cryptanalysis.md](cryptanalysis.md)).

## 4. Out of scope

- **Physical / local side channels**: power, EM, fault/glitch, Rowhammer,
  Spectre-class speculative leaks. Constant-time defeats *timing and cache*
  channels only.
- **Nonce-misuse for the streaming mode** — that mode assumes unique nonces; use
  SIV where uniqueness cannot be guaranteed.
- **Release of unverified plaintext (RUP)** — decryption returns plaintext only
  after the tag verifies.
- **Traffic analysis / length leakage** — ciphertext length ≈ plaintext length.
- **Key management, storage, and distribution** — the caller's responsibility.
- **Quantum adversaries** beyond the Grover halving noted in SPEC §10 (use
  N2Q-256 for long-term data).
- **Blind-index frequency/equality leakage** — deterministic by design; only
  index fields you must search, and never high-value low-entropy secrets.

## 5. Assumptions and usage requirements

1. **Keys** come from a CSPRNG or from N2Q-PW; they are stored in a KMS/secret
   store, never in source.
2. **Nonces** for the streaming mode are unique per (key, message). SIV tolerates
   reuse (leaking only equality). A 128-bit random nonce is safe to generate
   randomly.
3. **Password KDF:** Argon2id v19, random 16–64-byte salt, explicit version and
   stored costs. Defaults are 64 MiB, 3 passes, 1 lane. Bound concurrent calls in
   addition to per-call limits; migrate legacy custom N2Q-PW keys explicitly.
4. **One key, one purpose** — use dedicated keys for unrelated uses. A generic
   N2Q-KDF/extract/expand API is not provided; do not implement the withdrawn
   variable-length `Hash(salt || ikm)` sketch or assume it is HKDF.
5. **Do not deploy pre-audit.** Until external cryptanalysis (M6), use a vetted
   library for anything real.

## 6. Known limitations / residual risk

- No independent audit yet; the security goals are *claims*.
- Full-round differential/linear bounds and mode-composition proofs remain
  open. Small-component exact results and bounded SAT/measurements are recorded
  in the additional audit; they do not establish the claimed security levels.
- Blind index leaks equality and frequency (inherent to searchable determinism).
- The streaming mode is online but not misuse-resistant.
