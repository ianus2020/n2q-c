# N2Q-C — Threat model

Scope of this document: what N2Q-C is meant to protect, against whom, under what
assumptions, and what is explicitly out of scope. It frames the target for
external review (SPEC §12-M6). **N2Q-C is a research artifact and has not been
externally audited — do not use it to protect real secrets (SPEC §0).**

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
| N2Q-PW | Memory-hard (Balloon bound); data-independent access | per cost params |
| All | Constant-time (no secret-dependent branch/index/time) | — |

Reduction (SPEC §5.4): all of the above reduce to QP behaving as a random
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
3. **N2Q-PW cost** (`s_cost`, `t_cost`) is tuned to the deployment; do not use the
   test values in production.
4. **One key, one purpose** — HKDF sub-keys (N2Q-KDF) separate uses; do not reuse
   a raw key across unrelated primitives beyond the built-in domain separation.
5. **Do not deploy pre-audit.** Until external cryptanalysis (M6), use a vetted
   library for anything real.

## 6. Known limitations / residual risk

- No independent audit yet; the security goals are *claims*.
- The differential/linear bound is empirical (M4), not MILP-proven — the one
  headline open item.
- Blind index leaks equality and frequency (inherent to searchable determinism).
- The streaming mode is online but not misuse-resistant.
