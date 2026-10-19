# Project status and security disclosure

**Read this before using N2Q for anything that matters.** This is the single
authoritative statement of what has been verified, what has not, and what that
means in practice.

## Short version

N2Q is an **original cipher under active development**. It has **not undergone
external cryptanalysis or a third-party security audit**. Every security level
quoted anywhere in this project is a **design target supported by our own
measurements** — not a proven or independently confirmed guarantee.

**Do not use N2Q to protect real secrets or production data.** For production
today, use a vetted, widely reviewed library: libsodium, AES-GCM, or Ascon.

## Current implementation limits

Core ports use ANF rather than state-indexed S-box lookup. Python/PHP runtimes,
Go/Swift compilers, garbage collection and WASM/JIT behavior are not certified
constant-time. A historical C timing result cannot establish this for all ports.
N2QF v1 is rejected; [v2](docs/n2qf.md) requires authenticated EOF. Files and
stateful extensions still require application resource limits and independent
review. The six path-based N2QF ports stream bounded records to private staging
files and publish after authenticated EOF. Password KDF v2 uses bounded
Argon2id v19; legacy custom PW keys require explicit migration. CoNe signing
requires durable reservations plus an external monotonic anchor; no deployment
backend is validated. A persistent [local reference anchor](tools/anchor/README.md)
and C mTLS callback are provided; separate deployment rollback/storage domains
remain an operator responsibility. C core ANF constants require no runtime initialization.
The browser verifies its JS/WASM pair and handles worker failure/deadlines.
No RUP robustness is claimed ([correction](docs/robustness.md)).
Convergent master keys are fixed at 16 bytes; C convergent APIs require output
capacities. The [closed additional AI-assisted audit](docs/cryptographic-audit-2026-10-19.ru.md)
records experiments and fixes; it is not an independent external review.

## What *is* verified

These are facts, reproducible on your own machine from this repository:

| Verified | How to check |
|---|---|
| Six implementations agree **byte-for-byte** (Rust, C, Python, Go, PHP, Swift) | run each self-test; compare with `impl/conformance/vectors.txt` |
| Constants are **reproducible from a public seed** — no hand-picked values | `tools/const-search` reproduces `APPENDIX-A.md` |
| Measured cryptanalysis: diffusion, avalanche, degree, differential, timing | `docs/cryptanalysis.md`, `tools/cryptanalysis` |
| Lane-wise ANF S-box in the six core ports; no state-indexed S-box lookup | KATs and source; this does not prove runtime constant-time behavior |
| Every extended mode ships a self-test that passes | `docs/conformance.md` |
| Cross-language interop for files, modes and federation parcels | the cross-check tests in each port |
| Implementation regressions, ASan/UBSan, TSan, Go race checks and bounded fuzz smoke | CI and [execution ledger](docs/implementation-progress.ru.md); these are bounded checks, not cryptographic proofs |

## What is **not** verified

| Not verified | Consequence |
|---|---|
| **No external audit or public cryptanalysis** | Unknown weaknesses may exist. This is the big one. |
| No full-round differential/linear bound | Exact local results and bounded 2/3-round SAT do not establish full-round attack costs or mode security (`docs/cryptanalysis.md`) |
| No broad side-channel validation | Recorded Rust-host timing experiment only; no smartcard/embedded/power/EM/fault certification |
| Federation (`FireLine`) and certificates (`CoNe`) are new | Newer than the core, with correspondingly less scrutiny |
| `CoNe` is **stateful** and simplified vs RFC 8391 / FIPS 205 | Reusing a one-time index enables forgery; multi-target resistance is weaker than the standards (`docs/cone.md`) |
| Reference implementations are not performance-hardened | See `docs/performance.md` for measured numbers and the optimisation roadmap |

## What "not audited" actually means

A cipher is not trustworthy because its authors tested it. It becomes
trustworthy when **skilled people who want it to fail** have attacked it in
public for a long time and did not succeed. AES, ChaCha20 and Ascon all earned
their standing that way, over years.

N2Q has not been through that process. Our own measurements can only show the
absence of the weaknesses we thought to look for — they cannot show the absence
of the ones we did not.

## Where this project is appropriate today

- Evaluation, prototypes and integration pilots with **non-sensitive** data
- Research, teaching, and cryptanalysis practice
- Anything where the goal is to *study* the design, including trying to break it

**Not appropriate:** production systems, personal data, financial data, medical
data, credentials, or anything whose exposure would cause harm.

## The path to production readiness

Implementation hardening is ongoing; previous milestone completion labels
were not evidence that every parser, file format or extension was secure.
See [the remediation record](docs/security-fixes.md) for changes and remaining
work. Independent external cryptanalysis can be confidential; its findings must
be documented and addressed, together with the operational release gates.
Internal tests do not close that milestone. This repository and audit stay
private; disclosure requires a separate owner decision.

## Reporting a weakness

Record weaknesses in the private repository or through an agreed confidential
channel with its owner. Include reproduction and affected revision. Disclosure
decisions remain with the owner.
