# Project status and security disclosure

**Read this before using N2Q-C for anything that matters.** This is the single
authoritative statement of what has been verified, what has not, and what that
means in practice.

## Short version

N2Q-C is an **original cipher under active development**. It has **not undergone
external cryptanalysis or a third-party security audit**. Every security level
quoted anywhere in this project is a **design target supported by our own
measurements** — not a proven or independently confirmed guarantee.

**Do not use N2Q-C to protect real secrets or production data.** For production
today, use a vetted, widely reviewed library: libsodium, AES-GCM, or Ascon.

## What *is* verified

These are facts, reproducible on your own machine from this repository:

| Verified | How to check |
|---|---|
| Six implementations agree **byte-for-byte** (Rust, C, Python, Go, PHP, Swift) | run each self-test; compare with `impl/conformance/vectors.txt` |
| Constants are **reproducible from a public seed** — no hand-picked values | `tools/const-search` reproduces `APPENDIX-A.md` |
| Measured cryptanalysis: diffusion, avalanche, degree, differential, timing | `docs/cryptanalysis.md`, `tools/cryptanalysis` |
| Constant-time by design (no tables, no secret-dependent branches); dudect \|t\| = 0.48 | `docs/cryptanalysis.md` |
| Every extended mode ships a self-test that passes | `docs/conformance.md` |
| Cross-language interop for files, modes and federation parcels | the cross-check tests in each port |

## What is **not** verified

| Not verified | Consequence |
|---|---|
| **No external audit or public cryptanalysis** | Unknown weaknesses may exist. This is the big one. |
| No certified differential/linear bound | Only an upper bound from a solver-free search; a proof needs a full MILP/SAT model (`docs/cryptanalysis.md`) |
| No side-channel validation on hardware | Constant-time *by construction*, but not measured on smartcards/embedded targets |
| Federation (`FireLine`) and certificates (`CoNe`) are new | Newer than the core, with correspondingly less scrutiny |
| `CoNe` is **stateful** and simplified vs RFC 8391 / FIPS 205 | Reusing a one-time index enables forgery; multi-target resistance is weaker than the standards (`docs/cone.md`) |
| Reference implementations are not performance-hardened | See `docs/performance.md` for measured numbers and the optimisation roadmap |

## What "not audited" actually means

A cipher is not trustworthy because its authors tested it. It becomes
trustworthy when **skilled people who want it to fail** have attacked it in
public for a long time and did not succeed. AES, ChaCha20 and Ascon all earned
their standing that way, over years.

N2Q-C has not been through that process. Our own measurements can only show the
absence of the weaknesses we thought to look for — they cannot show the absence
of the ones we did not.

## Where this project is appropriate today

- Evaluation, prototypes and integration pilots with **non-sensitive** data
- Research, teaching, and cryptanalysis practice
- Anything where the goal is to *study* the design, including trying to break it

**Not appropriate:** production systems, personal data, financial data, medical
data, credentials, or anything whose exposure would cause harm.

## The path to production readiness

Milestones M1–M5 are complete (specification, reproducible constants,
implementations, in-house cryptanalysis, hardening). **M6 — external audit and a
public break-it challenge — is the gate.** Until M6 is done and its findings are
published and addressed, the guidance above does not change.

## Reporting a weakness

Found a break, a bug, or a flawed argument? That is the single most valuable
contribution to this project — please open an issue at
<https://github.com/ianus2020/n2q-c/issues>. Negative results are welcome and
will be published.
