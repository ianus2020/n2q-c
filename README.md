# N2Q — an original cryptographic algorithm (not a wrapper)

N2Q is a self-contained authenticated cipher, designed from scratch under real
crypto-design discipline — an attempt to lift the ideas of the earlier N2Q work
from a toy to an artifact ready for external audit.

**Construction:** a duplex **sponge over an original SPN permutation QP-w**
(a bitsliced 5-bit S-box plus a linear layer of lane rotations), in two sizes —
QP-320 (5×64, the **N2Q-128** suite) and QP-640 (5×128, the **N2Q-256** suite),
sharing the same S-box. One permutation yields the whole library: authenticated
encryption (the default mode is the **misuse-resistant SIV**, plus a fast
streaming mode), hashing, a password KDF, and a searchable **blind index**. The
design must be assessed at both the permutation and mode-composition levels.
General sponge or SIV results do not certify this implementation or its extensions.

> **Status:** see [STATUS.md](STATUS.md) for what is verified, what is not, and where this project is appropriate to use.

> **Security fixes and compatibility:** [remediation record](docs/security-fixes.md),
> [N2QF v2 and migration](docs/n2qf.md), [web build and tests](impl/n2q-c-wasm/README.md).
>
> **Implementation audit close-out:** [final report and remaining conditions](docs/audit-closure.ru.md).

---

## What's already here (M1–M5)

- **[SPEC.md](SPEC.md)** — specification v0.1: construction, selection criteria,
  and modes (SIV by default, the two 128/256 suites).
- **[APPENDIX-A.md](APPENDIX-A.md)** — the concrete constants from M2: the S-box
  (APN, nonlinearity 10, algebraic degree 4), rotations (full diffusion in 4
  rounds), round constants, and permutation test vectors. All reproducible from a
  public seed.
- **[impl/](impl)** — reference implementations in **Rust, C, Python, Go, PHP and
  Swift**, plus a **WebAssembly** build. Constant-time by design; cross-checked
  byte-for-byte against shared KAT vectors.
- **[docs/cryptanalysis.md](docs/cryptanalysis.md)** — the cryptanalysis dossier
  with measured results (avalanche, cubes, differential, timing) and their
  limitations. Round margins and claimed security levels remain unproven.
- **[docs/threat-model.md](docs/threat-model.md)** — assets, adversary model,
  security goals, out-of-scope items, and usage requirements.
- **[docs/comparison.md](docs/comparison.md)** — security (by design) and speed
  (as implemented) versus market algorithms.
- **[tools/](tools)** — the Rust tools that deterministically select the constants
  (`const-search`) and take the cryptanalysis measurements from the real
  permutation (`cryptanalysis`, `bench`).

## Roadmap to audit

| Stage | What | Status |
|---|---|---|
| M1 | Specification (construction + criteria) | ✅ done |
| M2 | Constant selection: S-box, rotations, round constants + KAT | ✅ done |
| M3 | Reference implementations: Rust, C, Python, Go, PHP, Swift + WASM tester, KAT cross-check | ✅ done |
| M4 | In-house cryptanalysis (avalanche / degree / differential / timing), round finalization | ◐ measurements done; a certified MILP bound is open |
| M5 | Wire format, password KDF (Argon2id), threat model | ✅ done |
| M6 | Independent external cryptanalysis; confidential review is possible | Open |

---

The [closed additional audit](docs/cryptographic-audit-2026-10-19.ru.md),
[local HTTPS/CoNe stand](tools/local_stand/README.md) and
[offline migration tools](tools/migration/README.md) have reproducible records
in [the local verification report](docs/stage-15-local-verification.ru.md).
The repository remains private. M6 review can be confidential; publication or a
public challenge requires a separate owner decision.
