# cryptanalysis — N2Q M4 measurements

Runs cryptanalytic *measurements* on the real QP-320 permutation (from the
reference crate) and reports honest results. Findings and margins are written up
in [`../../docs/cryptanalysis.md`](../../docs/cryptanalysis.md).

```sh
cargo run --release            # run all sections
cargo run --release avalanche  # diffusion / strict avalanche
cargo run --release degree     # algebraic degree via zero-sum cubes
cargo run --release differential
cargo run --release activesboxes # solver-free differential trail search (B&B)
cargo run --release rotational
cargo run --release timing      # dudect-lite constant-time (Welch t-test)
```

Each section labels its result **[P]** proven · **[E]** empirical · **[X]**
extrapolated. The headline open item — a MILP-proven active-S-box lower bound —
is *not* covered here; it needs an MILP/SAT solver and is a documented follow-up.
This is the designer's own analysis; it does not substitute for external review.

## Extended reproducible audit experiments (2026-10-19)

```sh
python3 tools/cryptanalysis/exact.py > exact.json
cargo run --release --locked --manifest-path tools/cryptanalysis/Cargo.toml --bin audit -- full > experiments.jsonl
# Optional bounded solver experiment, in an isolated virtual environment:
python3 -m venv /tmp/n2q-audit-solver
/tmp/n2q-audit-solver/bin/pip install z3-solver==4.15.4.0
/tmp/n2q-audit-solver/bin/python tools/cryptanalysis/trails.py --output /tmp/n2q-audit-smt > trails.jsonl
# Run timing separately on an otherwise idle host; writes raw CSVs to cwd:
cargo run --release --locked --manifest-path tools/cryptanalysis/Cargo.toml --bin audit -- timing > timing.jsonl
```

Run these commands from the repository root. `--quick` reduces sampling budgets
for harness checks; published results must distinguish quick/full. The full
suite covers both widths, all input/output avalanche pairs, selected linear
masks, differential histograms, two cube layouts, every nontrivial lane rotation,
reduced-round hashes, exhaustive single-bit AEAD mutations at block boundaries,
randomized roundtrips and forgery attempts. Public deterministic seeds are for
reproducibility, never production randomness. There are positive controls for
weak S-boxes, one-round linear correlations, truncated hash collisions, nonce
misuse and deliberately variable timing. Random test messages are synthetic.

`exact.py` exhaustively computes DDT/Walsh/BCT, component degrees, binary matrix
ranks/inverses, and independently inverts table-based permutation vectors.
`trails.py` encodes all nonzero starting differences modulo cyclic rotation and
exact local DDT feasibility; every SAT witness is independently rechecked.
Timeout means **unknown**, never a proven bound. An UNSAT result is solver-based
evidence in this model, without a separately checked UNSAT certificate. It is
not a differential-hull probability or a whole-cipher proof.

The family-wise Hoeffding thresholds are conservative diagnostic references
under the independent uniform-sampling model; the reproducible PRNG samples are
not a mathematical proof of that model. No significance threshold is a
cryptographic acceptance criterion. Zero observed collisions/forgeries gives
only finite-sample evidence. A nonzero cube sum lower-bounds the restricted
degree; a zero sum does not upper-bound global degree. Timing is randomized,
balanced, black-boxed and batched, with raw samples and a positive control;
passing does not establish constant time on this or other platforms.
