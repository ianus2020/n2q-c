# const-search — N2Q-C M2 constant selection

Deterministic tooling that measures 5-bit S-box cryptographic properties and
selects the N2Q-C constants (SPEC §7). All output is reproducible from the public
seed `"N2Q-C/v0.1"` — no hidden values.

## Commands

```sh
cargo run --release -- <N>          # random-table S-box search over N candidates
cargo run --release -- construct    # algebraic S-box constructions + properties
cargo run --release -- rotations 64 1500    # QP-320 rotation-constant search
cargo run --release -- rotations 128 500    # QP-640 rotation-constant search
cargo run --release -- finalize     # print the chosen constants + KAT vectors
```

## What each metric means

- **differential uniformity** — max entry of the difference distribution table;
  2 = APN (optimal for n=5). Lower ⇒ stronger vs. differential cryptanalysis.
- **nonlinearity** — distance to affine functions (max 12 for n=5). Higher ⇒
  stronger vs. linear cryptanalysis.
- **algebraic degree** — max 4 for n=5. Higher ⇒ stronger vs. algebraic / higher-
  order attacks.
- **diffusion rounds** — rounds until every input bit influences every output bit
  (linear model). Fewer ⇒ faster avalanche.

## Modules

| file | role |
|---|---|
| `sbox.rs` | DDT, LAT/Walsh, ANF degree, branch, fixed points; search |
| `gf.rs` | GF(2⁵) arithmetic, inverse & Gold S-boxes, affine wrapping |
| `diffusion.rs` | boolean bit-dependency model; rotation-constant search |
| `perm.rs` | reference QP permutation (table form) for KAT generation |
| `main.rs` | modes and reporting |

The chosen values are recorded in [`../../APPENDIX-A.md`](../../APPENDIX-A.md).
