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
