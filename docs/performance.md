# N2Q performance: baseline and optimisation roadmap

**Honest framing:** the reference implementations are written for *clarity and
constant-time correctness*, not speed. The numbers below are a **floor**. This
document records the measured baseline, names the hot path, and lays out the path
to a competitive build. No optimised/SIMD figures are claimed here that have not
been measured — the fast build is future work, tracked as a milestone.

## Measured baseline (this machine, single core)

| Workload | N2Q-128 Fast | N2Q-256 Fast | Notes |
|---|---|---|---|
| Bulk AEAD | ~15 MB/s | ~22.5 MB/s | un-vectorised reference (see `docs/comparison.md`) |
| Streaming (1200 B/pkt) | ~6.9 MB/s | ~12.1 MB/s | per-packet, incl. SIV two passes (`impl/c/n2q_bench.c`) |

Conditions: Apple M4 Max, single core, Rust 1.96.1 `--release` and Apple clang 21
at `-O2`. Bulk figures are the median of three `tools/bench` runs (spread under
1%); streaming figures are the median of five `impl/c/n2q_bench.c` runs (spread
about 7%, so treat them as approximate). Re-measuring on another machine or
toolchain will move these numbers; earlier revisions of this file quoted figures
roughly 6% higher taken on different hardware.

On the same machine `tools/bench` measures XChaCha20-Poly1305 at ~690 MB/s and
the AES-256-GCM crate at ~230 MB/s. A hardware-accelerated AES implementation on
a CPU with AES instructions reaches GB/s figures, but that is not what was
measured here. N2Q-256 is faster than N2Q-128 because its 128-bit lanes push
twice the bytes per permutation call.

## The hot path

Profiling points at one place: the **S-box**. The reference evaluates the 5-bit
S-box from its algebraic normal form at runtime — for each of the 5 output bits
it walks a list of monomials and ANDs the selected state lanes. That is fully
constant-time (no tables, no branches on secrets) but spends most cycles in that
inner loop, executed every round.

## Roadmap (each step is measurable and byte-exact against the KATs)

1. **Compile-time bitsliced S-box.** Replace the runtime ANF walk with the S-box's
   explicit boolean equations, hand-unrolled (a fixed set of AND/XOR over the 5
   lanes). Pure scalar, portable, expected several-fold speedup. *(next up)*
2. **Wide words / auto-vectorisation.** Process the two suites and multiple blocks
   with `uint64`/`__uint128` and compiler auto-vectorisation; align the linear
   layer's rotations for the vector units.
3. **Explicit SIMD.** NEON (Apple/ARM) and AVX2 intrinsics for the bitsliced round,
   processing several sponge states in parallel — the natural fit for a bitsliced
   design. Target: software-Ascon class.
4. **Platform AEAD offload where honest.** Document that N2Q will not beat
   AES-NI on raw AES workloads; its value is the feature set and the misuse/
   committing/forward-secrecy guarantees, not out-racing a hardware instruction.

## What this means for the pitch

The speed gap is an *implementation* gap, not a *design* gap: a bitsliced SPN
sponge is exactly the kind of primitive that vectorises well (Ascon, Keccak,
Xoodyak all ship fast SIMD builds). The reference is deliberately conservative
with a round margin; the optimised build closes most of the distance. Until it is
written and measured, we quote only the numbers above.
