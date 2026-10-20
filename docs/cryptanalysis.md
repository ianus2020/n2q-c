# N2Q — cryptanalysis dossier

This is an internal research dossier. The additional AI-assisted closed review
is [reported in Russian](cryptographic-audit-2026-10-19.ru.md), with
[raw evidence](audit/2026-10-19/), tool/source hashes and reproducible commands
in [tools/cryptanalysis](../tools/cryptanalysis/README.md). It is not external
or independently certified cryptanalysis. Claimed 128/256-bit levels remain
unestablished for both 8-round Fast and 16-round Secure.

## Exact small-component results

Exhaustive DDT/Walsh/BCT calculations confirm the bijective 5-bit S-box:
differential uniformity 2, maximum absolute Walsh coefficient 12, nonlinearity
10, degree 4 for all 31 nonzero components, boomerang uniformity 2, no fixed
or complement points. The identity-S-box positive control is detected.

All ten 64/128-bit lane-linear maps are invertible. Counting active five-bit
columns, pL has branch number exactly 4: one active column produces at least
three, and a one-column output cannot have a two-column input (every inverse
single-lane impulse has weight at least three). Invertibility covers the other
cases; a single input bit achieves 1+3. This is not a whole-cipher probability
bound. The full report includes inverse impulse weights and the proof's scope.

## Two-width empirical experiments

Both QP-320 and QP-640 were tested. Counts aggregate related experiments and
are not independent cryptographic guarantees:

| Experiment | Scope | Observation |
|---|---|---|
| Table oracle vs Rust ANF | 4,352 inputs, 0–16 rounds | No mismatch |
| Avalanche | 1,024 samples/input bit; every pair of bits | Full observed dependency at 4 rounds; no diagnostic outliers at 8/16 |
| Differential histograms | 4 differences, 65,536 pairs/variant | No duplicate output differences sampled at 8/16; no probability upper bound inferred |
| Linear masks | 8 mask pairs, 262,144 states/variant | Strong one-round control detected; no selected-mask diagnostic outliers at 8/16 |
| Cubes | dimensions 8/12/16, two layouts, four bases | No zero sums at 8/16; a 16-dimensional QP-640 cube still zero in 2/4 bases at 4 rounds |
| Exact lane rotations | every nonzero shift, 121,600 comparisons | No sampled relation; does not close rotational-XOR/invariant analysis |
| Reduced-round hashes | 393,216 messages | No full collision; pronounced 16-bit-prefix structure in some low-round variants |
| AEAD | 40,784 roundtrips; 662,648 mutations; 80,000 random forgeries | All expected rejects; streaming nonce-reuse first-block XOR leakage reproduced |
| Timing | 1.6 million balanced randomized batches, raw CSV retained | max real-permutation abs(t)=1.766; all deliberate-leak controls detected |

The timing result applies only to the recorded Rust binary and host, not every
port or API. No power/EM/fault/cache/speculation guarantees follow. Statistical
references assume independent uniform sampling; public deterministic test seeds
provide reproducibility, not proof of that assumption.

## Bounded all-start differential SAT

The new model covers all nonzero input differences modulo cyclic symmetry,
with exact local DDT feasibility and independent local preimages. These are
locally admissible trails, potentially more general than realizable multi-round
input pairs. Z3 4.15.4, 15 seconds/query; full SMT2 models retained. There is no
separately checked UNSAT certificate.

- QP-320: 2 rounds with at most 3 active boxes UNSAT (lower bound 4);
  3 rounds with at most 5 UNSAT (lower bound 6).
- QP-640: 2 rounds with at most 3 UNSAT (lower bound 4).
- Other 3/4-round queries timed out: **unknown**, not a bound or attack.
- No all-start 8/16-round SAT bound or linear-hull model was completed.

The historical single-column branch-and-bound remains restricted: completed
minima 2R=4/3R=7 are upper bounds on the unrestricted minimum. Exhausting 80M
nodes at 4 rounds proves nothing about the minimum. Combining local DDT/LAT
costs requires justified assumptions; trail probabilities do not directly bound
differential/linear hulls or AEAD attacks.

## Corrections to earlier claims

- Finite diffusion observations do not certify multiplicative round margins.
- A nonzero d-cube sum implies restricted degree at least d; a zero sum does
  not upper-bound global algebraic degree. Degree saturation was not proven.
- A histogram maximum of 1/N is not a bound below 1/N on true probability.
- No observed exact rotation does not rule out general invariants or slides.
- An old fixed-order timing result cannot certify a current binary.
- Generic sponge/SIV theorems do not automatically prove these exact modes or
  the extensions. SPEC §5.4 records outstanding composition proof obligations.

## Still open

External cryptanalysis; full-round differential/linear hull bounds and mode
composition; independently checked solver models/certificates; dedicated
rebound, division-property, invariant-subspace and related-key/multi-user work;
hardware side channels/faults; complete cryptanalysis of the extensions. Neither
the new measurements nor the implementation fixes close these items.
