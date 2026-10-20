//! N2Q — M4 cryptanalysis harness.
//!
//! Runs *measurements* on the real QP-320 permutation (from the reference crate)
//! and reports honest results. What is proven vs. empirical vs. extrapolated is
//! labelled in each section; a MILP-proven active-S-box lower bound is a
//! documented follow-up (see docs/cryptanalysis.md).

use std::time::Instant;

use n2q_c_ref::consts::{ROTS_320, SBOX};
use n2q_c_ref::perm::Qp;

// ===================== restricted single-column active-S-box search ===========
// Differentials cancel the round constants, so the differential structure is
// rotation-invariant: a single-active-column trail may be pinned to position 0.
// We branch-and-bound the minimum number of active S-boxes; when the search
// completes it is a PROVEN minimum for that round count.

fn ddt_outputs() -> [Vec<u8>; 32] {
    let mut outs: [Vec<u8>; 32] = Default::default();
    for (din, list) in outs.iter_mut().enumerate() {
        let mut seen = [false; 32];
        for x in 0..32u8 {
            let dout = SBOX[x as usize] ^ SBOX[(x ^ din as u8) as usize];
            seen[dout as usize] = true;
        }
        for (dout, &s) in seen.iter().enumerate() {
            if s {
                list.push(dout as u8);
            }
        }
    }
    outs
}

fn active_positions(d: &[u64; 5]) -> Vec<usize> {
    let o = d[0] | d[1] | d[2] | d[3] | d[4];
    (0..64).filter(|j| o & (1u64 << j) != 0).collect()
}

fn column_din(d: &[u64; 5], j: usize) -> u8 {
    let mut v = 0u8;
    for k in 0..5 {
        v |= (((d[k] >> j) & 1) as u8) << k;
    }
    v
}

fn set_column(d: &mut [u64; 5], j: usize, dout: u8) {
    for k in 0..5 {
        d[k] &= !(1u64 << j);
        d[k] |= (((dout >> k) & 1) as u64) << j;
    }
}

fn linear(mut d: [u64; 5]) -> [u64; 5] {
    for k in 0..5 {
        let (ra, rb) = ROTS_320[k];
        d[k] ^= d[k].rotate_right(ra) ^ d[k].rotate_right(rb);
    }
    d
}

struct Search<'a> {
    ddt: &'a [Vec<u8>; 32],
    best: usize,
    nodes: u64,
    cap: u64,
    hit_cap: bool,
}

impl<'a> Search<'a> {
    // `pre` enters the S-box layer of the current round.
    fn go(&mut self, pre: [u64; 5], rounds_left: usize, acc: usize) {
        self.nodes += 1;
        if self.nodes > self.cap {
            self.hit_cap = true;
            return;
        }
        let cols = active_positions(&pre);
        let new_acc = acc + cols.len();
        // optimistic future: each remaining round contributes >= 1 active S-box
        if new_acc + (rounds_left - 1) >= self.best {
            return;
        }
        if rounds_left == 1 {
            self.best = self.best.min(new_acc);
            return;
        }
        let dins: Vec<u8> = cols.iter().map(|&j| column_din(&pre, j)).collect();
        self.branch(&cols, &dins, 0, [0u64; 5], rounds_left, new_acc);
    }

    fn branch(
        &mut self,
        cols: &[usize],
        dins: &[u8],
        idx: usize,
        post: [u64; 5],
        rounds_left: usize,
        new_acc: usize,
    ) {
        if idx == cols.len() {
            self.go(linear(post), rounds_left - 1, new_acc);
            return;
        }
        let din = dins[idx];
        for &dout in &self.ddt[din as usize] {
            let mut p2 = post;
            set_column(&mut p2, cols[idx], dout);
            self.branch(cols, dins, idx + 1, p2, rounds_left, new_acc);
            if self.hit_cap {
                return;
            }
        }
    }
}

/// Minimum active S-boxes over `rounds`, searching single-active-column starts
/// (rotation-invariant, position 0). Returns (min, completed).
fn min_active_sboxes(rounds: usize, cap: u64) -> (usize, bool) {
    let ddt = ddt_outputs();
    let mut s = Search { ddt: &ddt, best: usize::MAX, nodes: 0, cap, hit_cap: false };
    for din in 1u8..32 {
        // single active column at position 0 with input difference `din`
        let mut start = [0u64; 5];
        set_column(&mut start, 0, din);
        s.go(start, rounds, 0);
        if s.hit_cap {
            break;
        }
    }
    (s.best, !s.hit_cap)
}

fn active_sboxes() {
    println!("## 6. Differential trail search (solver-free branch-and-bound)\n");
    println!("  Fewest active S-boxes among differential trails that start from a SINGLE");
    println!("  active column (rotation-invariant since round constants cancel in a");
    println!("  difference). Each active S-box costs <= 2^-4 (APN).\n");
    println!("  rounds   min-active(1-col)   trail-prob   completed");
    let cap = 80_000_000u64;
    for r in 2..=4 {
        let (m, done) = min_active_sboxes(r, cap);
        if done {
            println!("    {r:>3}         {m:>4}            2^{:>6.1}     yes", -(4.0 * m as f64));
        } else {
            println!("    {r:>3}          n/a              n/a        NO (search too large)");
        }
    }
    println!(
        "\n  HONEST SCOPE: these are the best *single-column-initiated* trails (2R->4,\n  \
         3R->7 active S-boxes). They are an UPPER bound on the true per-window minimum\n  \
         -- multi-column starts may cancel in the linear layer and do better -- so they\n  \
         do NOT by themselves certify a security bound. A valid lower bound must search\n  \
         ALL starting differences: that is exactly the full MILP/SAT model, which needs\n  \
         a solver or another rigorous argument. Hitting the 80M-node budget is\n  \
         inconclusive about the minimum. New all-start experiments: trails.py.\n\n  \
         -> These restricted trails do not certify differential/linear security.\n"
    );
}

// ---- deterministic RNG ----
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn state(&mut self) -> [u64; 5] {
        [self.next(), self.next(), self.next(), self.next(), self.next()]
    }
}

fn perm(qp: &Qp, mut s: [u64; 5], r: usize) -> [u64; 5] {
    qp.permute(&mut s, r);
    s
}

fn flip(mut s: [u64; 5], bit: usize) -> [u64; 5] {
    s[bit / 64] ^= 1u64 << (bit % 64);
    s
}

fn popcount(s: &[u64; 5]) -> u32 {
    s.iter().map(|x| x.count_ones()).sum()
}

// ---- 1. diffusion / avalanche (empirical, on the real permutation) ----
fn avalanche(qp: &Qp) {
    println!("## 1. Diffusion & strict avalanche (empirical)\n");
    let samples = 300;
    println!("  rounds  completeness  mean-flip-prob   (target: 1.000 / 0.500)");
    for r in 1..=8 {
        let mut rng = Rng(0xA1 + r as u64);
        let mut dep = vec![[0u64; 5]; 320];
        let mut flips = 0u64;
        let mut trials = 0u64;
        for _ in 0..samples {
            let base = rng.state();
            let bout = perm(qp, base, r);
            for i in 0..320 {
                let fout = perm(qp, flip(base, i), r);
                let d = [
                    bout[0] ^ fout[0],
                    bout[1] ^ fout[1],
                    bout[2] ^ fout[2],
                    bout[3] ^ fout[3],
                    bout[4] ^ fout[4],
                ];
                for k in 0..5 {
                    dep[i][k] |= d[k];
                }
                flips += popcount(&d) as u64;
                trials += 320;
            }
        }
        let dependent: u32 = dep.iter().map(|d| popcount(d)).sum();
        let completeness = dependent as f64 / (320.0 * 320.0);
        let meanflip = flips as f64 / trials as f64;
        println!("    {r:>3}     {completeness:>8.3}      {meanflip:>8.3}");
    }
    println!(
        "\n  -> finite-sample diffusion measurements only; no cryptographic bound.\n     \
         Implemented profiles are 8/16 rounds. See binary audit for both widths.\n"
    );
}

// ---- 2. algebraic degree via zero-sum cube testers ----
fn degree(qp: &Qp) {
    println!("## 2. Algebraic degree - zero-sum / cube distinguisher (empirical)\n");
    println!("  A NONZERO d-cube sum implies restricted degree >= d. A zero sum does");
    println!("  not imply low global degree. Report: initial consecutive zero-sum rounds.\n");
    println!("  cube-dim  max-rounds-with-zero-sum");
    for &d in &[8usize, 12, 16] {
        let mut rng = Rng(0xB0u64.wrapping_add(d as u64));
        let mut max_r = 0;
        for r in 1..=16 {
            let mut all_zero = true;
            for _ in 0..4 {
                let base = rng.state();
                let mut acc = [0u64; 5];
                for mask in 0u64..(1u64 << d) {
                    let mut s = base;
                    s[0] = (base[0] & !((1u64 << d) - 1)) | mask;
                    let o = perm(qp, s, r);
                    for k in 0..5 {
                        acc[k] ^= o[k];
                    }
                }
                if acc != [0u64; 5] {
                    all_zero = false;
                    break;
                }
            }
            if all_zero {
                max_r = r;
            } else {
                break;
            }
        }
        println!("     {d:>3}          {max_r}");
    }
    println!(
        "\n  -> this restricted cube experiment does not establish degree saturation,\n     \
         a global degree upper bound, or absence of higher-order attacks.\n"
    );
}

// ---- 3. differential behaviour (empirical) + per-S-box cost (exact) ----
fn differential(qp: &Qp) {
    println!("## 3. Differential probability (empirical collapse)\n");
    println!("  S-box max differential probability = 2/32 = 2^-4 (APN, exact).");
    println!("  For a single-bit input difference, best observed output-difference");
    println!("  probability over 2^16 random inputs:\n");
    println!("  rounds   best-observed-DP    distinct-output-diffs");
    let n: u64 = 1 << 16;
    for r in 1..=4 {
        let din = 1usize;
        let mut counts = std::collections::HashMap::<[u64; 5], u64>::new();
        let mut rng = Rng(0xD1 + r as u64);
        for _ in 0..n {
            let base = rng.state();
            let a = perm(qp, base, r);
            let b = perm(qp, flip(base, din), r);
            let d = [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3], a[4] ^ b[4]];
            *counts.entry(d).or_insert(0) += 1;
        }
        let best = counts.values().copied().max().unwrap_or(0);
        let p = best as f64 / n as f64;
        let log2 = if p > 0.0 { p.log2() } else { f64::NEG_INFINITY };
        println!("    {r:>3}      2^{:>6.2}         {}", log2, counts.len());
    }
    println!(
        "\n  -> max observed frequency is a sample statistic, not an upper bound on\n     \
         differential or characteristic probability. Multiplying local DDT costs\n     \
         requires a justified trail model and does not bound differential hulls.\n"
    );
}

// ---- 4. rotational-invariance test ----
fn rotational(qp: &Qp) {
    println!("## 4. Rotational symmetry (must be broken by round constants)\n");
    let rot = 1u32;
    let mut rng = Rng(0x40);
    println!("  rounds   #(rotational relation holds) / trials   (random ~ 2^-320)");
    for r in 1..=4 {
        let mut hold = 0u64;
        let trials = 2000u64;
        for _ in 0..trials {
            let s = rng.state();
            let sr = [
                s[0].rotate_left(rot),
                s[1].rotate_left(rot),
                s[2].rotate_left(rot),
                s[3].rotate_left(rot),
                s[4].rotate_left(rot),
            ];
            let a = perm(qp, s, r);
            let ar = perm(qp, sr, r);
            let a_rot = [
                a[0].rotate_left(rot),
                a[1].rotate_left(rot),
                a[2].rotate_left(rot),
                a[3].rotate_left(rot),
                a[4].rotate_left(rot),
            ];
            if ar == a_rot {
                hold += 1;
            }
        }
        println!("    {r:>3}          {hold}/{trials}");
    }
    println!("\n  -> no exact rotational relation observed for this offset and sample.\n");
}

// ---- 5. timing (dudect-lite): data-independence of the permutation ----
fn timing(qp: &Qp) {
    println!("## 5. Constant-time check (dudect-lite, Welch t-test)\n");
    let iters = 200_000usize;
    let warm = 5_000usize;
    let mut rng = Rng(0x7157);
    let mut ta = Vec::with_capacity(iters);
    let mut tb = Vec::with_capacity(iters);
    for it in 0..iters + warm {
        let za = [0u64; 5];
        let zb = rng.state();
        let t0 = Instant::now();
        std::hint::black_box(perm(qp, za, 16));
        let da = t0.elapsed().as_nanos() as f64;
        let t1 = Instant::now();
        std::hint::black_box(perm(qp, zb, 16));
        let db = t1.elapsed().as_nanos() as f64;
        if it >= warm {
            ta.push(da);
            tb.push(db);
        }
    }
    let t = welch_t(&ta, &tb);
    println!("  |t| = {:.2}   (threshold 4.5: |t| < 4.5 => no timing leak detected)", t.abs());
    println!(
        "\n  -> historical fixed-order timing harness; not a constant-time proof.\n     \
         Use audit timing for randomized balanced classes and positive controls.\n"
    );
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var =
        |v: &[f64], m: f64| v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0);
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

fn main() {
    let qp = Qp::qp320();
    println!("=== N2Q - M4 cryptanalysis measurements (QP-320) ===\n");
    let arg = std::env::args().nth(1).unwrap_or_else(|| "full".into());
    match arg.as_str() {
        "avalanche" => avalanche(&qp),
        "degree" => degree(&qp),
        "differential" => differential(&qp),
        "rotational" => rotational(&qp),
        "timing" => timing(&qp),
        "activesboxes" => active_sboxes(),
        _ => {
            avalanche(&qp);
            degree(&qp);
            differential(&qp);
            rotational(&qp);
            active_sboxes();
            timing(&qp);
        }
    }
}
