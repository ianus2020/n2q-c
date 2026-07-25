//! N2Q — M2 constant selection tool.
//!
//! Deterministically searches for the S-box (SPEC §7.1) and reports its
//! cryptographic properties. Seeded from the public string "N2Q/v0.1" so the
//! result is reproducible (nothing-up-my-sleeve).

mod diffusion;
mod gf;
mod perm;
mod sbox;

/// The chosen constants (outputs of the `construct` and `rotations` runs).
const SBOX: [u8; SIZE] = [
    0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
    0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09,
];
const ROTS_320: [(u32, u32); 5] = [(38, 55), (1, 23), (23, 36), (16, 14), (20, 46)];
const ROTS_640: [(u32, u32); 5] = [(75, 7), (89, 21), (56, 111), (30, 54), (25, 52)];

/// 16 distinct round constants derived from the public seed "N2Q/v0.1/rc".
fn round_constants() -> Vec<u64> {
    let mut rng = Rng(seed_from("N2Q/v0.1/rc"));
    let mut rc = Vec::new();
    while rc.len() < 16 {
        let v = rng.next() & 0xff;
        if !rc.contains(&v) {
            rc.push(v);
        }
    }
    rc
}

fn finalize() {
    let rc = round_constants();
    println!("=== N2Q M2 — FINAL constants + test vectors ===\n");
    println!("S-box (inverse ∘ affine, APN / NL10 / deg4 / no fixed points):");
    print!("  [");
    for (i, v) in SBOX.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("0x{v:02x}, ");
    }
    println!("\n  ]");
    println!("QP-320 rotations: {ROTS_320:?}   (full diffusion 4 rounds)");
    println!("QP-640 rotations: {ROTS_640:?}   (full diffusion 4 rounds)");
    println!("round constants (hex): {:02x?}\n", rc);

    for (name, w, rots) in [("QP-320", 64u32, ROTS_320), ("QP-640", 128u32, ROTS_640)] {
        let qp = perm::Qp {
            w,
            sbox: SBOX,
            rots,
            rc: rc.clone(),
        };
        println!("--- {name} known-answer vectors ---");
        for (label, init) in [
            ("zero", [0u128; 5]),
            (
                "pattern",
                [
                    0x0123456789abcdef,
                    0xfedcba9876543210,
                    0x0f1e2d3c4b5a6978,
                    0x1122334455667788,
                    0x8090a0b0c0d0e0f0,
                ],
            ),
        ] {
            for rounds in [12usize, 16usize] {
                let mut s = init;
                qp.permute(&mut s, rounds);
                let m = if w == 128 { u128::MAX } else { (1u128 << w) - 1 };
                print!("  {label} p^{rounds}: ");
                for lane in s.iter() {
                    if w == 128 {
                        print!("{:032x} ", lane & m);
                    } else {
                        print!("{:016x} ", lane & m);
                    }
                }
                println!();
            }
        }
        println!();
    }
}

use sbox::{analyze, meets_criteria, Props, SIZE};

fn report(name: &str, s: &[u8; SIZE]) {
    let p = analyze(s);
    println!("--- {name} ---");
    print_sbox(s);
    println!("  differential unif.   : {}  (2 = APN)", p.diff_uniformity);
    println!("  nonlinearity         : {}  (max 12)", p.nonlinearity);
    println!("  algebraic degree     : {}  (max 4)", p.degree);
    println!("  diff. branch number  : {}", p.diff_branch);
    println!("  fixed / anti-fixed   : {} / {}", p.fixed_points, p.anti_fixed_points);
    println!("  ANF ops (circuit ~)  : {}", p.anf_ops);
    println!("  meets all criteria   : {}\n", meets_criteria(&p));
}

/// SplitMix64 — small deterministic PRNG (reproducible search).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u32) -> u32 {
        (self.next() % n as u64) as u32
    }
}

/// Seed from the public spec string (FNV-1a 64-bit).
fn seed_from(s: &str) -> u64 {
    let mut h: u64 = 0xCBF29CE484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001B3);
    }
    h
}

/// Random 5-bit permutation via Fisher–Yates.
fn random_perm(rng: &mut Rng) -> [u8; SIZE] {
    let mut s = [0u8; SIZE];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    for i in (1..SIZE).rev() {
        let j = rng.below(i as u32 + 1) as usize;
        s.swap(i, j);
    }
    s
}

/// Ranking: prefer lower diff-uniformity, then higher nonlinearity, then higher
/// degree, then higher branch, then fewer ANF ops.
fn better(a: &Props, b: &Props) -> bool {
    (
        a.diff_uniformity,
        u32::MAX - a.nonlinearity,
        u32::MAX - a.degree,
        u32::MAX - a.diff_branch,
        a.anf_ops,
    ) < (
        b.diff_uniformity,
        u32::MAX - b.nonlinearity,
        u32::MAX - b.degree,
        u32::MAX - b.diff_branch,
        b.anf_ops,
    )
}

fn print_sbox(s: &[u8; SIZE]) {
    print!("[");
    for (i, v) in s.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n  ");
        }
        print!("0x{:02x}, ", v);
    }
    println!("\n]");
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();

    if arg == "construct" {
        println!("=== N2Q M2 — algebraic S-box constructions ===\n");
        report("GF(2^5) inverse  S(x)=x^-1", &gf::inverse_sbox());
        report("Gold             S(x)=x^3", &gf::gold3_sbox());
        // Inverse wrapped in a seeded INVERTIBLE affine bijection chosen to
        // remove fixed points (properties are affine-invariant). Deterministic.
        let inv = gf::inverse_sbox();
        let mut rng = Rng(seed_from("N2Q/v0.1/affine"));
        let mut chosen = None;
        for _ in 0..2_000_000u64 {
            let rows = [
                (rng.next() & 0x1F) as u8,
                (rng.next() & 0x1F) as u8,
                (rng.next() & 0x1F) as u8,
                (rng.next() & 0x1F) as u8,
                (rng.next() & 0x1F) as u8,
            ];
            if !gf::is_invertible(rows) {
                continue;
            }
            let c = (rng.next() & 0x1F) as u8;
            let s = gf::affine_wrap(&inv, rows, c);
            let p = sbox::analyze(&s);
            if p.fixed_points == 0 && p.anti_fixed_points == 0 {
                chosen = Some((rows, c, s));
                break;
            }
        }
        match chosen {
            Some((rows, c, s)) => {
                println!("(affine rows = {:02x?}, c = 0x{:02x})", rows, c);
                report("Inverse ∘ affine (FINAL candidate)", &s);
            }
            None => println!("no fixed-point-free affine wrap found"),
        }
        return;
    }

    if arg == "finalize" {
        finalize();
        return;
    }

    if arg == "rotations" {
        let w: usize = std::env::args()
            .nth(2)
            .and_then(|a| a.parse().ok())
            .unwrap_or(64);
        let sets: u64 = std::env::args()
            .nth(3)
            .and_then(|a| a.parse().ok())
            .unwrap_or(1500);
        println!("=== N2Q M2 — rotation-constant search (lane width {w}) ===");
        let mut rng = Rng(seed_from(&format!("N2Q/v0.1/rot{w}")));
        let mut best: Option<([(u32, u32); 5], usize)> = None;
        for _ in 0..sets {
            let mut rots = [(0u32, 0u32); 5];
            let mut ok = true;
            for r in rots.iter_mut() {
                let ra = 1 + rng.below(w as u32 - 1);
                let rb = 1 + rng.below(w as u32 - 1);
                if ra == rb {
                    ok = false;
                }
                *r = (ra, rb);
            }
            if !ok {
                continue;
            }
            let rounds = diffusion::diffusion_rounds(w, &rots, 12);
            let take = match best {
                None => true,
                Some((_, br)) => rounds < br,
            };
            if take {
                best = Some((rots, rounds));
            }
        }
        match best {
            Some((rots, rounds)) => {
                println!("best rotation set: {rots:?}");
                println!("full linear diffusion in {rounds} rounds");
            }
            None => println!("no valid set found"),
        }
        return;
    }

    let budget: u64 = arg.parse().unwrap_or(40_000_000);
    let seed = seed_from("N2Q/v0.1");
    let mut rng = Rng(seed);

    println!("=== N2Q M2 — S-box search ===");
    println!("seed(\"N2Q/v0.1\") = 0x{:016x}", seed);
    println!("budget = {} candidates\n", budget);

    let mut best: Option<([u8; SIZE], Props)> = None;
    let mut best_idx = 0u64;
    let mut apn_found = 0u64;
    let mut survivors = 0u64;

    for i in 0..budget {
        let s = random_perm(&mut rng);
        // cheap prune: reject high differential uniformity before full analysis.
        let du = sbox::diff_uniformity(&s);
        if du > 4 {
            continue;
        }
        survivors += 1;
        let p = analyze(&s);
        if p.diff_uniformity == 2 {
            apn_found += 1;
        }
        if !meets_criteria(&p) {
            continue;
        }
        let take = match &best {
            None => true,
            Some((_, bp)) => better(&p, bp),
        };
        if take {
            best = Some((s, p));
            best_idx = i;
        }
    }

    println!("candidates with diff-uniformity <= 4 : {survivors}");
    println!("APN (diff-uniformity == 2) seen      : {apn_found}\n");

    match best {
        None => println!("No candidate met all hard criteria within budget."),
        Some((s, p)) => {
            println!("--- CHOSEN S-BOX (first-best, index {best_idx}) ---");
            print_sbox(&s);
            println!("\nProperties:");
            println!("  bijective            : {}", p.bijective);
            println!("  differential unif.   : {}  (2 = APN; <=4 required)", p.diff_uniformity);
            println!("  linearity            : {}", p.linearity);
            println!("  nonlinearity         : {}  (>=10 required, max 12)", p.nonlinearity);
            println!("  algebraic degree     : {}  (>=3 required, max 4)", p.degree);
            println!("  diff. branch number  : {}  (>=3 required)", p.diff_branch);
            println!("  fixed points         : {}", p.fixed_points);
            println!("  anti-fixed points    : {}", p.anti_fixed_points);
            println!("  ANF ops (circuit ~)  : {}", p.anf_ops);
            println!("\n  meets ALL hard criteria: {}", meets_criteria(&p));
        }
    }
}
