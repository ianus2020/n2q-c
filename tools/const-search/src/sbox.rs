//! Cryptographic property analysis of 5-bit S-boxes, and a seeded search.
//!
//! An S-box is a permutation of 0..32 stored as `[u8; 32]`. All metrics here are
//! standard and defined for n = 5 (so 2^n = 32, 2^{n-1} = 16).

pub const N: usize = 5;
pub const SIZE: usize = 1 << N; // 32
pub const MASK: u8 = (SIZE as u8) - 1; // 0x1F

/// Full property report for one S-box.
#[derive(Clone, Debug)]
pub struct Props {
    pub bijective: bool,
    /// Differential uniformity = max DDT entry over a != 0. Lower is better; 2 = APN.
    pub diff_uniformity: u32,
    /// Linearity = max |Walsh| over nonzero components. Lower is better.
    pub linearity: u32,
    /// Nonlinearity = 16 - linearity/2. Higher is better (max 12 for n=5).
    pub nonlinearity: u32,
    /// Algebraic degree = max degree over all 31 nonzero component functions.
    pub degree: u32,
    /// min(wt(Δin) + wt(Δout)) over all possible (nonzero) differentials. ≥3 wanted.
    pub diff_branch: u32,
    pub fixed_points: u32,
    /// x with S(x) == x ^ 0x1F (complement).
    pub anti_fixed_points: u32,
    /// Number of AND/XOR/NOT ops to evaluate the bitsliced ANF (a circuit-cost proxy).
    pub anf_ops: u32,
}

pub fn is_bijective(s: &[u8; SIZE]) -> bool {
    let mut seen = [false; SIZE];
    for &v in s {
        if v as usize >= SIZE || seen[v as usize] {
            return false;
        }
        seen[v as usize] = true;
    }
    true
}

/// Differential uniformity via the difference distribution table.
pub fn diff_uniformity(s: &[u8; SIZE]) -> u32 {
    let mut max = 0u32;
    for a in 1..SIZE as u8 {
        let mut row = [0u32; SIZE];
        for x in 0..SIZE as u8 {
            let b = (s[(x ^ a) as usize] ^ s[x as usize]) as usize;
            row[b] += 1;
        }
        for &c in &row {
            if c > max {
                max = c;
            }
        }
    }
    max
}

/// min Hamming-weight differential (over nonzero DDT entries).
pub fn diff_branch(s: &[u8; SIZE]) -> u32 {
    let mut best = u32::MAX;
    for a in 1..SIZE as u8 {
        let mut row = [0u32; SIZE];
        for x in 0..SIZE as u8 {
            let b = (s[(x ^ a) as usize] ^ s[x as usize]) as usize;
            row[b] += 1;
        }
        for (b, &c) in row.iter().enumerate() {
            if c > 0 {
                let w = a.count_ones() + (b as u8).count_ones();
                if w < best {
                    best = w;
                }
            }
        }
    }
    best
}

fn parity(x: u8) -> u8 {
    x.count_ones() as u8 & 1
}

/// Linearity = max over nonzero output-mask b, all input-mask a, of |Walsh|.
pub fn linearity(s: &[u8; SIZE]) -> u32 {
    let mut max = 0i32;
    for b in 1..SIZE as u8 {
        // component function f(x) = parity(b & S[x])
        let mut f = [0u8; SIZE];
        for x in 0..SIZE {
            f[x] = parity(b & s[x]);
        }
        for a in 0..SIZE as u8 {
            let mut sum = 0i32;
            for x in 0..SIZE as u8 {
                let e = f[x as usize] ^ parity(a & x);
                sum += if e == 0 { 1 } else { -1 };
            }
            let abs = sum.abs();
            if abs > max {
                max = abs;
            }
        }
    }
    max as u32
}

/// Möbius transform in place: truth table -> ANF coefficients.
fn mobius(tt: &mut [u8; SIZE]) {
    let mut step = 1;
    while step < SIZE {
        let mut i = 0;
        while i < SIZE {
            for j in i..i + step {
                tt[j + step] ^= tt[j];
            }
            i += step << 1;
        }
        step <<= 1;
    }
}

/// Algebraic degree = max degree of any nonzero component function.
pub fn algebraic_degree(s: &[u8; SIZE]) -> u32 {
    let mut max_deg = 0u32;
    for b in 1..SIZE as u8 {
        let mut tt = [0u8; SIZE];
        for x in 0..SIZE {
            tt[x] = parity(b & s[x]);
        }
        mobius(&mut tt);
        for (mono, &c) in tt.iter().enumerate() {
            if c & 1 == 1 {
                let d = (mono as u32).count_ones();
                if d > max_deg {
                    max_deg = d;
                }
            }
        }
    }
    max_deg
}

/// Total ANF monomials across the 5 output-bit functions — a rough circuit cost.
pub fn anf_ops(s: &[u8; SIZE]) -> u32 {
    let mut total = 0u32;
    for bit in 0..N {
        let mut tt = [0u8; SIZE];
        for x in 0..SIZE {
            tt[x] = (s[x] >> bit) & 1;
        }
        mobius(&mut tt);
        for &c in tt.iter() {
            if c & 1 == 1 {
                total += 1;
            }
        }
    }
    total
}

pub fn fixed_points(s: &[u8; SIZE]) -> (u32, u32) {
    let mut fp = 0;
    let mut afp = 0;
    for x in 0..SIZE as u8 {
        if s[x as usize] == x {
            fp += 1;
        }
        if s[x as usize] == (x ^ MASK) {
            afp += 1;
        }
    }
    (fp, afp)
}

pub fn analyze(s: &[u8; SIZE]) -> Props {
    let bijective = is_bijective(s);
    let du = diff_uniformity(s);
    let lin = linearity(s);
    let (fp, afp) = fixed_points(s);
    Props {
        bijective,
        diff_uniformity: du,
        linearity: lin,
        nonlinearity: 16 - lin / 2,
        degree: algebraic_degree(s),
        diff_branch: diff_branch(s),
        fixed_points: fp,
        anti_fixed_points: afp,
        anf_ops: anf_ops(s),
    }
}

/// Hard criteria from SPEC §7.1 (with the M2 refinement: constant-time via ANF,
/// so `anf_ops` is a metric to minimise, not a hard gate).
pub fn meets_criteria(p: &Props) -> bool {
    p.bijective
        && p.diff_uniformity <= 4
        && p.nonlinearity >= 10
        && p.degree >= 3
        && p.diff_branch >= 3
        && p.fixed_points == 0
        && p.anti_fixed_points == 0
}
