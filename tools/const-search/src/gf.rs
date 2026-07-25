//! GF(2^5) arithmetic and algebraic S-box constructions.
//!
//! Field GF(2^5) with primitive polynomial x^5 + x^2 + 1 (reduction constant
//! 0x05). Used to build well-understood S-boxes whose cryptographic properties
//! come from algebra, not luck.

use crate::sbox::SIZE;

/// Multiply in GF(2^5).
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut aa = a & 0x1F;
    let mut bb = b & 0x1F;
    for _ in 0..5 {
        if bb & 1 != 0 {
            p ^= aa;
        }
        let carry = aa & 0x10;
        aa = (aa << 1) & 0x1F;
        if carry != 0 {
            aa ^= 0x05; // x^5 ≡ x^2 + 1
        }
        bb >>= 1;
    }
    p & 0x1F
}

fn gf_pow(a: u8, mut e: u32) -> u8 {
    let mut r = 1u8;
    let mut base = a;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

/// Multiplicative inverse in GF(2^5); inv(0) = 0 by convention. x^{-1} = x^30.
pub fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        0
    } else {
        gf_pow(a, 30)
    }
}

/// The inverse S-box: S(x) = x^{-1}. APN, nonlinearity 12, degree 4 for n=5.
pub fn inverse_sbox() -> [u8; SIZE] {
    let mut s = [0u8; SIZE];
    for x in 0..SIZE {
        s[x] = gf_inv(x as u8);
    }
    s
}

/// Gold S-box S(x) = x^3 (APN, nonlinearity 12, but algebraic degree only 2).
pub fn gold3_sbox() -> [u8; SIZE] {
    let mut s = [0u8; SIZE];
    for x in 0..SIZE {
        s[x] = gf_mul(gf_mul(x as u8, x as u8), x as u8);
    }
    s
}

/// Is the 5×5 bit-matrix (given as 5 row-masks) invertible over GF(2)?
pub fn is_invertible(rows: [u8; 5]) -> bool {
    let mut m = rows;
    let mut rank = 0;
    for col in 0..5 {
        // find a pivot row at or below `rank` with bit `col` set
        let mut piv = None;
        for r in rank..5 {
            if m[r] & (1 << col) != 0 {
                piv = Some(r);
                break;
            }
        }
        if let Some(pr) = piv {
            m.swap(rank, pr);
            for r in 0..5 {
                if r != rank && m[r] & (1 << col) != 0 {
                    m[r] ^= m[rank];
                }
            }
            rank += 1;
        }
    }
    rank == 5
}

/// Apply an affine bijection over GF(2)^5: y = M·inv(x) ⊕ c, where M is an
/// invertible 5×5 bit-matrix (rows) and c a constant. Affine wrapping preserves
/// differential uniformity, nonlinearity, and degree while letting us remove
/// fixed points and pick a specific representation.
pub fn affine_wrap(base: &[u8; SIZE], rows: [u8; 5], c: u8) -> [u8; SIZE] {
    let mut s = [0u8; SIZE];
    for x in 0..SIZE {
        let v = base[x];
        let mut y = 0u8;
        for (i, &row) in rows.iter().enumerate() {
            let bit = (row & v).count_ones() & 1;
            y |= (bit as u8) << i;
        }
        s[x] = (y ^ c) & 0x1F;
    }
    s
}
