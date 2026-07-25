//! The QP permutation — constant-time, bitsliced.
//!
//! The S-box is applied as a bitslice: each output bit is the algebraic normal
//! form (ANF) of the 5 input bits, so all 64 (or 128) columns are processed in
//! parallel with data-independent AND/XOR/NOT — no table lookup, no branch, no
//! secret-dependent memory access. Cross-checked against the table-based
//! reference (Appendix A KATs) in `tests/kat.rs`.

use crate::consts::{RC, ROTS_320, ROTS_640};

/// A permutation lane (64 bits for QP-320, 128 for QP-640).
pub trait Lane: Copy {
    const ZERO: Self;
    const ONES: Self;
    /// Lane size in bytes (= sponge rate in bytes).
    const BYTES: usize;
    fn rotr(self, r: u32) -> Self;
    fn xor(self, o: Self) -> Self;
    fn and(self, o: Self) -> Self;
    fn from_u8(v: u8) -> Self;
    /// Read `BYTES` little-endian bytes.
    fn read_le(b: &[u8]) -> Self;
    /// Append `BYTES` little-endian bytes.
    fn write_le(self, out: &mut Vec<u8>);
}

impl Lane for u64 {
    const ZERO: Self = 0;
    const ONES: Self = u64::MAX;
    const BYTES: usize = 8;
    #[inline]
    fn rotr(self, r: u32) -> Self {
        self.rotate_right(r)
    }
    #[inline]
    fn xor(self, o: Self) -> Self {
        self ^ o
    }
    #[inline]
    fn and(self, o: Self) -> Self {
        self & o
    }
    #[inline]
    fn from_u8(v: u8) -> Self {
        v as u64
    }
    #[inline]
    fn read_le(b: &[u8]) -> Self {
        u64::from_le_bytes(b[..8].try_into().unwrap())
    }
    #[inline]
    fn write_le(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

impl Lane for u128 {
    const ZERO: Self = 0;
    const ONES: Self = u128::MAX;
    const BYTES: usize = 16;
    #[inline]
    fn rotr(self, r: u32) -> Self {
        self.rotate_right(r)
    }
    #[inline]
    fn xor(self, o: Self) -> Self {
        self ^ o
    }
    #[inline]
    fn and(self, o: Self) -> Self {
        self & o
    }
    #[inline]
    fn from_u8(v: u8) -> Self {
        v as u128
    }
    #[inline]
    fn read_le(b: &[u8]) -> Self {
        u128::from_le_bytes(b[..16].try_into().unwrap())
    }
    #[inline]
    fn write_le(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

/// S-box in bitsliced form: for each of the 5 output bits, the list of ANF
/// monomials (each a 5-bit mask over the input lanes). Derived once from the
/// fixed table so the table stays the single source of truth.
pub struct Sbox {
    anf: [Vec<u8>; 5],
}

impl Sbox {
    pub fn new(table: &[u8; 32]) -> Self {
        let mut anf: [Vec<u8>; 5] = Default::default();
        for (bit, list) in anf.iter_mut().enumerate() {
            // truth table of output bit `bit`
            let mut tt = [0u8; 32];
            for (x, cell) in tt.iter_mut().enumerate() {
                *cell = (table[x] >> bit) & 1;
            }
            // Möbius transform -> ANF coefficients
            let mut step = 1;
            while step < 32 {
                let mut i = 0;
                while i < 32 {
                    for j in i..i + step {
                        tt[j + step] ^= tt[j];
                    }
                    i += step << 1;
                }
                step <<= 1;
            }
            for (mono, &c) in tt.iter().enumerate() {
                if c & 1 == 1 {
                    list.push(mono as u8);
                }
            }
        }
        Sbox { anf }
    }

    /// Apply the S-box to the 5-lane column vector (bitsliced, constant-time).
    #[inline]
    fn apply<L: Lane>(&self, s: &mut [L; 5]) {
        let mut out = [L::ZERO; 5];
        for (k, list) in self.anf.iter().enumerate() {
            let mut acc = L::ZERO;
            for &m in list {
                let mut term = L::ONES;
                for (i, si) in s.iter().enumerate() {
                    if (m >> i) & 1 == 1 {
                        term = term.and(*si);
                    }
                }
                acc = acc.xor(term);
            }
            out[k] = acc;
        }
        *s = out;
    }
}

/// Parameters that pin one width (rotation constants).
pub struct Qp {
    sbox: Sbox,
    rots: [(u32, u32); 5],
}

impl Qp {
    pub fn qp320() -> Self {
        Qp {
            sbox: Sbox::new(&crate::consts::SBOX),
            rots: ROTS_320,
        }
    }
    pub fn qp640() -> Self {
        Qp {
            sbox: Sbox::new(&crate::consts::SBOX),
            rots: ROTS_640,
        }
    }

    /// Apply `rounds` rounds of QP to the state in place.
    #[allow(clippy::needless_range_loop)] // explicit lane index reads clearer here
    pub fn permute<L: Lane>(&self, s: &mut [L; 5], rounds: usize) {
        for &rc in RC.iter().take(rounds) {
            // pC — round constant into lane x2
            s[2] = s[2].xor(L::from_u8(rc));
            // pS — bitsliced S-box
            self.sbox.apply(s);
            // pL — intra-lane diffusion
            for k in 0..5 {
                let (ra, rb) = self.rots[k];
                s[k] = s[k].xor(s[k].rotr(ra)).xor(s[k].rotr(rb));
            }
        }
    }
}
