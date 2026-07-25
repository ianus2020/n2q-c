//! Reference (non-optimized) implementation of the QP permutation, used only to
//! generate known-answer test vectors. The shipping reference will be the
//! constant-time bitsliced C/Rust code of milestone M3; this table-based version
//! defines the *values* those must reproduce.

/// QP state: 5 lanes of `W` bits. We support W=64 (QP-320) and W=128 (QP-640).
pub struct Qp {
    pub w: u32,
    pub sbox: [u8; 32],
    pub rots: [(u32, u32); 5],
    pub rc: Vec<u64>,
}

fn rotr(x: u128, r: u32, w: u32) -> u128 {
    let mask = if w == 128 { u128::MAX } else { (1u128 << w) - 1 };
    let r = r % w;
    ((x >> r) | (x << (w - r))) & mask
}

impl Qp {
    fn mask(&self) -> u128 {
        if self.w == 128 {
            u128::MAX
        } else {
            (1u128 << self.w) - 1
        }
    }

    /// One round on a 5-lane state (lanes as u128, using low `w` bits).
    fn round(&self, s: &mut [u128; 5], i: usize) {
        // pC: add round constant into lane 2.
        s[2] ^= self.rc[i] as u128 & self.mask();
        // pS: apply the 5-bit S-box to each bit-column (table form; value-exact).
        for j in 0..self.w {
            let col = ((s[0] >> j) & 1) as u8
                | (((s[1] >> j) & 1) as u8) << 1
                | (((s[2] >> j) & 1) as u8) << 2
                | (((s[3] >> j) & 1) as u8) << 3
                | (((s[4] >> j) & 1) as u8) << 4;
            let o = self.sbox[col as usize];
            for lane in 0..5 {
                let bit = ((o >> lane) & 1) as u128;
                s[lane] = (s[lane] & !(1u128 << j)) | (bit << j);
            }
        }
        // pL: intra-lane diffusion.
        for lane in 0..5 {
            let (ra, rb) = self.rots[lane];
            s[lane] ^= rotr(s[lane], ra, self.w) ^ rotr(s[lane], rb, self.w);
            s[lane] &= self.mask();
        }
    }

    pub fn permute(&self, s: &mut [u128; 5], rounds: usize) {
        for i in 0..rounds {
            self.round(s, i);
        }
    }
}
