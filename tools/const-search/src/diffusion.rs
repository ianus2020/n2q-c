//! Rotation-constant selection for the linear diffusion layer (SPEC §7.2).
//!
//! Rotation constants are chosen for *linear* diffusion — how fast every input
//! bit comes to influence every output bit — independent of the S-box's
//! nonlinearity. We model one round's bit-dependency as a boolean matrix:
//! pS mixes the 5 bits of each column (a column-full mix), pL spreads bits
//! within each 64/128-bit lane by the two rotations. Composing rounds and
//! finding when the matrix becomes all-ones gives the "full diffusion" round
//! count; we search rotation sets minimising it.

/// One boolean row = `words` u64 covering `nbits` = 5 * lane_width bits.
type Row = Vec<u64>;

fn set_bit(row: &mut Row, i: usize) {
    row[i >> 6] |= 1u64 << (i & 63);
}
fn get_bit(row: &Row, i: usize) -> bool {
    row[i >> 6] & (1u64 << (i & 63)) != 0
}

struct Mat {
    n: usize,
    words: usize,
    rows: Vec<Row>,
}

impl Mat {
    fn zeros(n: usize) -> Self {
        let words = (n + 63) / 64;
        Mat {
            n,
            words,
            rows: vec![vec![0u64; words]; n],
        }
    }
    /// C = self · b  (boolean: OR over shared index of AND).
    fn mul(&self, b: &Mat) -> Mat {
        let mut c = Mat::zeros(self.n);
        for o in 0..self.n {
            let arow = &self.rows[o];
            let crow = &mut c.rows[o];
            for i in 0..self.n {
                if get_bit(arow, i) {
                    let brow = &b.rows[i];
                    for w in 0..self.words {
                        crow[w] |= brow[w];
                    }
                }
            }
        }
        c
    }
    fn is_full(&self) -> bool {
        for row in &self.rows {
            for i in 0..self.n {
                if !get_bit(row, i) {
                    return false;
                }
            }
        }
        true
    }
}

/// Dependency matrix of the S-box layer: each output column bit depends on all
/// 5 input bits of its column.
fn ps_dep(w: usize) -> Mat {
    let n = 5 * w;
    let mut m = Mat::zeros(n);
    for j in 0..w {
        for k in 0..5 {
            let o = k * w + j;
            for lane in 0..5 {
                set_bit(&mut m.rows[o], lane * w + j);
            }
        }
    }
    m
}

/// Dependency matrix of the linear layer x ^= (x>>>ra) ^ (x>>>rb), per lane.
fn pl_dep(w: usize, rots: &[(u32, u32); 5]) -> Mat {
    let n = 5 * w;
    let mut m = Mat::zeros(n);
    for k in 0..5 {
        let (ra, rb) = rots[k];
        for p in 0..w {
            let o = k * w + p;
            set_bit(&mut m.rows[o], k * w + p);
            set_bit(&mut m.rows[o], k * w + ((p + ra as usize) % w));
            set_bit(&mut m.rows[o], k * w + ((p + rb as usize) % w));
        }
    }
    m
}

/// Rounds to full diffusion for a given rotation set, capped at `max_r`.
/// Returns `max_r + 1` if not reached.
pub fn diffusion_rounds(w: usize, rots: &[(u32, u32); 5], max_r: usize) -> usize {
    let round = pl_dep(w, rots).mul(&ps_dep(w));
    let mut acc = round.clone_shallow();
    for r in 1..=max_r {
        if acc.is_full() {
            return r;
        }
        acc = acc.mul(&round);
    }
    if acc.is_full() {
        max_r
    } else {
        max_r + 1
    }
}

impl Mat {
    fn clone_shallow(&self) -> Mat {
        Mat {
            n: self.n,
            words: self.words,
            rows: self.rows.clone(),
        }
    }
}
