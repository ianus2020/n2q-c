//! Fixed N2Q-C constants (Appendix A, milestone M2). Do not edit by hand — these
//! are reproduced by `tools/const-search`.

/// The 5-bit S-box: GF(2^5) inverse wrapped in an invertible affine bijection.
/// APN (differential uniformity 2), nonlinearity 10, algebraic degree 4, no
/// fixed points.
pub const SBOX: [u8; 32] = [
    0x1b, 0x04, 0x0d, 0x06, 0x1f, 0x1c, 0x10, 0x0e, 0x03, 0x15, 0x17, 0x13, 0x14, 0x0f, 0x0b, 0x11,
    0x01, 0x08, 0x05, 0x19, 0x18, 0x16, 0x00, 0x0a, 0x0c, 0x1e, 0x02, 0x07, 0x1a, 0x12, 0x1d, 0x09,
];

/// Linear-layer rotation constants (ra, rb) per lane — full diffusion in 4 rounds.
pub const ROTS_320: [(u32, u32); 5] = [(38, 55), (1, 23), (23, 36), (16, 14), (20, 46)];
pub const ROTS_640: [(u32, u32); 5] = [(75, 7), (89, 21), (56, 111), (30, 54), (25, 52)];

/// Round constants (XORed into lane x2). 16 distinct bytes from the public seed.
pub const RC: [u8; 16] = [
    0x15, 0xe3, 0x2d, 0xa2, 0x5e, 0x5c, 0xab, 0xae, 0xc8, 0x9b, 0xb6, 0xb3, 0xeb, 0xbf, 0xd9, 0xf2,
];

/// Provisional round counts (Appendix A.4; finalised in M4).
pub const ROUNDS_A: usize = 16; // init / finalisation
pub const ROUNDS_B: usize = 12; // data processing
