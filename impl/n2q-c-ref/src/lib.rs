//! N2Q-C reference implementation (Rust).
//!
//! Constant-time, memory-safe reference for the N2Q-C permutation and modes.
//! Cross-validated against the table-based tool output (Appendix A) and against
//! the C reference. **Research artifact — not for protecting real data yet.**

#![forbid(unsafe_code)]

pub mod consts;
pub mod file;
pub mod frame;
pub mod modes;
pub mod modes_ext;
pub mod perm;
pub mod pw;
