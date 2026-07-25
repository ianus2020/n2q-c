//! N2Q-PW — password-based key derivation (memory-hard).
//!
//! This does **not** invent a new memory-hard primitive. It instantiates
//! **Balloon hashing** (Boneh–Corrigan-Gibbs–Schechter, 2016) — a construction
//! with a proven memory-hardness bound for any cryptographic hash — with
//! [`crate::modes::n128::hash`] (N2Q-Hash-256). The data-*independent*
//! addressing variant is used, so the access pattern never depends on the
//! password: no cache-timing side channel.
//!
//! Cost parameters: `s_cost` = memory in 32-byte blocks, `t_cost` = passes.
//! Tune per deployment; a common floor is s_cost ≈ 2^15 (~1 MiB), t_cost = 3.

use crate::modes::{n128, Profile};

const DELTA: usize = 3; // dependencies per block (Balloon default)

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    n128::hash(Profile::Secure, &v)
}

/// Derive a 32-byte key from `password` and `salt` with the given cost.
/// Deterministic: equal inputs yield equal output. `s_cost` must be ≥ 1.
pub fn derive(password: &[u8], salt: &[u8], s_cost: usize, t_cost: usize) -> [u8; 32] {
    assert!(s_cost >= 1, "s_cost must be >= 1");
    let mut buf: Vec<[u8; 32]> = Vec::with_capacity(s_cost);
    let mut cnt: u64 = 0;

    // Step 1 — expand into the buffer.
    let c = cnt.to_le_bytes();
    buf.push(h(&[&c, password, salt]));
    cnt += 1;
    for m in 1..s_cost {
        let c = cnt.to_le_bytes();
        let prev = buf[m - 1];
        buf.push(h(&[&c, &prev]));
        cnt += 1;
    }

    // Step 2 — mix, t_cost passes.
    for t in 0..t_cost as u64 {
        for m in 0..s_cost {
            let c = cnt.to_le_bytes();
            let prev = buf[(m + s_cost - 1) % s_cost];
            let cur = buf[m];
            buf[m] = h(&[&c, &prev, &cur]);
            cnt += 1;
            for i in 0..DELTA as u64 {
                // data-INDEPENDENT addressing (depends only on salt, t, m, i)
                let c1 = cnt.to_le_bytes();
                let idx = h(&[&c1, salt, &t.to_le_bytes(), &(m as u64).to_le_bytes(), &i.to_le_bytes()]);
                cnt += 1;
                let other = (u64::from_le_bytes(idx[0..8].try_into().unwrap()) as usize) % s_cost;
                let c2 = cnt.to_le_bytes();
                let cur = buf[m];
                let oth = buf[other];
                buf[m] = h(&[&c2, &cur, &oth]);
                cnt += 1;
            }
        }
    }

    buf[s_cost - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = derive(b"correct horse", b"salt-16-bytes!!!", 32, 3);
        let b = derive(b"correct horse", b"salt-16-bytes!!!", 32, 3);
        assert_eq!(a, b);
    }

    #[test]
    fn sensitive_to_password_and_salt() {
        let base = derive(b"pw", b"saltAsaltAsaltA1", 16, 2);
        assert_ne!(base, derive(b"pX", b"saltAsaltAsaltA1", 16, 2));
        assert_ne!(base, derive(b"pw", b"saltBsaltBsaltB2", 16, 2));
    }

    #[test]
    fn cost_changes_output() {
        // Different cost parameters are a different function instance.
        assert_ne!(derive(b"pw", b"s", 16, 2), derive(b"pw", b"s", 16, 3));
        assert_ne!(derive(b"pw", b"s", 16, 2), derive(b"pw", b"s", 32, 2));
    }
}
