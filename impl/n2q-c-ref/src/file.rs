//! N2QF binary file container (N2Q-128).
//!
//! Layout: `b"N2QF" | version(1) | suite(1) | { le32(len) | sealed(tag||ct) }*`.
//! The nonce for chunk `i` is its 16-byte little-endian index (deterministic, so
//! it is not stored). Overhead is 6 header bytes + 20 bytes per 64 KiB chunk
//! (~0.03 %). Byte-compatible with the Python / Go / C / PHP / Swift references —
//! a file encrypted in one decrypts in all the others.

use std::fs;
use std::io;

use crate::modes::{n128, Profile};

const CHUNK: usize = 1 << 16;

fn suite_byte(profile: Profile) -> u8 {
    0x01 | if profile == Profile::Fast { 0x20 } else { 0 }
}

/// Encrypt any file (any format — bytes are bytes) into an N2QF container.
pub fn encrypt_file(profile: Profile, key: &[u8; 16], in_path: &str, out_path: &str) -> io::Result<()> {
    let data = fs::read(in_path)?;
    let mut out = vec![b'N', b'2', b'Q', b'F', 1, suite_byte(profile)];
    for (idx, chunk) in data.chunks(CHUNK).enumerate() {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(idx as u64).to_le_bytes());
        let sealed = n128::seal(profile, key, &nonce, b"", chunk);
        out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed);
    }
    fs::write(out_path, out)
}

/// Decrypt an N2QF container; the profile is read from its header.
pub fn decrypt_file(key: &[u8; 16], in_path: &str, out_path: &str) -> io::Result<()> {
    let data = fs::read(in_path)?;
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    if data.len() < 6 || &data[0..4] != b"N2QF" {
        return Err(bad("not an N2QF file"));
    }
    if data[5] & 0x0f != 0x01 {
        return Err(bad("this helper handles the N2Q-128 suite only"));
    }
    let profile = if data[5] & 0x20 != 0 { Profile::Fast } else { Profile::Secure };
    let mut out = Vec::new();
    let mut p = 6usize;
    let mut idx = 0u64;
    while p < data.len() {
        if p + 4 > data.len() {
            return Err(bad("truncated length"));
        }
        let l = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + l > data.len() {
            return Err(bad("truncated chunk"));
        }
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&idx.to_le_bytes());
        let pt = n128::open(profile, key, &nonce, b"", &data[p..p + l])
            .ok_or_else(|| bad("authentication failed"))?;
        out.extend_from_slice(&pt);
        p += l;
        idx += 1;
    }
    fs::write(out_path, out)
}
