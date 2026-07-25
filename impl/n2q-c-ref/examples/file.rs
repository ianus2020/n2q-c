//! N2QF binary file container — CLI helper.
//!   cargo run --example file -- encrypt <in> <out>
//!   cargo run --example file -- decrypt <in> <out>
//! Layout: "N2QF" | version(1) | suite(1) | { le32(len) | sealed(tag||ct) }*
//! nonce for chunk i = 16-byte little-endian i. Uses the fixed demo key so the
//! container interoperates byte-for-byte with the Python/Go/C references.

use n2q_c_ref::modes::{n128, Profile};
use std::{env, fs};

const KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const CHUNK: usize = 1 << 16;

fn encrypt(inp: &str, out: &str) {
    let data = fs::read(inp).unwrap();
    let suite: u8 = 0x01 | 0x20; // SIV-128-Fast
    let mut o = Vec::from(&b"N2QF"[..]);
    o.push(1);
    o.push(suite);
    for (idx, chunk) in data.chunks(CHUNK).enumerate() {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(idx as u64).to_le_bytes());
        let sealed = n128::seal(Profile::Fast, &KEY, &nonce, b"", chunk);
        o.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        o.extend_from_slice(&sealed);
    }
    fs::write(out, o).unwrap();
}

fn decrypt(inp: &str, out: &str) {
    let data = fs::read(inp).unwrap();
    assert_eq!(&data[..4], b"N2QF", "not an N2QF file");
    let suite = data[5];
    let profile = if suite & 0x20 != 0 { Profile::Fast } else { Profile::Secure };
    let mut o = Vec::new();
    let mut p = 6usize;
    let mut idx = 0u64;
    while p < data.len() {
        let len = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let sealed = &data[p..p + len];
        p += len;
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&idx.to_le_bytes());
        let pt = n128::open(profile, &KEY, &nonce, b"", sealed).expect("authentication failed");
        o.extend_from_slice(&pt);
        idx += 1;
    }
    fs::write(out, o).unwrap();
}

fn main() {
    let a: Vec<String> = env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("encrypt") => encrypt(&a[2], &a[3]),
        Some("decrypt") => decrypt(&a[2], &a[3]),
        _ => eprintln!("usage: file encrypt|decrypt <in> <out>"),
    }
}
