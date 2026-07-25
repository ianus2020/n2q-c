//! N2QF file container: round-trip + cross-language interop.

use n2q_c_ref::file::{decrypt_file, encrypt_file};
use n2q_c_ref::modes::Profile;

fn hexkey(h: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    for i in 0..16 {
        k[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    k
}

#[test]
fn n2qf_roundtrip_multiblock() {
    let dir = std::env::temp_dir();
    let src = dir.join("n2q_rs_src.bin");
    let enc = dir.join("n2q_rs.n2q");
    let dec = dir.join("n2q_rs.out");
    // >64 KiB so multiple chunks are exercised
    let data: Vec<u8> = (0..200_000u32).map(|i| (i.wrapping_mul(2654435761)) as u8).collect();
    std::fs::write(&src, &data).unwrap();
    let key = [0x11u8; 16];
    for p in [Profile::Secure, Profile::Fast] {
        encrypt_file(p, &key, src.to_str().unwrap(), enc.to_str().unwrap()).unwrap();
        decrypt_file(&key, enc.to_str().unwrap(), dec.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(&dec).unwrap(), data, "round-trip {p:?}");
    }
}

/// If the Python reference produced /tmp/filedemo/photo.n2q, Rust must decrypt it
/// to the exact original bytes — proving the N2QF container is cross-language.
#[test]
fn n2qf_cross_language_from_python() {
    let enc = "/tmp/filedemo/photo.n2q";
    let orig = "/tmp/filedemo/photo.png";
    if !std::path::Path::new(enc).exists() || !std::path::Path::new(orig).exists() {
        eprintln!("skipped: {enc} not present");
        return;
    }
    let key = hexkey("00112233445566778899aabbccddeeff");
    let out = std::env::temp_dir().join("photo.rs.png");
    decrypt_file(&key, enc, out.to_str().unwrap()).unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(orig).unwrap(),
        "Rust must decrypt the Python-encrypted N2QF file to identical bytes"
    );
}
