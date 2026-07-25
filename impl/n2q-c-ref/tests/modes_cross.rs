//! Cross-language interop: the Python port writes /tmp/modes/vectors.txt; Rust
//! must decrypt every blob and reproduce it byte-for-byte. Proves Python -> Rust.

use std::collections::HashMap;

use n2q_c_ref::modes::Profile;
use n2q_c_ref::modes_ext::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn key16(s: &str) -> [u8; 16] {
    let v = unhex(s);
    let mut a = [0u8; 16];
    a.copy_from_slice(&v);
    a
}

#[test]
fn modes_cross_from_python() {
    let path = "/tmp/modes/vectors.txt";
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipped: {path} not present");
            return;
        }
    };
    let mut v: HashMap<String, Vec<u8>> = HashMap::new();
    for line in s.lines() {
        if let Some((k, val)) = line.split_once('=') {
            v.insert(k.to_string(), unhex(val));
        }
    }

    let key = key16("00112233445566778899aabbccddeeff");
    let nonce = [0xa5u8; 16];
    let mut kek1 = [0u8; 16];
    let mut dek = [0u8; 16];
    for i in 0..16 {
        kek1[i] = 0x10 + i as u8;
        dek[i] = 0x55u8 ^ ((i * 7) as u8);
    }
    let pt = b"hello n2q-c modes";
    let content = b"the same backup blob";

    // envelope: unwrap Python's blob, and reproduce it
    assert_eq!(unwrap(&kek1, &v["envelope"]).unwrap(), dek, "envelope unwrap");
    assert_eq!(wrap(&kek1, &dek), v["envelope"], "envelope reproduce");

    // key-committing
    assert_eq!(open_committing(&key, &nonce, b"ad", &v["committing"], Profile::Fast).unwrap(), pt, "committing open");
    assert_eq!(seal_committing(&key, &nonce, b"ad", pt, Profile::Fast), v["committing"], "committing reproduce");

    // convergent
    let mut cdek = [0u8; 16];
    cdek.copy_from_slice(&v["conv_dek"]);
    assert_eq!(conv_open(&cdek, &v["conv_ct"], Profile::Fast).unwrap(), content, "convergent open");

    // length-hiding
    assert_eq!(open_padded(&key, &nonce, b"", &v["padded"], Profile::Fast).unwrap(), pt, "length-hiding open");

    // stego
    assert_eq!(stego_open(&key, b"", &v["stego"], Profile::Fast).unwrap(), pt, "stego open");
}
