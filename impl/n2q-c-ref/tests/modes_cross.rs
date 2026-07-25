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
    let mut raw: HashMap<String, String> = HashMap::new();
    for line in s.lines() {
        if let Some((k, val)) = line.split_once('=') {
            v.insert(k.to_string(), unhex(val));
            raw.insert(k.to_string(), val.to_string());
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

    // audit-log
    let recs = vec![v["log0"].clone(), v["log1"].clone(), v["log2"].clone()];
    assert!(log_verify(&key, &recs, &v["log_head"]), "audit-log verify");
    let mut head = log_genesis();
    let mut rr: Vec<Vec<u8>> = Vec::new();
    for (i, &e) in [&b"login alice"[..], &b"config change"[..], &b"logout bob"[..]].iter().enumerate() {
        let (r, h) = log_append(&head, i as u64, &key, e);
        head = h;
        rr.push(r);
    }
    assert_eq!(&head[..], &v["log_head"][..], "audit-log reproduce head");
    assert_eq!(rr[0], v["log0"], "audit-log reproduce rec0");

    // franking
    let (fm, fcf, fop) = frank_open(&key, &nonce, &v["franking"]).unwrap();
    assert_eq!(fm, b"the abusive message".to_vec(), "franking open");
    assert!(frank_report_verify(&fcf, &fop, &fm), "franking report verify");
    assert_eq!(frank_seal(&key, &nonce, b"the abusive message"), v["franking"], "franking reproduce");

    // seekable
    assert_eq!(seek_chunk(&key, &v["seek"], 1).unwrap(), b"chunk one data".to_vec(), "seekable chunk 1");

    // streaming
    let mut srx = StreamRx::new(key, Profile::Fast);
    assert_eq!(srx.open(b"rtp", &v["strm0"]).unwrap(), b"frame0".to_vec(), "stream0");
    assert_eq!(srx.open(b"rtp", &v["strm1"]).unwrap(), b"frame1 longer".to_vec(), "stream1");
    assert_eq!(srx.open(b"rtp", &v["strm2"]).unwrap(), b"f2".to_vec(), "stream2");
    assert_eq!(StreamTx::new(key, Profile::Fast).seal(b"rtp", b"frame0"), v["strm0"], "stream reproduce");

    // ratchet
    let mut root = [0u8; 16];
    for i in 0..16 {
        root[i] = 0x40 + i as u8;
    }
    let mut rrx = RatchetRx::new(root);
    assert_eq!(rrx.open(b"hdr", &v["rtc0"]).unwrap(), b"r0".to_vec(), "rtc0");
    assert_eq!(rrx.open(b"hdr", &v["rtc1"]).unwrap(), b"r1 data".to_vec(), "rtc1");
    assert_eq!(rrx.open(b"hdr", &v["rtc2"]).unwrap(), b"r2!".to_vec(), "rtc2");
    assert_eq!(RatchetTx::new(root).seal(b"hdr", b"r0"), v["rtc0"], "rtc reproduce");

    // FPE (fpe_card / fpe_ct are digit strings, not hex)
    let tw = b"acct-42";
    assert_eq!(fpe_encrypt(&key, tw, &raw["fpe_card"]), raw["fpe_ct"], "fpe encrypt");
    assert_eq!(fpe_decrypt(&key, tw, &raw["fpe_ct"]), raw["fpe_card"], "fpe decrypt");
}
