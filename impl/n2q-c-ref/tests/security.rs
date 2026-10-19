use n2q_c_ref::{file, frame, modes::Profile};
#[test]
fn rejects_truncation_splicing_and_lengths() {
    let key = [0; 16];
    for profile in [Profile::Secure, Profile::Fast] {
        let a = file::build(profile, &key, &[b"first", b"second"]).unwrap();
        let b = file::build(profile, &key, &[b"other", b"second"]).unwrap();
        assert_eq!(
            file::parse(&key, &a).unwrap(),
            [b"first".to_vec(), b"second".to_vec()]
        );
        let mut cases = vec![
            a[..22].to_vec(),
            a[..48].to_vec(),
            a[..a.len() - 1].to_vec(),
            [a.as_slice(), b"x"].concat(),
            [&a[..48], &b[48..]].concat(),
        ];
        for len in [0u32, 15, 65553, u32::MAX] {
            let mut x = a.clone();
            x[23..27].copy_from_slice(&len.to_le_bytes());
            cases.push(x);
        }
        for x in cases {
            assert!(file::parse(&key, &x).is_err());
        }
    }
}
#[test]
fn failed_decrypt_preserves_output() {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("bad");
    let out = d.path().join("out");
    std::fs::write(&src, b"N2QF\x01\x01").unwrap();
    std::fs::write(&out, b"keep").unwrap();
    assert!(file::decrypt_file(&[0; 16], src.to_str().unwrap(), out.to_str().unwrap()).is_err());
    assert_eq!(std::fs::read(&out).unwrap(), b"keep");
}
#[test]
fn strict_frames() {
    let t = frame::encode(1, &[0; 16], &[0; 16]);
    assert!(frame::decode(&(t.clone() + "\n")).is_err());
    assert!(frame::decode(&frame::encode(0x81, &[0; 16], &[0; 16])).is_err());
    // 34 decoded bytes: last sextet has four unused bits; alternative encoding rejected.
    let mut b = t.into_bytes();
    let last = b.len() - 1;
    b[last] = b'B';
    assert!(frame::decode(std::str::from_utf8(&b).unwrap()).is_err());
}
#[test]
fn invalid_fpe_does_not_panic() {
    for s in ["", "1", "жж", "1a", "1234567890123456789"] {
        assert!(n2q_c_ref::modes_ext::fpe_encrypt(&[0; 16], b"", s).is_empty());
        assert!(n2q_c_ref::modes_ext::fpe_decrypt(&[0; 16], b"", s).is_empty());
    }
}
