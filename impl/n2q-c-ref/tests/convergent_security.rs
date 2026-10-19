use n2q_c_ref::modes::{n128, Profile};
use n2q_c_ref::modes_ext::{conv_open, conv_seal, open_committing, seal_committing};

#[test]
fn convergent_fixed_boundary_keeps_valid_bytes() {
    let key = [b'A';16];
    for p in [Profile::Fast,Profile::Secure] {
        let (dek,ct) = conv_seal(&key,b"Bpayload",p);
        let mut legacy = key.to_vec(); legacy.extend_from_slice(b"Bpayload");
        assert_eq!(dek, n128::hash(Profile::Secure,&legacy)[..16]);
        assert_eq!(conv_open(&dek,&ct,p).unwrap(),b"Bpayload");
        assert_eq!(conv_seal(&key,b"Bpayload",p),(dek,ct));
    }
    assert!(<&[u8;16]>::try_from(&[b'A';17][..]).is_err());
}

#[test]
fn committing_rejects_every_commitment_bit() {
    let key = [0x42;16]; let nonce = [0xa5;16];
    for p in [Profile::Fast,Profile::Secure] {
        let ct = seal_committing(&key,&nonce,b"ad",b"payload",p);
        assert_eq!(open_committing(&key,&nonce,b"ad",&ct,p).unwrap(),b"payload");
        for bit in 0..256 {
            let mut bad = ct.clone(); bad[bit/8] ^= 1 << (bit%8);
            assert!(open_committing(&key,&nonce,b"ad",&bad,p).is_none());
        }
    }
}
