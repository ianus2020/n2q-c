//! Known-answer tests: the bitsliced Rust permutation must reproduce the
//! table-based reference vectors of Appendix A exactly. Agreement proves the
//! S-box ANF (bitsliced) matches the S-box table.

use n2q_c_ref::perm::Qp;

#[test]
fn qp320_zero_p12() {
    let qp = Qp::qp320();
    let mut s = [0u64; 5];
    qp.permute(&mut s, 12);
    assert_eq!(
        s,
        [
            0x6c3d34cc09474fbb,
            0x4ad0c1e3cc099b31,
            0xe4493f2ea310ec56,
            0x4e5d2d1f0f612aa3,
            0xa629041fa88cbba2
        ]
    );
}

#[test]
fn qp320_zero_p16() {
    let qp = Qp::qp320();
    let mut s = [0u64; 5];
    qp.permute(&mut s, 16);
    assert_eq!(
        s,
        [
            0x0a80d3fda988ac26,
            0x221c8fdc996d211e,
            0x4970cbaefa3be331,
            0xc52528314439a60d,
            0xb15ae981e77924c9
        ]
    );
}

#[test]
fn qp320_pattern_p12() {
    let qp = Qp::qp320();
    let mut s: [u64; 5] = [
        0x0123456789abcdef,
        0xfedcba9876543210,
        0x0f1e2d3c4b5a6978,
        0x1122334455667788,
        0x8090a0b0c0d0e0f0,
    ];
    qp.permute(&mut s, 12);
    assert_eq!(
        s,
        [
            0xcacee3c01fa6963e,
            0xf808bd597a3cf500,
            0x8ded22db7633bad2,
            0x8f876e846c9ea9a8,
            0x5130139b0338a456
        ]
    );
}

#[test]
fn qp640_zero_p12() {
    let qp = Qp::qp640();
    let mut s = [0u128; 5];
    qp.permute(&mut s, 12);
    assert_eq!(
        s,
        [
            0x92d9767d204356d5bf69412869804a6a,
            0xc810337e8e03196a656eea5765acdcdf,
            0xc8f6c409f8e38370b1621e358303e666,
            0x0b312a32ac9c8523a94c52eb50bcdc8f,
            0x47ed01c11be8cc1d9bd809f54ccff628
        ]
    );
}
