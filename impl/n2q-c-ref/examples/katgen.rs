//! Print mode known-answer vectors, used to cross-check the C reference.

use n2q_c_ref::modes::{n128, n256, Profile};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KEY: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const NONCE: [u8; 16] = [0xa5; 16];

const KEY32: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn main() {
    let s = Profile::Secure;
    let f = Profile::Fast;
    println!("== N2Q-128 (Secure) ==");
    println!("hash(\"\")            = {}", hex(&n128::hash(s, b"")));
    println!("hash(\"abc\")         = {}", hex(&n128::hash(s, b"abc")));
    println!("seal(h,\"hello n2q-c\") = {}", hex(&n128::seal(s, &KEY, &NONCE, b"header", b"hello n2q-c")));
    println!("blind_index(\"alice\") = {}", hex(&n128::blind_index(s, &KEY, b"alice@x.com")));
    println!("stream(h,\"hello n2q-c\")={}", hex(&n128::stream_seal(s, &KEY, &NONCE, b"header", b"hello n2q-c")));

    println!("== N2Q-128 (Fast) ==");
    println!("seal(h,\"hello n2q-c\") = {}", hex(&n128::seal(f, &KEY, &NONCE, b"header", b"hello n2q-c")));

    println!("== N2Q-256 (Secure) ==");
    println!("hash(\"abc\")         = {}", hex(&n256::hash(s, b"abc")));
    println!("seal(h,\"hello n2q-c\") = {}", hex(&n256::seal(s, &KEY32, &NONCE, b"header", b"hello n2q-c")));
    println!("blind_index(\"alice\") = {}", hex(&n256::blind_index(s, &KEY32, b"alice@x.com")));
    println!("stream(h,\"hello n2q-c\")={}", hex(&n256::stream_seal(s, &KEY32, &NONCE, b"header", b"hello n2q-c")));

    println!("== N2Q-256 (Fast) ==");
    println!("seal(h,\"hello n2q-c\") = {}", hex(&n256::seal(f, &KEY32, &NONCE, b"header", b"hello n2q-c")));
}
