//! N2Q modes built on QP, generic over lane width:
//! **N2Q-128** (QP-320, [`n128`]) and **N2Q-256** (QP-640, [`n256`]).
//!
//! Sponge: rate = one lane (x0), capacity = x1..x4, sponge function `p^a`
//! (16 rounds). Padding pad10*1 (append 0x01, zero-fill to a rate multiple, set
//! the final byte's MSB). Domain constants XORed into lane x4 at init:
//! HASH=1, MAC=2, ENC=3, BI=4. Key occupies (x1,x2), the SIV synthetic tag V
//! occupies (x3,x4); tag and V are two lanes wide (16 B for N2Q-128, 32 B for
//! N2Q-256).

use crate::perm::{Lane, Qp};
use zeroize::{Zeroize, Zeroizing};

const DOM_HASH: u8 = 0x01;
const DOM_MAC: u8 = 0x02;
const DOM_ENC: u8 = 0x03;
const DOM_BI: u8 = 0x04;
const DOM_STREAM: u8 = 0x05;

/// Reliability / speed profile: the number of rounds the sponge function runs.
/// **Secure** is the default; **Fast** trades margin for ~2× throughput. The
/// profile is recorded in the wire frame's suite byte (see `frame`), so a single
/// decoder reads both — the two are mutually interoperable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Secure,
    Fast,
}

impl Profile {
    /// Round count of the sponge function for this profile.
    pub const fn rounds(self) -> usize {
        match self {
            Profile::Secure => 16,
            Profile::Fast => 8,
        }
    }
}

fn f<L: Lane>(qp: &Qp, s: &mut [L; 5], r: usize) {
    qp.permute(s, r);
}

/// Absorb pad10*1 with one fixed-size final block, without copying the input.
fn absorb<L: Lane>(qp: &Qp, s: &mut [L; 5], msg: &[u8], r: usize) {
    let mut chunks = msg.chunks_exact(L::BYTES);
    for chunk in &mut chunks {
        s[0] = s[0].xor(L::read_le(chunk));
        f(qp, s, r);
    }
    let rem = chunks.remainder();
    let mut block = Zeroizing::new([0u8; 16]);
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x01;
    block[L::BYTES - 1] |= 0x80;
    s[0] = s[0].xor(L::read_le(&block[..L::BYTES]));
    f(qp, s, r);
}

fn squeeze<L: Lane>(qp: &Qp, s: &mut [L; 5], n: usize, r: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        s[0].write_le(&mut out);
        f(qp, s, r);
    }
    out.truncate(n);
    out
}

fn hash_g<L: Lane>(qp: &Qp, msg: &[u8], outlen: usize, r: usize) -> Vec<u8> {
    let mut s = [L::ZERO; 5];
    s[4] = s[4].xor(L::from_u8(DOM_HASH));
    f(qp, &mut s, r);
    absorb(qp, &mut s, msg, r);
    squeeze(qp, &mut s, outlen, r)
}

fn mac_g<L: Lane>(qp: &Qp, key: &[u8], data: &[u8], dom: u8, r: usize) -> Vec<u8> {
    let b = L::BYTES;
    let mut s = [L::ZERO; 5];
    s[1] = L::read_le(&key[0..b]);
    s[2] = L::read_le(&key[b..2 * b]);
    s[4] = s[4].xor(L::from_u8(dom));
    f(qp, &mut s, r);
    absorb(qp, &mut s, data, r);
    squeeze(qp, &mut s, 2 * b, r) // tag = two lanes
}

fn keystream_g<L: Lane>(qp: &Qp, key: &[u8], v: &[u8], n: usize, r: usize) -> Vec<u8> {
    let b = L::BYTES;
    let mut s = [L::ZERO; 5];
    s[1] = L::read_le(&key[0..b]);
    s[2] = L::read_le(&key[b..2 * b]);
    s[3] = L::read_le(&v[0..b]);
    s[4] = L::read_le(&v[b..2 * b]).xor(L::from_u8(DOM_ENC));
    f(qp, &mut s, r);
    squeeze(qp, &mut s, n, r)
}

/// nonce ‖ le64(|ad|) ‖ ad ‖ le64(|pt|) ‖ pt
fn siv_input(nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(32 + ad.len() + pt.len()));
    v.extend_from_slice(nonce);
    v.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    v.extend_from_slice(ad);
    v.extend_from_slice(&(pt.len() as u64).to_le_bytes());
    v.extend_from_slice(pt);
    v
}

fn seal_g<L: Lane>(
    qp: &Qp,
    key: &[u8],
    nonce: &[u8; 16],
    ad: &[u8],
    pt: &[u8],
    r: usize,
) -> Vec<u8> {
    let v = mac_g::<L>(qp, key, &siv_input(nonce, ad, pt), DOM_MAC, r);
    let ks = Zeroizing::new(keystream_g::<L>(qp, key, &v, pt.len(), r));
    let mut out = v;
    out.extend(pt.iter().zip(ks.iter()).map(|(p, k)| p ^ k));
    out
}

fn open_g<L: Lane>(
    qp: &Qp,
    key: &[u8],
    nonce: &[u8; 16],
    ad: &[u8],
    sealed: &[u8],
    r: usize,
) -> Option<Vec<u8>> {
    let tag = 2 * L::BYTES;
    if sealed.len() < tag {
        return None;
    }
    let (v, ct) = sealed.split_at(tag);
    let ks = Zeroizing::new(keystream_g::<L>(qp, key, v, ct.len(), r));
    let mut pt: Vec<u8> = ct.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect();
    let v2 = mac_g::<L>(qp, key, &siv_input(nonce, ad, &pt), DOM_MAC, r);
    if ct_eq(v, &v2) {
        Some(pt)
    } else {
        pt.zeroize();
        None
    }
}

/// Constant-time byte-slice comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ---- Streaming AEAD (online duplex, nonce-respecting) — SPEC §5.2 ----

fn lane_bytes<L: Lane>(x: L) -> Vec<u8> {
    let mut v = Vec::with_capacity(L::BYTES);
    x.write_le(&mut v);
    v
}

fn stream_init<L: Lane>(qp: &Qp, key: &[u8], nonce: &[u8; 16], r: usize) -> [L; 5] {
    let b = L::BYTES;
    let mut nb = [0u8; 32];
    nb[..16].copy_from_slice(nonce);
    let mut s = [L::ZERO; 5];
    s[1] = L::read_le(&key[0..b]);
    s[2] = L::read_le(&key[b..2 * b]);
    s[3] = L::read_le(&nb[0..b]);
    s[4] = L::read_le(&nb[b..2 * b]).xor(L::from_u8(DOM_STREAM));
    qp.permute(&mut s, r);
    s[3] = s[3].xor(L::read_le(&key[0..b]));
    s[4] = s[4].xor(L::read_le(&key[b..2 * b]));
    s
}

fn stream_ad<L: Lane>(qp: &Qp, s: &mut [L; 5], ad: &[u8], r: usize) {
    absorb(qp, s, ad, r);
    s[4] = s[4].xor(L::from_u8(1)); // domain separation AD | message
}

fn stream_finalize<L: Lane>(qp: &Qp, s: &mut [L; 5], key: &[u8], r: usize) -> Vec<u8> {
    let b = L::BYTES;
    s[3] = s[3].xor(L::read_le(&key[0..b]));
    s[4] = s[4].xor(L::read_le(&key[b..2 * b]));
    qp.permute(s, r);
    let mut tag = lane_bytes(s[3]);
    tag.extend(lane_bytes(s[4]));
    tag // 2 lanes
}

/// Returns ciphertext ‖ tag(2 lanes).
fn stream_seal<L: Lane>(
    qp: &Qp,
    key: &[u8],
    nonce: &[u8; 16],
    ad: &[u8],
    pt: &[u8],
    r: usize,
) -> Vec<u8> {
    let b = L::BYTES;
    let mut s = stream_init::<L>(qp, key, nonce, r);
    stream_ad::<L>(qp, &mut s, ad, r);
    let mut out = Vec::with_capacity(pt.len() + 2 * b);
    let full = pt.len() / b;
    for i in 0..full {
        s[0] = s[0].xor(L::read_le(&pt[i * b..(i + 1) * b]));
        out.extend(lane_bytes(s[0]));
        qp.permute(&mut s, r);
    }
    let rem = &pt[full * b..];
    let l = rem.len();
    let rb = lane_bytes(s[0]);
    for j in 0..l {
        out.push(rem[j] ^ rb[j]);
    }
    let mut padblk = [0u8; 16];
    padblk[..l].copy_from_slice(rem);
    padblk[l] ^= 0x01;
    s[0] = s[0].xor(L::read_le(&padblk[..b]));
    let tag = stream_finalize::<L>(qp, &mut s, key, r);
    out.extend(tag);
    out
}

fn stream_open<L: Lane>(
    qp: &Qp,
    key: &[u8],
    nonce: &[u8; 16],
    ad: &[u8],
    sealed: &[u8],
    r: usize,
) -> Option<Vec<u8>> {
    let b = L::BYTES;
    if sealed.len() < 2 * b {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 2 * b);
    let mut s = stream_init::<L>(qp, key, nonce, r);
    stream_ad::<L>(qp, &mut s, ad, r);
    let mut pt = Vec::with_capacity(ct.len());
    let full = ct.len() / b;
    for i in 0..full {
        let cblk = &ct[i * b..(i + 1) * b];
        let rbytes = lane_bytes(s[0]);
        for j in 0..b {
            pt.push(rbytes[j] ^ cblk[j]);
        }
        s[0] = L::read_le(cblk);
        qp.permute(&mut s, r);
    }
    let rem = &ct[full * b..];
    let l = rem.len();
    let rbytes = lane_bytes(s[0]);
    for j in 0..l {
        pt.push(rem[j] ^ rbytes[j]);
    }
    let mut newr = rbytes;
    newr[..l].copy_from_slice(rem);
    newr[l] ^= 0x01;
    s[0] = L::read_le(&newr[..b]);
    let tag2 = stream_finalize::<L>(qp, &mut s, key, r);
    if ct_eq(tag, &tag2) {
        Some(pt)
    } else {
        pt.zeroize();
        None
    }
}

/// N2Q-128 (QP-320): 128-bit key/nonce/tag, 256-bit hash. Each function takes a
/// [`Profile`] (Secure or Fast); the profile is what a `frame` suite byte records.
pub mod n128 {
    use super::*;

    pub fn hash(p: Profile, msg: &[u8]) -> [u8; 32] {
        hash_g::<u64>(&Qp::qp320(), msg, 32, p.rounds())
            .try_into()
            .unwrap()
    }
    pub fn seal(p: Profile, key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
        seal_g::<u64>(&Qp::qp320(), key, nonce, ad, pt, p.rounds())
    }
    pub fn open(
        p: Profile,
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        open_g::<u64>(&Qp::qp320(), key, nonce, ad, sealed, p.rounds())
    }
    pub fn blind_index(p: Profile, key: &[u8; 16], value: &[u8]) -> [u8; 16] {
        mac_g::<u64>(&Qp::qp320(), key, value, DOM_BI, p.rounds())
            .try_into()
            .unwrap()
    }
    /// Streaming AEAD (online, nonce-respecting): ciphertext ‖ tag.
    pub fn stream_seal(
        p: Profile,
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: &[u8],
        pt: &[u8],
    ) -> Vec<u8> {
        super::stream_seal::<u64>(&Qp::qp320(), key, nonce, ad, pt, p.rounds())
    }
    pub fn stream_open(
        p: Profile,
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        super::stream_open::<u64>(&Qp::qp320(), key, nonce, ad, sealed, p.rounds())
    }
}

/// N2Q-256 (QP-640): 256-bit key/tag, 128-bit nonce, 512-bit hash.
pub mod n256 {
    use super::*;

    pub fn hash(p: Profile, msg: &[u8]) -> [u8; 64] {
        hash_g::<u128>(&Qp::qp640(), msg, 64, p.rounds())
            .try_into()
            .unwrap()
    }
    pub fn seal(p: Profile, key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
        seal_g::<u128>(&Qp::qp640(), key, nonce, ad, pt, p.rounds())
    }
    pub fn open(
        p: Profile,
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        open_g::<u128>(&Qp::qp640(), key, nonce, ad, sealed, p.rounds())
    }
    pub fn blind_index(p: Profile, key: &[u8; 32], value: &[u8]) -> [u8; 32] {
        mac_g::<u128>(&Qp::qp640(), key, value, DOM_BI, p.rounds())
            .try_into()
            .unwrap()
    }
    pub fn stream_seal(
        p: Profile,
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        pt: &[u8],
    ) -> Vec<u8> {
        super::stream_seal::<u128>(&Qp::qp640(), key, nonce, ad, pt, p.rounds())
    }
    pub fn stream_open(
        p: Profile,
        key: &[u8; 32],
        nonce: &[u8; 16],
        ad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        super::stream_open::<u128>(&Qp::qp640(), key, nonce, ad, sealed, p.rounds())
    }
}

/// High-level self-describing tokens. Pick a [`Profile`]; you get an `nqc.`
/// token whose suite byte records mode + size + profile, so a single `open*`
/// reads both Secure and Fast tokens — the two profiles are interoperable.
pub mod capsule {
    use super::{Profile, n128, n256};
    use crate::frame;

    // suite byte: low nibble = size (1=128, 2=256); bit 0x10 = streaming;
    // bit 0x20 = Fast profile. SIV-128-secure=0x01, SIV-128-fast=0x21, etc.
    const FAST_BIT: u8 = 0x20;

    fn is_fast(p: Profile) -> u8 {
        if p == Profile::Fast { FAST_BIT } else { 0 }
    }
    fn profile_of(suite: u8) -> Profile {
        if suite & FAST_BIT != 0 {
            Profile::Fast
        } else {
            Profile::Secure
        }
    }

    /// N2Q-128 SIV → self-describing token.
    pub fn seal128(p: Profile, key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> String {
        frame::encode(0x01 | is_fast(p), nonce, &n128::seal(p, key, nonce, ad, pt))
    }
    /// Decrypt an N2Q-128 SIV token, reading the profile from the suite byte.
    pub fn open128(key: &[u8; 16], ad: &[u8], token: &str) -> Option<Vec<u8>> {
        let (suite, nonce, sealed) = frame::decode(token).ok()?;
        if suite & 0x1f != 0x01 {
            return None; // not SIV-128
        }
        n128::open(profile_of(suite), key, &nonce, ad, &sealed)
    }
    /// N2Q-256 SIV → self-describing token.
    pub fn seal256(p: Profile, key: &[u8; 32], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> String {
        frame::encode(0x02 | is_fast(p), nonce, &n256::seal(p, key, nonce, ad, pt))
    }
    /// Decrypt an N2Q-256 SIV token, reading the profile from the suite byte.
    pub fn open256(key: &[u8; 32], ad: &[u8], token: &str) -> Option<Vec<u8>> {
        let (suite, nonce, sealed) = frame::decode(token).ok()?;
        if suite & 0x1f != 0x02 {
            return None;
        }
        n256::open(profile_of(suite), key, &nonce, ad, &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const KEY32: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];
    const NONCE: [u8; 16] = [0xa5; 16];
    const SEC: Profile = Profile::Secure;
    const FAST: Profile = Profile::Fast;

    #[test]
    fn hash_is_deterministic_and_sensitive() {
        assert_eq!(n128::hash(SEC, b"abc"), n128::hash(SEC, b"abc"));
        assert_ne!(n128::hash(SEC, b"abc"), n128::hash(SEC, b"abd"));
    }

    #[test]
    fn aead_roundtrip_both_profiles() {
        for p in [SEC, FAST] {
            let sealed = n128::seal(p, &KEY, &NONCE, b"header", b"hello n2q-c");
            assert_eq!(
                n128::open(p, &KEY, &NONCE, b"header", &sealed).unwrap(),
                b"hello n2q-c"
            );
        }
    }

    #[test]
    fn profiles_differ_but_each_roundtrips() {
        let s = n128::seal(SEC, &KEY, &NONCE, b"", b"msg");
        let f = n128::seal(FAST, &KEY, &NONCE, b"", b"msg");
        assert_ne!(s, f, "Secure and Fast must produce different ciphertext");
        // a Fast ciphertext opened as Secure must fail (wrong rounds)
        assert!(n128::open(SEC, &KEY, &NONCE, b"", &f).is_none());
    }

    #[test]
    fn tokens_are_interoperable() {
        // ONE decoder reads BOTH profiles, auto-detecting from the suite byte.
        let ts = capsule::seal128(SEC, &KEY, &NONCE, b"ad", b"hi n2q");
        let tf = capsule::seal128(FAST, &KEY, &NONCE, b"ad", b"hi n2q");
        assert_ne!(ts, tf);
        assert_eq!(capsule::open128(&KEY, b"ad", &ts).unwrap(), b"hi n2q");
        assert_eq!(capsule::open128(&KEY, b"ad", &tf).unwrap(), b"hi n2q");
        // 256-bit too
        let t2 = capsule::seal256(FAST, &KEY32, &NONCE, b"", b"big");
        assert_eq!(capsule::open256(&KEY32, b"", &t2).unwrap(), b"big");
    }

    #[test]
    fn aead_rejects_tamper_and_wrong_key() {
        let mut sealed = n128::seal(SEC, &KEY, &NONCE, b"h", b"secret");
        assert!(n128::open(SEC, &KEY, &NONCE, b"other", &sealed).is_none());
        let n = sealed.len() - 1;
        sealed[n] ^= 1;
        assert!(n128::open(SEC, &KEY, &NONCE, b"h", &sealed).is_none());
    }

    #[test]
    fn siv_nonce_misuse_only_leaks_equality() {
        let a = n128::seal(SEC, &KEY, &NONCE, b"", b"msg");
        let b = n128::seal(SEC, &KEY, &NONCE, b"", b"msg");
        assert_eq!(a, b);
        let c = n128::seal(SEC, &KEY, &NONCE, b"", b"msh");
        assert_ne!(a[..16], c[..16]);
    }

    #[test]
    fn blind_index_matches_and_separates() {
        assert_eq!(
            n128::blind_index(SEC, &KEY, b"alice@x.com"),
            n128::blind_index(SEC, &KEY, b"alice@x.com")
        );
        assert_ne!(
            n128::blind_index(SEC, &KEY, b"alice@x.com"),
            n128::blind_index(SEC, &KEY, b"bob@x.com")
        );
    }

    #[test]
    fn aead_roundtrip_256() {
        let sealed = n256::seal(SEC, &KEY32, &NONCE, b"header", b"hello n2q-c-256");
        assert_eq!(
            n256::open(SEC, &KEY32, &NONCE, b"header", &sealed).unwrap(),
            b"hello n2q-c-256"
        );
        assert_eq!(sealed.len(), 32 + 15);
    }

    #[test]
    fn hash_256_is_512_bits() {
        assert_eq!(n256::hash(SEC, b"abc").len(), 64);
        assert_ne!(n256::hash(SEC, b"abc"), n256::hash(SEC, b"abd"));
    }

    #[test]
    fn stream_roundtrip_various_lengths() {
        for p in [SEC, FAST] {
            for len in [0usize, 1, 7, 8, 9, 16, 40, 63] {
                let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let sealed = n128::stream_seal(p, &KEY, &NONCE, b"ad", &pt);
                assert_eq!(sealed.len(), pt.len() + 16);
                assert_eq!(
                    n128::stream_open(p, &KEY, &NONCE, b"ad", &sealed).unwrap(),
                    pt
                );
            }
            for len in [0usize, 15, 16, 17, 100] {
                let pt: Vec<u8> = (0..len).map(|i| (i * 3) as u8).collect();
                let sealed = n256::stream_seal(p, &KEY32, &NONCE, b"", &pt);
                assert_eq!(
                    n256::stream_open(p, &KEY32, &NONCE, b"", &sealed).unwrap(),
                    pt
                );
            }
        }
    }

    #[test]
    fn stream_rejects_tamper() {
        let mut sealed = n128::stream_seal(SEC, &KEY, &NONCE, b"h", b"streaming secret");
        assert!(n128::stream_open(SEC, &KEY, &NONCE, b"other", &sealed).is_none());
        let n = sealed.len() - 1;
        sealed[n] ^= 1;
        assert!(n128::stream_open(SEC, &KEY, &NONCE, b"h", &sealed).is_none());
    }
}
