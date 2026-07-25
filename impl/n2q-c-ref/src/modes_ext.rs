//! Extended modes in pure Rust, built only on the native core (`n128`). No C.
//! Byte-compatible with the Python / Go / C ports — a blob made in one opens in
//! the others. Envelope, key-committing AEAD, convergent, length-hiding, stego.

use crate::modes::{n128, Profile};

const ENV_AD: &[u8] = b"n2q-envelope-v1";
const CONV_AD: &[u8] = b"n2q-conv";
const ZERO: [u8; 16] = [0u8; 16];

// ---- envelope + rotation ----
pub fn wrap(kek: &[u8; 16], dek: &[u8]) -> Vec<u8> {
    n128::seal(Profile::Secure, kek, &ZERO, ENV_AD, dek)
}
pub fn unwrap(kek: &[u8; 16], blob: &[u8]) -> Option<Vec<u8>> {
    n128::open(Profile::Secure, kek, &ZERO, ENV_AD, blob)
}
pub fn rewrap(old: &[u8; 16], new: &[u8; 16], blob: &[u8]) -> Option<Vec<u8>> {
    unwrap(old, blob).map(|d| wrap(new, &d))
}

// ---- key-committing AEAD:  token = KC(32) | sealed ----
fn commit(key: &[u8; 16], tag: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 16 + tag.len());
    buf.push(0x07);
    buf.extend_from_slice(key);
    buf.extend_from_slice(tag);
    n128::hash(Profile::Secure, &buf)
}
pub fn seal_committing(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], p: Profile) -> Vec<u8> {
    let sealed = n128::seal(p, key, nonce, ad, pt);
    let mut out = commit(key, &sealed[..16]).to_vec();
    out.extend_from_slice(&sealed);
    out
}
pub fn open_committing(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], token: &[u8], p: Profile) -> Option<Vec<u8>> {
    if token.len() < 32 + 16 {
        return None;
    }
    let (kc, sealed) = token.split_at(32);
    if &commit(key, &sealed[..16])[..] != kc {
        return None;
    }
    n128::open(p, key, nonce, ad, sealed)
}

// ---- convergent (dedup) ----
pub fn conv_seal(mk: &[u8], content: &[u8], p: Profile) -> ([u8; 16], Vec<u8>) {
    let mut m = mk.to_vec();
    m.extend_from_slice(content);
    let h = n128::hash(Profile::Secure, &m);
    let mut dek = [0u8; 16];
    dek.copy_from_slice(&h[..16]);
    let ct = n128::seal(p, &dek, &ZERO, CONV_AD, content);
    (dek, ct)
}
pub fn conv_open(dek: &[u8; 16], ct: &[u8], p: Profile) -> Option<Vec<u8>> {
    n128::open(p, dek, &ZERO, CONV_AD, ct)
}

// ---- length-hiding:  padded = le32(len) | pt | zeros to bucket ----
pub fn seal_padded(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], p: Profile, bucket: usize) -> Vec<u8> {
    let need = 4 + pt.len();
    let padded = ((need + bucket - 1) / bucket) * bucket;
    let mut buf = vec![0u8; padded];
    buf[..4].copy_from_slice(&(pt.len() as u32).to_le_bytes());
    buf[4..4 + pt.len()].copy_from_slice(pt);
    n128::seal(p, key, nonce, ad, &buf)
}
pub fn open_padded(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], token: &[u8], p: Profile) -> Option<Vec<u8>> {
    let buf = n128::open(p, key, nonce, ad, token)?;
    if buf.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if 4 + n > buf.len() {
        return None;
    }
    Some(buf[4..4 + n].to_vec())
}

// ---- stego framing:  out = nonce(16) | sealed ----
pub fn stego_seal(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], p: Profile) -> Vec<u8> {
    let mut out = nonce.to_vec();
    out.extend_from_slice(&n128::seal(p, key, nonce, ad, pt));
    out
}
pub fn stego_open(key: &[u8; 16], ad: &[u8], blob: &[u8], p: Profile) -> Option<Vec<u8>> {
    if blob.len() < 16 {
        return None;
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&blob[..16]);
    n128::open(p, key, &nonce, ad, &blob[16..])
}

// ---- append-only, tamper-evident log (hash chain) ----
const LOG_AD: &[u8] = b"n2q-log";

pub fn log_genesis() -> [u8; 32] {
    n128::hash(Profile::Secure, b"n2q-log-genesis")
}
pub fn log_append(head: &[u8], seq: u64, key: &[u8; 16], entry: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&seq.to_le_bytes());
    let sealed = n128::seal(Profile::Secure, key, &nonce, LOG_AD, entry);
    let mut record = seq.to_le_bytes().to_vec();
    record.extend_from_slice(&sealed);
    let mut hin = head.to_vec();
    hin.extend_from_slice(&record);
    (record, n128::hash(Profile::Secure, &hin))
}
pub fn log_verify(key: &[u8; 16], records: &[Vec<u8>], expected_head: &[u8]) -> bool {
    let mut head = log_genesis();
    for (i, rec) in records.iter().enumerate() {
        if rec.len() < 8 + 16 || u64::from_le_bytes(rec[..8].try_into().unwrap()) != i as u64 {
            return false;
        }
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&rec[..8]);
        if n128::open(Profile::Secure, key, &nonce, LOG_AD, &rec[8..]).is_none() {
            return false;
        }
        let mut hin = head.to_vec();
        hin.extend_from_slice(rec);
        head = n128::hash(Profile::Secure, &hin);
    }
    &head[..] == expected_head
}

// ---- message franking ----
fn frank_opening(key: &[u8; 16], nonce: &[u8; 16]) -> [u8; 16] {
    let mut b = vec![0x08u8];
    b.extend_from_slice(key);
    b.extend_from_slice(nonce);
    let h = n128::hash(Profile::Secure, &b);
    let mut o = [0u8; 16];
    o.copy_from_slice(&h[..16]);
    o
}
fn frank_commit(opening: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut b = vec![0x09u8];
    b.extend_from_slice(opening);
    b.extend_from_slice(msg);
    n128::hash(Profile::Secure, &b)
}
pub fn frank_seal(key: &[u8; 16], nonce: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    let cf = frank_commit(&frank_opening(key, nonce), msg);
    let mut out = cf.to_vec();
    out.extend_from_slice(&n128::seal(Profile::Secure, key, nonce, &cf, msg));
    out
}
pub fn frank_open(key: &[u8; 16], nonce: &[u8; 16], token: &[u8]) -> Option<(Vec<u8>, [u8; 32], [u8; 16])> {
    if token.len() < 32 + 16 {
        return None;
    }
    let cf: [u8; 32] = token[..32].try_into().unwrap();
    let msg = n128::open(Profile::Secure, key, nonce, &cf, &token[32..])?;
    let op = frank_opening(key, nonce);
    if frank_commit(&op, &msg) != cf {
        return None;
    }
    Some((msg, cf, op))
}
pub fn frank_report_verify(cf: &[u8; 32], opening: &[u8; 16], msg: &[u8]) -> bool {
    &frank_commit(opening, msg) == cf
}

// ---- seekable N2QF ----
pub fn n2qf_build(key: &[u8; 16], chunks: &[&[u8]], p: Profile) -> Vec<u8> {
    let suite = 0x01u8 | if p == Profile::Fast { 0x20 } else { 0 };
    let mut out = b"N2QF".to_vec();
    out.push(1);
    out.push(suite);
    for (i, ch) in chunks.iter().enumerate() {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let sealed = n128::seal(p, key, &nonce, b"", ch);
        out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed);
    }
    out
}
pub fn seek_chunk(key: &[u8; 16], buf: &[u8], index: usize) -> Option<Vec<u8>> {
    if buf.len() < 6 || &buf[..4] != b"N2QF" {
        return None;
    }
    let p = if buf[5] & 0x20 != 0 { Profile::Fast } else { Profile::Secure };
    let (mut pos, mut i) = (6usize, 0usize);
    while pos + 4 <= buf.len() {
        let l = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if i == index {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
            return n128::open(p, key, &nonce, b"", &buf[pos..pos + l]);
        }
        pos += l;
        i += 1;
    }
    None
}
