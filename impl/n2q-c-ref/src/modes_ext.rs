//! Extended modes in pure Rust, built only on the native core (`n128`). No C.
//! Byte-compatible with the Python / Go / C ports — a blob made in one opens in
//! the others. Envelope, key-committing AEAD, convergent, length-hiding, stego.

use crate::modes::{Profile, n128};
use zeroize::Zeroizing;

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
pub fn seal_committing(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    pt: &[u8],
    p: Profile,
) -> Vec<u8> {
    let sealed = n128::seal(p, key, nonce, ad, pt);
    let mut out = commit(key, &sealed[..16]).to_vec();
    out.extend_from_slice(&sealed);
    out
}
pub fn open_committing(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    token: &[u8],
    p: Profile,
) -> Option<Vec<u8>> {
    if token.len() < 32 + 16 {
        return None;
    }
    let (kc, sealed) = token.split_at(32);
    if !crate::modes::ct_eq(&commit(key, &sealed[..16]), kc) {
        return None;
    }
    n128::open(p, key, nonce, ad, sealed)
}

// ---- convergent (dedup) ----
/// Fixed 16-byte master key makes `master_key || content` unambiguous.
///
/// ```compile_fail
/// use n2q_c_ref::{modes::Profile, modes_ext::conv_seal};
/// conv_seal(&[0u8; 17], b"content", Profile::Secure);
/// ```
pub fn conv_seal(mk: &[u8; 16], content: &[u8], p: Profile) -> ([u8; 16], Vec<u8>) {
    let mut m = Zeroizing::new(mk.to_vec());
    m.extend_from_slice(content);
    let h = Zeroizing::new(n128::hash(Profile::Secure, &m));
    let mut dek = [0u8; 16];
    dek.copy_from_slice(&h[..16]);
    let ct = n128::seal(p, &dek, &ZERO, CONV_AD, content);
    (dek, ct)
}
pub fn conv_open(dek: &[u8; 16], ct: &[u8], p: Profile) -> Option<Vec<u8>> {
    n128::open(p, dek, &ZERO, CONV_AD, ct)
}

// ---- length-hiding:  padded = le32(len) | pt | zeros to bucket ----
pub fn seal_padded(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    pt: &[u8],
    p: Profile,
    bucket: usize,
) -> Vec<u8> {
    let need = 4 + pt.len();
    let padded = ((need + bucket - 1) / bucket) * bucket;
    let mut buf = vec![0u8; padded];
    buf[..4].copy_from_slice(&(pt.len() as u32).to_le_bytes());
    buf[4..4 + pt.len()].copy_from_slice(pt);
    n128::seal(p, key, nonce, ad, &buf)
}
pub fn open_padded(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    token: &[u8],
    p: Profile,
) -> Option<Vec<u8>> {
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
pub fn frank_open(
    key: &[u8; 16],
    nonce: &[u8; 16],
    token: &[u8],
) -> Option<(Vec<u8>, [u8; 32], [u8; 16])> {
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
pub fn n2qf_build(key: &[u8; 16], chunks: &[&[u8]], p: Profile) -> std::io::Result<Vec<u8>> {
    crate::file::build(p, key, chunks)
}
pub fn seek_chunk(key: &[u8; 16], buf: &[u8], index: usize) -> Option<Vec<u8>> {
    crate::file::parse(key, buf).ok()?.into_iter().nth(index)
}

// ---- streaming AEAD (seq -> nonce, sliding replay window) ----
pub struct StreamTx {
    key: [u8; 16],
    p: Profile,
    seq: u64,
}
impl StreamTx {
    pub fn new(key: [u8; 16], p: Profile) -> Self {
        Self { key, p, seq: 0 }
    }
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.seq.to_le_bytes());
        let mut out = self.seq.to_le_bytes().to_vec();
        out.extend_from_slice(&n128::seal(self.p, &self.key, &nonce, aad, pt));
        self.seq += 1;
        out
    }
}
pub struct StreamRx {
    key: [u8; 16],
    p: Profile,
    max: u64,
    win: u64,
    started: bool,
}
impl StreamRx {
    pub fn new(key: [u8; 16], p: Profile) -> Self {
        Self {
            key,
            p,
            max: 0,
            win: 0,
            started: false,
        }
    }
    pub fn open(&mut self, aad: &[u8], pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 8 + 16 {
            return None;
        }
        let seq = u64::from_le_bytes(pkt[..8].try_into().unwrap());
        if self.started && seq <= self.max {
            let diff = self.max - seq;
            if diff >= 64 || (self.win >> diff) & 1 != 0 {
                return None;
            }
        }
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&pkt[..8]);
        let pt = n128::open(self.p, &self.key, &nonce, aad, &pkt[8..])?;
        if !self.started {
            self.max = seq;
            self.win = 1;
            self.started = true;
        } else if seq > self.max {
            let shift = seq - self.max;
            self.win = if shift >= 64 {
                1
            } else {
                (self.win << shift) | 1
            };
            self.max = seq;
        } else {
            self.win |= 1 << (self.max - seq);
        }
        Some(pt)
    }
}

// ---- forward-secret ratchet ----
fn rkdf(ck: &[u8], dom: u8) -> [u8; 16] {
    let mut b = vec![dom];
    b.extend_from_slice(ck);
    let h = n128::hash(Profile::Secure, &b);
    let mut o = [0u8; 16];
    o.copy_from_slice(&h[..16]);
    o
}
pub struct RatchetTx {
    ck: [u8; 16],
    seq: u64,
}
impl RatchetTx {
    pub fn new(root: [u8; 16]) -> Self {
        Self { ck: root, seq: 0 }
    }
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let mk = rkdf(&self.ck, 0x01);
        let ck2 = rkdf(&self.ck, 0x02);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.seq.to_le_bytes());
        let mut out = self.seq.to_le_bytes().to_vec();
        out.extend_from_slice(&n128::seal(Profile::Fast, &mk, &nonce, aad, pt));
        self.ck = ck2;
        self.seq += 1;
        out
    }
}
pub struct RatchetRx {
    ck: [u8; 16],
    next: u64,
    skip: std::collections::HashMap<u64, [u8; 16]>,
}
impl RatchetRx {
    pub fn new(root: [u8; 16]) -> Self {
        Self {
            ck: root,
            next: 0,
            skip: std::collections::HashMap::new(),
        }
    }
    pub fn open(&mut self, aad: &[u8], pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 8 + 16 {
            return None;
        }
        let seq = u64::from_le_bytes(pkt[..8].try_into().unwrap());
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&pkt[..8]);
        if seq < self.next {
            let mk = *self.skip.get(&seq)?;
            let pt = n128::open(Profile::Fast, &mk, &nonce, aad, &pkt[8..])?;
            self.skip.remove(&seq);
            return Some(pt);
        }
        if seq - self.next > 64 {
            return None;
        }
        let mut ck = self.ck;
        let mut skipped: Vec<(u64, [u8; 16])> = Vec::new();
        for i in self.next..seq {
            skipped.push((i, rkdf(&ck, 0x01)));
            ck = rkdf(&ck, 0x02);
        }
        let mk = rkdf(&ck, 0x01);
        let cn = rkdf(&ck, 0x02);
        let pt = n128::open(Profile::Fast, &mk, &nonce, aad, &pkt[8..])?;
        for (i, m) in skipped {
            self.skip.insert(i, m);
        }
        while self.skip.len() > 64 {
            if let Some(oldest) = self.skip.keys().min().copied() {
                self.skip.remove(&oldest);
            }
        }
        self.ck = cn;
        self.next = seq + 1;
        Some(pt)
    }
}

// ---- format-preserving encryption (FF1 Feistel, PRF = blind_index) ----
fn fp10(m: u32) -> u64 {
    10u64.pow(m)
}
fn fpe_round(key: &[u8; 16], tw: &[u8], i: usize, n: usize, m: usize, bval: u64) -> u64 {
    let mut buf = vec![i as u8, n as u8, m as u8, tw.len() as u8];
    buf.extend_from_slice(tw);
    buf.extend_from_slice(&bval.to_be_bytes());
    let mac = n128::blind_index(Profile::Secure, key, &buf);
    let md = fp10(m as u32);
    let mut y = 0u64;
    for &b in mac.iter() {
        y = (y * 256 + b as u64) % md;
    }
    y
}
fn fp_atoi(s: &str) -> u64 {
    s.bytes().fold(0u64, |v, c| v * 10 + (c - b'0') as u64)
}
fn fp_fill(mut v: u64, l: usize) -> String {
    let mut b = vec![b'0'; l];
    for i in (0..l).rev() {
        b[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    String::from_utf8(b).unwrap()
}
pub fn fpe_encrypt(key: &[u8; 16], tw: &[u8], s: &str) -> String {
    if !(2..=18).contains(&s.len()) || tw.len() > 255 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return String::new();
    }
    let n = s.len();
    let (u, v) = (n / 2, n - n / 2);
    let (mut a, mut b, mut al, mut bl) = (fp_atoi(&s[..u]), fp_atoi(&s[u..]), u, v);
    for i in 0..10 {
        let m = if i % 2 == 0 { u } else { v };
        let c = (a + fpe_round(key, tw, i, n, m, b)) % fp10(m as u32);
        a = b;
        al = bl;
        b = c;
        bl = m;
    }
    format!("{}{}", fp_fill(a, al), fp_fill(b, bl))
}
pub fn fpe_decrypt(key: &[u8; 16], tw: &[u8], s: &str) -> String {
    if !(2..=18).contains(&s.len()) || tw.len() > 255 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return String::new();
    }
    let n = s.len();
    let (u, v) = (n / 2, n - n / 2);
    let (mut a, mut b, mut al, mut bl) = (fp_atoi(&s[..u]), fp_atoi(&s[u..]), u, v);
    for i in (0..10).rev() {
        let m = if i % 2 == 0 { u } else { v };
        let c = b;
        b = a;
        bl = al;
        let p = fp10(m as u32);
        let y = fpe_round(key, tw, i, n, m, b);
        a = (c + p - y % p) % p;
        al = m;
    }
    format!("{}{}", fp_fill(a, al), fp_fill(b, bl))
}
