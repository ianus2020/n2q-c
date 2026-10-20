//! Reproducible experiments, not a security certification. Public test keys only.
use n2q_c_ref::consts::{RC, ROTS_320, ROTS_640, SBOX};
use n2q_c_ref::modes::{n128, n256, Profile};
use n2q_c_ref::perm::Qp;
use std::{collections::HashMap, hint::black_box, time::Instant};

const ROUNDS: [usize; 7] = [1, 2, 3, 4, 5, 8, 16];
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
        x ^ (x >> 31)
    }
    fn state(&mut self, w: usize) -> [u128; 5] {
        std::array::from_fn(|_| {
            let lo = self.next() as u128;
            if w == 64 {
                lo
            } else {
                lo | (self.next() as u128) << 64
            }
        })
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}
fn perm(q: &Qp, s: [u128; 5], r: usize, w: usize) -> [u128; 5] {
    if w == 64 {
        let mut t = s.map(|x| x as u64);
        q.permute(&mut t, r);
        t.map(|x| x as u128)
    } else {
        let mut t = s;
        q.permute(&mut t, r);
        t
    }
}
fn rotr(x: u128, r: u32, w: usize) -> u128 {
    if w == 64 {
        (x as u64).rotate_right(r) as u128
    } else {
        x.rotate_right(r)
    }
}
fn table_perm(mut s: [u128; 5], r: usize, w: usize) -> [u128; 5] {
    let rots = if w == 64 { ROTS_320 } else { ROTS_640 };
    for &rc in &RC[..r] {
        s[2] ^= rc as u128;
        let mut t = [0u128; 5];
        for j in 0..w {
            let x = (0..5).fold(0usize, |a, k| a | (((s[k] >> j) & 1) as usize) << k);
            for (k, v) in t.iter_mut().enumerate() {
                *v |= (((SBOX[x] >> k) & 1) as u128) << j;
            }
        }
        s = std::array::from_fn(|k| t[k] ^ rotr(t[k], rots[k].0, w) ^ rotr(t[k], rots[k].1, w));
    }
    s
}
fn xor(a: [u128; 5], b: [u128; 5]) -> [u128; 5] {
    std::array::from_fn(|k| a[k] ^ b[k])
}
fn flip(mut s: [u128; 5], bit: usize, w: usize) -> [u128; 5] {
    s[bit / w] ^= 1u128 << (bit % w);
    s
}
fn oracle(q: &Qp, w: usize, quick: bool) {
    let mut rng = Rng(0x4f5241434c45);
    let mut n = 0;
    for r in 0..=16 {
        for _ in 0..if quick { 4 } else { 128 } {
            let s = rng.state(w);
            assert_eq!(perm(q, s, r, w), table_perm(s, r, w));
            n += 1;
        }
    }
    println!(
        "{{\"kind\":\"table_oracle\",\"width\":{},\"cases\":{n},\"mismatches\":0}}",
        w * 5
    );
}
fn avalanche(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 32 } else { 1024 };
    let bits = 5 * w;
    // Hoeffding + union bound across all input/output pairs and all 14 tables.
    let epsilon = ((2.0 * (bits * bits * 14) as f64 / 0.01).ln() / (2.0 * n as f64)).sqrt();
    for r in ROUNDS {
        let mut rng = Rng(0x534143 + r as u64);
        let mut counts = vec![0u32; bits * bits];
        let mut total = 0u64;
        for _ in 0..n {
            let s = rng.state(w);
            let a = perm(q, s, r, w);
            for i in 0..bits {
                let d = xor(a, perm(q, flip(s, i, w), r, w));
                for (k, &lane) in d.iter().enumerate() {
                    total += lane.count_ones() as u64;
                    let mut x = lane;
                    while x != 0 {
                        let j = x.trailing_zeros() as usize;
                        counts[i * bits + k * w + j] += 1;
                        x &= x - 1;
                    }
                }
            }
        }
        let completeness = counts.iter().filter(|&&x| x != 0).count() as f64 / counts.len() as f64;
        let max_bias = counts
            .iter()
            .map(|&x| (x as f64 / n as f64 - 0.5).abs())
            .fold(0.0, f64::max);
        let flagged = counts
            .iter()
            .filter(|&&x| (x as f64 / n as f64 - 0.5).abs() > epsilon)
            .count();
        let mean = total as f64 / (n * bits * bits) as f64;
        println!("{{\"kind\":\"avalanche\",\"width\":{bits},\"rounds\":{r},\"samples_per_input_bit\":{n},\"pairs\":{},\"completeness\":{completeness},\"mean_flip\":{mean},\"max_abs_bias\":{max_bias},\"family_alpha\":0.01,\"hoeffding_epsilon\":{epsilon},\"flagged_pairs\":{flagged}}}", bits * bits);
    }
}
fn differential(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 1024 } else { 65536 };
    let diffs = [
        [1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1u128 << (w - 1)],
        [1; 5],
        [3, 0, 1, 0, 0],
    ];
    for r in [1, 2, 3, 4, 8, 16] {
        for (di, din) in diffs.iter().enumerate() {
            let mut rng = Rng(0x44494646 + r as u64 + di as u64 * 17);
            let mut counts = HashMap::<[u128; 5], u32>::new();
            for _ in 0..n {
                let s = rng.state(w);
                *counts
                    .entry(xor(perm(q, s, r, w), perm(q, xor(s, *din), r, w)))
                    .or_default() += 1;
            }
            let max = counts.values().copied().max().unwrap();
            println!("{{\"kind\":\"differential\",\"width\":{},\"rounds\":{r},\"difference_id\":{di},\"samples\":{n},\"distinct\":{},\"max_count\":{max},\"max_empirical_frequency\":{}}}", w * 5, counts.len(), max as f64 / n as f64);
        }
    }
}
fn inverse_row0(w: usize, ra: usize, rb: usize) -> u128 {
    let mut rows: Vec<(u128, u128)> = (0..w)
        .map(|j| {
            (
                (1u128 << j) ^ (1u128 << ((j + ra) % w)) ^ (1u128 << ((j + rb) % w)),
                1u128 << j,
            )
        })
        .collect();
    for j in 0..w {
        let pivot = (j..w).find(|&k| rows[k].0 >> j & 1 != 0).unwrap();
        rows.swap(j, pivot);
        for k in 0..w {
            if k != j && rows[k].0 >> j & 1 != 0 {
                rows[k].0 ^= rows[j].0;
                rows[k].1 ^= rows[j].1;
            }
        }
    }
    rows[0].1
}
fn linear(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 1024 } else { 262144 };
    let rots = if w == 64 { ROTS_320 } else { ROTS_640 };
    let inverse: [u128; 5] =
        std::array::from_fn(|k| inverse_row0(w, rots[k].0 as usize, rots[k].1 as usize));
    let mut best = (0u8, 0u8, 0i32);
    for a in 1..32u8 {
        for b in 1..32u8 {
            let corr: i32 = (0..32u8)
                .map(|x| {
                    if ((a & x).count_ones() ^ (b & SBOX[x as usize]).count_ones()) & 1 == 0 {
                        1
                    } else {
                        -1
                    }
                })
                .sum();
            if corr.abs() > best.2.abs() {
                best = (a, b, corr);
            }
        }
    }
    let mut masks = Vec::new();
    for pos in [0, w / 3, w / 2, w - 1] {
        masks.push((
            std::array::from_fn::<_, 5, _>(|k| {
                if best.0 >> k & 1 != 0 {
                    1u128 << pos
                } else {
                    0
                }
            }),
            std::array::from_fn::<_, 5, _>(|k| {
                if best.1 >> k & 1 != 0 {
                    rotr(inverse[k], ((w - pos) % w) as u32, w)
                } else {
                    0
                }
            }),
        ));
    }
    let mut rng = Rng(0x4c494e454152);
    for _ in 0..4 {
        masks.push((rng.state(w), rng.state(w)));
    }
    let epsilon = (2.0 * (2.0 * 96.0_f64 / 0.01).ln() / n as f64).sqrt();
    for r in [1, 2, 3, 4, 8, 16] {
        let mut rng = Rng(0x4c494e + r as u64);
        let mut sums = [0i64; 8];
        for _ in 0..n {
            let s = rng.state(w);
            let out = perm(q, s, r, w);
            for (i, (a, b)) in masks.iter().enumerate() {
                let parity: u32 = (0..5)
                    .map(|k| (a[k] & s[k]).count_ones() + (b[k] & out[k]).count_ones())
                    .sum();
                sums[i] += if parity & 1 == 0 { 1 } else { -1 };
            }
        }
        let correlations: Vec<f64> = sums.iter().map(|&s| s as f64 / n as f64).collect();
        if r == 1 && !quick {
            for c in &correlations[..4] {
                assert!((c.abs() - 0.375).abs() < epsilon);
            }
        }
        let flagged = correlations.iter().filter(|x| x.abs() > epsilon).count();
        println!("{{\"kind\":\"linear_masks\",\"width\":{},\"rounds\":{r},\"samples\":{n},\"mask_pairs\":8,\"correlations\":{correlations:?},\"family_alpha\":0.01,\"hoeffding_epsilon\":{epsilon},\"flagged_pairs\":{flagged},\"round1_positive_control_abs_correlation\":0.375}}",w*5);
    }
}
fn cubes(q: &Qp, w: usize, quick: bool) {
    for dim in if quick { vec![8] } else { vec![8, 12, 16] } {
        for layout in 0..2 {
            let positions: Vec<usize> = (0..dim)
                .map(|i| if layout == 0 { i } else { (i * 37) % (5 * w) })
                .collect();
            for r in ROUNDS {
                let mut rng = Rng(0x43554245 + dim as u64 + layout);
                let mut zero = 0;
                for _ in 0..4 {
                    let mut base = rng.state(w);
                    for &p in &positions {
                        base[p / w] &= !(1u128 << (p % w));
                    }
                    let mut acc = [0u128; 5];
                    for mask in 0..1usize << dim {
                        let mut s = base;
                        for (i, &p) in positions.iter().enumerate() {
                            if mask >> i & 1 != 0 {
                                s = flip(s, p, w);
                            }
                        }
                        acc = xor(acc, perm(q, s, r, w));
                    }
                    if acc == [0; 5] {
                        zero += 1;
                    }
                }
                println!("{{\"kind\":\"cube\",\"width\":{},\"rounds\":{r},\"dimension\":{dim},\"layout\":{layout},\"bases\":4,\"zero_sums\":{zero}}}", w * 5);
            }
        }
    }
}
fn rotational(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 8 } else { 128 };
    for r in [1, 2, 4, 8, 16] {
        let mut rng = Rng(0x524f5441 + r as u64);
        let mut hold = 0;
        for shift in 1..w {
            for _ in 0..n {
                let s = rng.state(w);
                let sr = s.map(|x| rotr(x, shift as u32, w));
                if perm(q, sr, r, w) == perm(q, s, r, w).map(|x| rotr(x, shift as u32, w)) {
                    hold += 1;
                }
            }
        }
        println!("{{\"kind\":\"rotational\",\"width\":{},\"rounds\":{r},\"offsets\":{},\"trials\":{},\"relations\":{hold}}}", w * 5, w - 1, n * (w - 1));
    }
}
fn reduced_hash(q: &Qp, msg: &[u8], r: usize, w: usize) -> Vec<u8> {
    let b = w / 8;
    let mut s = perm(q, [0, 0, 0, 0, 1], r, w);
    let mut padded = msg.to_vec();
    padded.push(1);
    while padded.len() % b != 0 {
        padded.push(0);
    }
    *padded.last_mut().unwrap() |= 0x80;
    for chunk in padded.chunks(b) {
        let mut block = [0u8; 16];
        block[..b].copy_from_slice(chunk);
        s[0] ^= u128::from_le_bytes(block);
        s = perm(q, s, r, w);
    }
    let mut out = Vec::new();
    for _ in 0..4 {
        out.extend_from_slice(&s[0].to_le_bytes()[..b]);
        s = perm(q, s, r, w);
    }
    out
}
fn hashes(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 512 } else { 32768 };
    for r in [1, 2, 3, 4, 8, 16] {
        let mut full = HashMap::<Vec<u8>, usize>::new();
        let mut prefixes = [0u32; 65536];
        let mut full_collisions = 0u64;
        let mut truncated_pairs = 0u64;
        let mut nearest = u32::MAX;
        let mut previous: Option<Vec<u8>> = None;
        for i in 0..n as u64 {
            let m = i.to_le_bytes();
            let h = reduced_hash(q, &m, r, w);
            if r == 8 || r == 16 {
                let p = if r == 8 {
                    Profile::Fast
                } else {
                    Profile::Secure
                };
                if w == 64 {
                    assert_eq!(h, n128::hash(p, &m));
                } else {
                    assert_eq!(h, n256::hash(p, &m));
                }
            }
            let prefix = u16::from_le_bytes([h[0], h[1]]) as usize;
            truncated_pairs += prefixes[prefix] as u64;
            prefixes[prefix] += 1;
            if let Some(last) = &previous {
                nearest = nearest.min(last.iter().zip(&h).map(|(a, b)| (a ^ b).count_ones()).sum());
            }
            previous = Some(h.clone());
            full_collisions += *full.get(&h).unwrap_or(&0) as u64;
            *full.entry(h).or_default() += 1;
        }
        println!("{{\"kind\":\"hash_collision\",\"width\":{},\"rounds\":{r},\"messages\":{n},\"full_collision_pairs\":{full_collisions},\"truncated_16bit_collision_pairs\":{truncated_pairs},\"min_adjacent_hamming_distance\":{nearest}}}", w * 5);
    }
}
fn seal(
    w: usize,
    stream: bool,
    p: Profile,
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    match (w, stream) {
        (64, false) => n128::seal(p, key[..16].try_into().unwrap(), nonce, ad, pt),
        (64, true) => n128::stream_seal(p, key[..16].try_into().unwrap(), nonce, ad, pt),
        (_, false) => n256::seal(p, key, nonce, ad, pt),
        (_, true) => n256::stream_seal(p, key, nonce, ad, pt),
    }
}
fn open(
    w: usize,
    stream: bool,
    p: Profile,
    key: &[u8; 32],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
) -> Option<Vec<u8>> {
    match (w, stream) {
        (64, false) => n128::open(p, key[..16].try_into().unwrap(), nonce, ad, ct),
        (64, true) => n128::stream_open(p, key[..16].try_into().unwrap(), nonce, ad, ct),
        (_, false) => n256::open(p, key, nonce, ad, ct),
        (_, true) => n256::stream_open(p, key, nonce, ad, ct),
    }
}
fn aead(w: usize, quick: bool) {
    let key = [0x42u8; 32];
    let nonce = [0xa5; 16];
    for p in [Profile::Fast, Profile::Secure] {
        for stream in [false, true] {
            let mut rejects = 0u64;
            let mut roundtrips = 0u64;
            let mut rng = Rng(0x41454144);
            for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
                for alen in [0, 1, 7, 8, 15, 16, 17] {
                    let pt = rng.bytes(len);
                    let ad = rng.bytes(alen);
                    let ct = seal(w, stream, p, &key, &nonce, &ad, &pt);
                    assert_eq!(open(w, stream, p, &key, &nonce, &ad, &ct), Some(pt));
                    roundtrips += 1;
                    // Exhaust every single bit in ciphertext AND tag.
                    for bit in 0..ct.len() * 8 {
                        let mut bad = ct.clone();
                        bad[bit / 8] ^= 1 << (bit % 8);
                        assert!(open(w, stream, p, &key, &nonce, &ad, &bad).is_none());
                        rejects += 1;
                    }
                    // Every truncation; insertion; wrong profile/mode/key/nonce/AD.
                    for end in 0..ct.len() {
                        assert!(open(w, stream, p, &key, &nonce, &ad, &ct[..end]).is_none());
                        rejects += 1;
                    }
                    let mut extra = ct.clone();
                    extra.push(0);
                    assert!(open(w, stream, p, &key, &nonce, &ad, &extra).is_none());
                    rejects += 1;
                    let other = if p == Profile::Fast {
                        Profile::Secure
                    } else {
                        Profile::Fast
                    };
                    assert!(open(w, stream, other, &key, &nonce, &ad, &ct).is_none());
                    rejects += 1;
                    assert!(open(w, !stream, p, &key, &nonce, &ad, &ct).is_none());
                    rejects += 1;
                    for bit in 0..2 * w {
                        let mut k = key;
                        k[bit / 8] ^= 1 << (bit % 8);
                        assert!(open(w, stream, p, &k, &nonce, &ad, &ct).is_none());
                        rejects += 1;
                    }
                    for bit in 0..128 {
                        let mut nn = nonce;
                        nn[bit / 8] ^= 1 << (bit % 8);
                        assert!(open(w, stream, p, &key, &nn, &ad, &ct).is_none());
                        rejects += 1;
                    }
                    let mut bad_ad = ad.clone();
                    bad_ad.push(0);
                    assert!(open(w, stream, p, &key, &nonce, &bad_ad, &ct).is_none());
                    rejects += 1;
                    for bit in 0..ad.len() * 8 {
                        let mut aa = ad.clone();
                        aa[bit / 8] ^= 1 << (bit % 8);
                        assert!(open(w, stream, p, &key, &nonce, &aa, &ct).is_none());
                        rejects += 1;
                    }
                }
            }
            for _ in 0..if quick { 32 } else { 5000 } {
                let len = (rng.next() % 257) as usize;
                let alen = (rng.next() % 65) as usize;
                let pt = rng.bytes(len);
                let ad = rng.bytes(alen);
                let k: [u8; 32] = rng.bytes(32).try_into().unwrap();
                let n: [u8; 16] = rng.bytes(16).try_into().unwrap();
                let ct = seal(w, stream, p, &k, &n, &ad, &pt);
                assert_eq!(open(w, stream, p, &k, &n, &ad, &ct), Some(pt));
                roundtrips += 1;
            }
            let forgeries = if quick { 32 } else { 10000 };
            for _ in 0..forgeries {
                let ct = rng.bytes(w / 4 + 31);
                assert!(open(w, stream, p, &key, &nonce, b"forgery", &ct).is_none());
            }
            // Negative/positive misuse controls: first rate-block XOR is
            // exposed by nonce reuse in STREAM, but not observed in SIV here.
            let a = vec![0; 32];
            let b = vec![0xff; 32];
            let ca = seal(w, stream, p, &key, &nonce, b"", &a);
            let cb = seal(w, stream, p, &key, &nonce, b"", &b);
            assert_eq!(ca, seal(w, stream, p, &key, &nonce, b"", &a));
            let start = if stream { 0 } else { w / 4 };
            let xor_exposed = (0..w / 8).all(|i| ca[start + i] ^ cb[start + i] == a[i] ^ b[i]);
            assert_eq!(xor_exposed, stream);
            // Same raw AD||plaintext concatenation, different field boundary.
            if !stream {
                let x = seal(w, false, p, &key, &nonce, b"a", b"bc");
                let y = seal(w, false, p, &key, &nonce, b"ab", b"c");
                assert_ne!(x[..w / 4], y[..w / 4]);
            }
            println!("{{\"kind\":\"aead\",\"width\":{},\"rounds\":{},\"stream\":{stream},\"roundtrips\":{roundtrips},\"tamper_rejections\":{rejects},\"random_forgeries\":{forgeries},\"accepted_forgeries\":0,\"nonce_reuse_first_block_xor_exposed\":{xor_exposed}}}", w * 5, p.rounds());
        }
    }
}
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let m = v.iter().sum::<f64>() / v.len() as f64;
        (
            m,
            v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() - 1) as f64,
        )
    };
    let (ma, va) = stats(a);
    let (mb, vb) = stats(b);
    let denom = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (ma - mb) / denom
    }
}
fn timing(q: &Qp, w: usize, quick: bool) {
    let n = if quick { 4000 } else { 200000 };
    for r in [8, 16] {
        let mut rng = Rng(0x54494d45 + r as u64);
        let mut schedule: Vec<u8> = (0..n).map(|i| (i % 2) as u8).collect();
        for i in (1..n).rev() {
            let j = rng.next() as usize % (i + 1);
            schedule.swap(i, j);
        }
        let inputs: Vec<[u128; 5]> = schedule
            .iter()
            .map(|&c| if c == 0 { [0; 5] } else { rng.state(w) })
            .collect();
        for (s, &c) in inputs.iter().zip(&schedule).take(2000) {
            black_box(perm(q, black_box(*s), r, w));
            black_box(c);
        }
        for control in [false, true] {
            let mut groups: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
            let mut raw = String::with_capacity(n * 20);
            for (&state, &class) in inputs.iter().zip(&schedule) {
                let mut s = black_box(state);
                let t = Instant::now();
                for _ in 0..8 {
                    s = black_box(perm(q, black_box(s), r, w));
                }
                // Deliberate leak verifies sensitivity; never part of crypto.
                if control && black_box(class) != 0 {
                    for _ in 0..64 {
                        s = black_box(perm(q, black_box(s), r, w));
                    }
                }
                black_box(s);
                let elapsed = t.elapsed().as_nanos();
                groups[class as usize].push(elapsed as f64);
                use std::fmt::Write;
                writeln!(&mut raw, "{class},{elapsed}").unwrap();
            }
            let t = welch(&groups[0], &groups[1]);
            let filename = format!(
                "timing-{}-{r}-{}.csv",
                w * 5,
                if control {
                    "positive-control"
                } else {
                    "permutation"
                }
            );
            std::fs::write(&filename, raw).unwrap();
            println!("{{\"kind\":\"timing\",\"width\":{},\"rounds\":{r},\"batch_permutations\":8,\"positive_control\":{control},\"samples\":{n},\"class0\":{},\"class1\":{},\"welch_t\":{t},\"raw_csv\":\"{filename}\"}}", w*5, groups[0].len(), groups[1].len());
            assert!(
                !control || t.abs() > 4.5,
                "timing positive control was not detected"
            );
        }
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let section = args.get(1).map(String::as_str).unwrap_or("full");
    let quick = args.iter().any(|x| x == "--quick");
    assert!(
        [
            "full",
            "oracle",
            "avalanche",
            "differential",
            "linear",
            "cubes",
            "rotational",
            "hashes",
            "aead",
            "timing"
        ]
        .contains(&section),
        "unknown audit section"
    );
    println!("{{\"kind\":\"metadata\",\"schema\":1,\"quick\":{quick},\"section\":\"{section}\",\"test_rng\":\"public SplitMix64 seeds; not for secrets\"}}");
    for w in [64, 128] {
        let q = if w == 64 { Qp::qp320() } else { Qp::qp640() };
        if section == "full" || section == "oracle" {
            oracle(&q, w, quick);
        }
        if section == "full" || section == "avalanche" {
            avalanche(&q, w, quick);
        }
        if section == "full" || section == "differential" {
            differential(&q, w, quick);
        }
        if section == "full" || section == "linear" {
            linear(&q, w, quick);
        }
        if section == "full" || section == "cubes" {
            cubes(&q, w, quick);
        }
        if section == "full" || section == "rotational" {
            rotational(&q, w, quick);
        }
        if section == "full" || section == "hashes" {
            hashes(&q, w, quick);
        }
        if section == "full" || section == "aead" {
            aead(w, quick);
        }
        if section == "timing" {
            timing(&q, w, quick);
        }
    }
}
