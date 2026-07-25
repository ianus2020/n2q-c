//! Same-machine throughput benchmark: N2Q-C vs. RustCrypto AES-256-GCM and
//! XChaCha20-Poly1305. Measures MB/s of encryption/hashing on one buffer.
//! Not a rigorous microbenchmark, but a fair apples-to-apples on this CPU.

use std::hint::black_box;
use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::XChaCha20Poly1305;

use n2q_c_ref::modes::{n128, n256, Profile};

const MB: usize = 1 << 20;

fn bench<F: FnMut()>(name: &str, bytes_per_iter: usize, iters: usize, mut f: F) {
    for _ in 0..3 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let secs = t.elapsed().as_secs_f64();
    let mbps = (bytes_per_iter * iters) as f64 / secs / MB as f64;
    println!("  {name:<34} {mbps:>9.1} MB/s");
}

fn main() {
    let size = MB;
    let iters = 20;
    let data = vec![0x5au8; size];

    let k16 = [0x11u8; 16];
    let k32 = [0x22u8; 32];
    let nonce16 = [0xa5u8; 16];

    println!("=== N2Q-C throughput vs. reference AEADs (same machine) ===");
    println!("  buffer = {} MiB, {} iters, single-threaded\n", size / MB, iters);

    let sec = Profile::Secure;
    let fast = Profile::Fast;
    println!("-- N2Q-C (this project) --");
    bench("N2Q-128 stream Secure (16 rnd)", size, iters, || {
        black_box(n128::stream_seal(sec, &k16, &nonce16, b"", black_box(&data)));
    });
    bench("N2Q-128 stream Fast   (8 rnd)", size, iters, || {
        black_box(n128::stream_seal(fast, &k16, &nonce16, b"", black_box(&data)));
    });
    bench("N2Q-256 stream Secure (16 rnd)", size, iters, || {
        black_box(n256::stream_seal(sec, &k32, &nonce16, b"", black_box(&data)));
    });
    bench("N2Q-256 stream Fast   (8 rnd)", size, iters, || {
        black_box(n256::stream_seal(fast, &k32, &nonce16, b"", black_box(&data)));
    });
    bench("N2Q-128 SIV Secure (2-pass)", size, iters, || {
        black_box(n128::seal(sec, &k16, &nonce16, b"", black_box(&data)));
    });
    bench("N2Q-256 SIV Fast   (2-pass)", size, iters, || {
        black_box(n256::seal(fast, &k32, &nonce16, b"", black_box(&data)));
    });

    println!("\n-- RustCrypto references (same CPU) --");
    let aes = Aes256Gcm::new_from_slice(&k32).unwrap();
    let aes_nonce = GenericArray::from_slice(&nonce16[..12]);
    bench("AES-256-GCM (aes-gcm crate)", size, iters, || {
        black_box(aes.encrypt(aes_nonce, black_box(&data[..])).unwrap());
    });
    let chacha = XChaCha20Poly1305::new_from_slice(&k32).unwrap();
    let xnonce = GenericArray::from_slice(&[0x7u8; 24]);
    bench("XChaCha20-Poly1305 (chacha crate)", size, iters, || {
        black_box(chacha.encrypt(xnonce, black_box(&data[..])).unwrap());
    });

    println!("\n  Note: N2Q-C reference uses p^a=16 rounds per 8/16-byte block (clarity/");
    println!("  margin over speed) with no SIMD; the RustCrypto ciphers use AES-NI /");
    println!("  vectorized ChaCha. See analysis for the speed levers.");
}
