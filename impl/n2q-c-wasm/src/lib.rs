//! WebAssembly bindings for the N2Q-C reference — browser tester on the *own*
//! cipher, with the reliability/speed **profile** switch. Encryption returns a
//! self-describing `nqc.` token; decryption reads the profile back from it, so a
//! single `open` handles both Secure and Fast — the two are interoperable.

use n2q_c_ref::modes::{capsule, n128, n256, Profile};
use wasm_bindgen::prelude::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, JsError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(JsError::new("hex length must be even"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| JsError::new("invalid hex")))
        .collect()
}
fn rand_hex(n: usize) -> Result<String, JsError> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|_| JsError::new("no secure RNG"))?;
    Ok(hex(&b))
}
fn key16(h: &str) -> Result<[u8; 16], JsError> {
    unhex(h)?.try_into().map_err(|_| JsError::new("key must be 16 bytes (32 hex)"))
}
fn key32(h: &str) -> Result<[u8; 32], JsError> {
    unhex(h)?.try_into().map_err(|_| JsError::new("key must be 32 bytes (64 hex)"))
}
fn nonce16(h: &str) -> Result<[u8; 16], JsError> {
    unhex(h)?.try_into().map_err(|_| JsError::new("nonce must be 16 bytes (32 hex)"))
}
fn profile(fast: bool) -> Profile {
    if fast {
        Profile::Fast
    } else {
        Profile::Secure
    }
}

#[wasm_bindgen]
pub fn keygen128() -> Result<String, JsError> {
    rand_hex(16)
}
#[wasm_bindgen]
pub fn keygen256() -> Result<String, JsError> {
    rand_hex(32)
}
#[wasm_bindgen]
pub fn gen_nonce() -> Result<String, JsError> {
    rand_hex(16)
}

#[wasm_bindgen]
pub fn hash128(fast: bool, msg: &str) -> String {
    hex(&n128::hash(profile(fast), msg.as_bytes()))
}
#[wasm_bindgen]
pub fn hash256(fast: bool, msg: &str) -> String {
    hex(&n256::hash(profile(fast), msg.as_bytes()))
}

/// Encrypt (SIV) → self-describing `nqc.` token that records the profile.
#[wasm_bindgen]
pub fn seal128(fast: bool, key: &str, nonce: &str, ad: &str, pt: &str) -> Result<String, JsError> {
    Ok(capsule::seal128(profile(fast), &key16(key)?, &nonce16(nonce)?, ad.as_bytes(), pt.as_bytes()))
}
#[wasm_bindgen]
pub fn seal256(fast: bool, key: &str, nonce: &str, ad: &str, pt: &str) -> Result<String, JsError> {
    Ok(capsule::seal256(profile(fast), &key32(key)?, &nonce16(nonce)?, ad.as_bytes(), pt.as_bytes()))
}

/// Decrypt a token — profile (and nonce) are read from the token itself.
#[wasm_bindgen]
pub fn open128(key: &str, ad: &str, token: &str) -> Result<String, JsError> {
    let pt = capsule::open128(&key16(key)?, ad.as_bytes(), token)
        .ok_or_else(|| JsError::new("authentication failed (wrong key/AAD or tampered)"))?;
    String::from_utf8(pt).map_err(|_| JsError::new("plaintext is not valid UTF-8"))
}
#[wasm_bindgen]
pub fn open256(key: &str, ad: &str, token: &str) -> Result<String, JsError> {
    let pt = capsule::open256(&key32(key)?, ad.as_bytes(), token)
        .ok_or_else(|| JsError::new("authentication failed (wrong key/AAD or tampered)"))?;
    String::from_utf8(pt).map_err(|_| JsError::new("plaintext is not valid UTF-8"))
}

#[wasm_bindgen]
pub fn blind_index128(fast: bool, key: &str, value: &str) -> Result<String, JsError> {
    Ok(hex(&n128::blind_index(profile(fast), &key16(key)?, value.as_bytes())))
}
#[wasm_bindgen]
pub fn blind_index256(fast: bool, key: &str, value: &str) -> Result<String, JsError> {
    Ok(hex(&n256::blind_index(profile(fast), &key32(key)?, value.as_bytes())))
}
