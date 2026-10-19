//! WebAssembly bindings for the N2Q reference — browser tester on the *own*
//! cipher, with the reliability/speed **profile** switch. Encryption returns a
//! self-describing `nqc.` token; decryption reads the profile back from it, so a
//! single `open` handles both Secure and Fast — the two are interoperable.

use n2q_c_ref::keys::{SecretKey128, SecretKey256};
use n2q_c_ref::modes::{Profile, capsule, n128, n256};
use wasm_bindgen::prelude::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn parse_hex(s: &str) -> Result<Vec<u8>, &'static str> {
    fn nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid ASCII hex"),
        }
    }
    if s.len() > 64 || s.len() % 2 != 0 {
        return Err("invalid hex length");
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| Ok(nibble(c[0])? * 16 + nibble(c[1])?))
        .collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, JsError> {
    parse_hex(s).map_err(JsError::new)
}
fn rand_hex(n: usize) -> Result<String, JsError> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|_| JsError::new("no secure RNG"))?;
    Ok(hex(&b))
}
fn key16(h: &str) -> Result<SecretKey128, JsError> {
    let bytes = zeroize::Zeroizing::new(unhex(h)?);
    let array = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("key must be 16 bytes (32 hex)"))?;
    Ok(SecretKey128::from_bytes(array))
}
fn key32(h: &str) -> Result<SecretKey256, JsError> {
    let bytes = zeroize::Zeroizing::new(unhex(h)?);
    let array = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("key must be 32 bytes (64 hex)"))?;
    Ok(SecretKey256::from_bytes(array))
}
fn nonce16(h: &str) -> Result<[u8; 16], JsError> {
    unhex(h)?
        .try_into()
        .map_err(|_| JsError::new("nonce must be 16 bytes (32 hex)"))
}
fn profile(fast: bool) -> Profile {
    if fast { Profile::Fast } else { Profile::Secure }
}

#[wasm_bindgen]
pub fn keygen128() -> Result<String, JsError> {
    let key = SecretKey128::generate().map_err(|_| JsError::new("no secure RNG"))?;
    Ok(hex(key.expose()))
}
#[wasm_bindgen]
pub fn keygen256() -> Result<String, JsError> {
    let key = SecretKey256::generate().map_err(|_| JsError::new("no secure RNG"))?;
    Ok(hex(key.expose()))
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
    Ok(capsule::seal128(
        profile(fast),
        key16(key)?.expose(),
        &nonce16(nonce)?,
        ad.as_bytes(),
        pt.as_bytes(),
    ))
}
#[wasm_bindgen]
pub fn seal256(fast: bool, key: &str, nonce: &str, ad: &str, pt: &str) -> Result<String, JsError> {
    Ok(capsule::seal256(
        profile(fast),
        key32(key)?.expose(),
        &nonce16(nonce)?,
        ad.as_bytes(),
        pt.as_bytes(),
    ))
}

/// Decrypt a token — profile (and nonce) are read from the token itself.
#[wasm_bindgen]
pub fn open128(key: &str, ad: &str, token: &str) -> Result<String, JsError> {
    let pt = capsule::open128(key16(key)?.expose(), ad.as_bytes(), token)
        .ok_or_else(|| JsError::new("authentication failed (wrong key/AAD or tampered)"))?;
    String::from_utf8(pt).map_err(|_| JsError::new("plaintext is not valid UTF-8"))
}
#[wasm_bindgen]
pub fn open256(key: &str, ad: &str, token: &str) -> Result<String, JsError> {
    let pt = capsule::open256(key32(key)?.expose(), ad.as_bytes(), token)
        .ok_or_else(|| JsError::new("authentication failed (wrong key/AAD or tampered)"))?;
    String::from_utf8(pt).map_err(|_| JsError::new("plaintext is not valid UTF-8"))
}

#[wasm_bindgen]
pub fn blind_index128(fast: bool, key: &str, value: &str) -> Result<String, JsError> {
    Ok(hex(&n128::blind_index(
        profile(fast),
        key16(key)?.expose(),
        value.as_bytes(),
    )))
}
#[wasm_bindgen]
pub fn blind_index256(fast: bool, key: &str, value: &str) -> Result<String, JsError> {
    Ok(hex(&n256::blind_index(
        profile(fast),
        key32(key)?.expose(),
        value.as_bytes(),
    )))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_is_bounded_and_unicode_safe() {
        assert!(super::parse_hex("aжb").is_err());
        assert!(super::parse_hex(&"a".repeat(66)).is_err());
        assert!(super::parse_hex("a").is_err());
        assert_eq!(super::parse_hex("00aAFF").unwrap(), [0, 170, 255]);
    }
}
