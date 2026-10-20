//! Self-describing, versioned wire frame (SPEC §9).
//!
//! ```text
//! token = "nqc." ‖ base64url( version(1) ‖ suite(1) ‖ nonce(16) ‖ sealed )
//! ```
//! `sealed` is the raw output of the chosen mode (tag‖ct for SIV, ct‖tag for
//! streaming). The `suite` byte identifies the mode + parameter set, so a
//! decoder knows which `open` to call without external metadata (the matured
//! `!Z/!X` auto-mode of N2Q 2.5). The key is never in the frame.

pub const VERSION: u8 = 1;
pub const SUITE_SIV_128: u8 = 0x01;
pub const SUITE_SIV_256: u8 = 0x02;
pub const SUITE_STREAM_128: u8 = 0x11;
pub const SUITE_STREAM_256: u8 = 0x12;

const PREFIX: &str = "nqc.";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let val = |c: u8| -> Result<u32, &'static str> {
        B64.iter()
            .position(|&x| x == c)
            .map(|p| p as u32)
            .ok_or("invalid base64url")
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            return Err("truncated base64url");
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16 & 0xff) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Encode a frame.
pub fn encode(suite: u8, nonce: &[u8; 16], sealed: &[u8]) -> String {
    let mut raw = Vec::with_capacity(2 + 16 + sealed.len());
    raw.push(VERSION);
    raw.push(suite);
    raw.extend_from_slice(nonce);
    raw.extend_from_slice(sealed);
    format!("{PREFIX}{}", b64_encode(&raw))
}

/// Decode a frame into `(suite, nonce, sealed)`.
pub fn decode(token: &str) -> Result<(u8, [u8; 16], Vec<u8>), &'static str> {
    let body = token.strip_prefix(PREFIX).ok_or("missing nqc. prefix")?;
    if body.len() > 24 * 1024 * 1024 {
        return Err("token too large");
    }
    let raw = b64_decode(body)?;
    if b64_encode(&raw) != body {
        return Err("noncanonical base64url");
    }
    if raw.len() < 2 + 16 {
        return Err("frame too short");
    }
    if raw[0] != VERSION {
        return Err("unsupported version");
    }
    let suite = raw[1];
    if !matches!(suite, 0x01 | 0x02 | 0x21 | 0x22 | 0x11 | 0x12 | 0x31 | 0x32) {
        return Err("unsupported suite");
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&raw[2..18]);
    Ok((suite, nonce, raw[18..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::n128;

    #[test]
    fn base64_roundtrip_all_lengths() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn frame_roundtrip() {
        let nonce = [0x5a; 16];
        let sealed = vec![1u8, 2, 3, 4, 5];
        let tok = encode(SUITE_SIV_128, &nonce, &sealed);
        assert!(tok.starts_with("nqc."));
        let (suite, n, s) = decode(&tok).unwrap();
        assert_eq!((suite, n, s), (SUITE_SIV_128, nonce, sealed));
    }

    #[test]
    fn end_to_end_token() {
        use crate::modes::Profile;
        let key = [7u8; 16];
        let nonce = [0xa5; 16];
        let sealed = n128::seal(Profile::Secure, &key, &nonce, b"ad", b"hello");
        let tok = encode(SUITE_SIV_128, &nonce, &sealed);

        // decode, dispatch on the suite, open
        let (suite, n, s) = decode(&tok).unwrap();
        assert_eq!(suite, SUITE_SIV_128);
        assert_eq!(
            n128::open(Profile::Secure, &key, &n, b"ad", &s).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("xxx.AAAA").is_err());
        assert!(decode("nqc.").is_err());
    }
}
