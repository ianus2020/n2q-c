#![no_main]
use libfuzzer_sys::fuzz_target;
use n2q_c_ref::{frame, modes::capsule};
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    if let Ok(token) = std::str::from_utf8(data) {
        if let Ok((suite, nonce, sealed)) = frame::decode(token) {
            assert_eq!(frame::encode(suite, &nonce, &sealed), token);
        }
        let _ = capsule::open128(&[0; 16], b"ctx", token);
        let _ = capsule::open256(&[0; 32], b"ctx", token);
    }
});
