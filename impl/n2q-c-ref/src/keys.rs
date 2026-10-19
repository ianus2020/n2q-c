//! Owned keys with redacted formatting and zeroization on drop.
//! Copies explicitly made by callers, the compiler or host runtime are outside
//! this type's control. Never log/serialize exposed bytes or use them as passwords.
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! owned_key {
    ($name:ident, $size:expr) => {
        pub struct $name([u8; $size]);
        impl $name {
            /// Import raw key bytes; the caller must manage any earlier copies.
            pub fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }
            /// Generate directly into an owned buffer. RNG failure is an error.
            pub fn generate() -> Result<Self, getrandom::Error> {
                let mut key = Self([0; $size]);
                getrandom::getrandom(&mut key.0)?;
                Ok(key)
            }
            /// Explicit access for encryption APIs; do not retain/log the bytes.
            pub fn expose(&self) -> &[u8; $size] {
                &self.0
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        impl ZeroizeOnDrop for $name {}
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
owned_key!(SecretKey128, 16);
owned_key!(SecretKey256, 32);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debug_never_discloses_key() {
        assert_eq!(
            format!("{:?}", SecretKey128::from_bytes([0xaa; 16])),
            "SecretKey128([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", SecretKey256::from_bytes([0xbb; 32])),
            "SecretKey256([REDACTED])"
        );
    }
    #[test]
    fn generated_keys_have_the_required_lengths() {
        assert_eq!(SecretKey128::generate().unwrap().expose().len(), 16);
        assert_eq!(SecretKey256::generate().unwrap().expose().len(), 32);
    }
}
