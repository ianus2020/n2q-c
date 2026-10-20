//! Password KDF v2: Argon2id v19, replacing the ambiguous custom v1 KDF.
//! This is an explicit API/output change. Store algorithm/version, salt and
//! parameters with encrypted data. Old keys need a trusted offline migration.
//! Costs are checked BEFORE allocation or hashing, including for untrusted metadata.
//! Limits bound one call; services must additionally limit concurrent calls.
use crate::keys::SecretKey256;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

pub const KDF_ID: &str = "argon2id-v19";
pub const MAX_PASSWORD_BYTES: usize = 1 << 20;
pub const MIN_SALT_BYTES: usize = 16;
pub const MAX_SALT_BYTES: usize = 64;
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
pub const MAX_MEMORY_KIB: u32 = 64 * 1024;
pub const MAX_BLOCK_PASSES: u64 = 3 * MAX_MEMORY_KIB as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Costs {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}
impl Default for Costs {
    fn default() -> Self {
        Self {
            memory_kib: MAX_MEMORY_KIB,
            passes: 3,
            lanes: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfError {
    Input,
    Parameters,
    Budget,
    Allocation,
    Derivation,
}
impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Input => "invalid password or salt length",
            Self::Parameters => "invalid KDF parameters",
            Self::Budget => "KDF resource budget exceeded",
            Self::Allocation => "KDF memory allocation failed",
            Self::Derivation => "KDF derivation failed",
        })
    }
}
impl std::error::Error for KdfError {}

fn checked_params(password: &[u8], salt: &[u8], costs: Costs) -> Result<Params, KdfError> {
    if password.is_empty()
        || password.len() > MAX_PASSWORD_BYTES
        || !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&salt.len())
    {
        return Err(KdfError::Input);
    }
    if costs.memory_kib < MIN_MEMORY_KIB
        || !(2..=6).contains(&costs.passes)
        || !(1..=4).contains(&costs.lanes)
    {
        return Err(KdfError::Parameters);
    }
    if costs.memory_kib > MAX_MEMORY_KIB
        || u64::from(costs.memory_kib) * u64::from(costs.passes) > MAX_BLOCK_PASSES
    {
        return Err(KdfError::Budget);
    }
    Params::new(costs.memory_kib, costs.passes, costs.lanes, Some(32))
        .map_err(|_| KdfError::Parameters)
}

/// Derive an owned key with bounded, fallible allocation and wiped scratch space.
/// Generate a fresh random salt of at least 16 bytes for each new password key.
pub fn derive(password: &[u8], salt: &[u8], costs: Costs) -> Result<SecretKey256, KdfError> {
    let params = checked_params(password, salt, costs)?;
    let mut memory = Zeroizing::new(Vec::<Block>::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| KdfError::Allocation)?;
    memory.resize(params.block_count(), Block::default());
    let mut output = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut *output, memory.as_mut_slice())
        .map_err(|_| KdfError::Derivation)?;
    Ok(SecretKey256::from_bytes(*output))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SALT: &[u8] = b"salt-16-bytes!!!";
    fn small() -> Costs {
        Costs {
            memory_kib: MIN_MEMORY_KIB,
            passes: 2,
            lanes: 1,
        }
    }

    #[test]
    fn untrusted_costs_are_rejected_before_allocation() {
        for c in [
            Costs {
                memory_kib: 0,
                ..small()
            },
            Costs {
                memory_kib: u32::MAX,
                ..small()
            },
            Costs {
                passes: 0,
                ..small()
            },
            Costs {
                passes: u32::MAX,
                ..small()
            },
            Costs {
                lanes: 0,
                ..small()
            },
            Costs {
                lanes: u32::MAX,
                ..small()
            },
            Costs {
                passes: 6,
                ..Costs::default()
            },
        ] {
            assert!(derive(b"pw", SALT, c).is_err());
        }
        assert!(derive(b"", SALT, small()).is_err());
        assert!(derive(b"pw", b"short", small()).is_err());
        assert!(derive(b"pw", &[1; 65], small()).is_err());
        assert!(derive(&vec![0; MAX_PASSWORD_BYTES + 1], SALT, small()).is_err());
    }
    #[test]
    fn deterministic_and_unambiguous() {
        let a = derive(b"a", b"bbbbbbbbbbbbbbbbb", small()).unwrap();
        let b = derive(b"ab", b"bbbbbbbbbbbbbbbb", small()).unwrap();
        assert_ne!(a.expose(), b.expose()); // these collided in custom v1 at s=1
        assert_eq!(
            a.expose(),
            derive(b"a", b"bbbbbbbbbbbbbbbbb", small())
                .unwrap()
                .expose()
        );
        assert_ne!(
            a.expose(),
            derive(
                b"a",
                b"bbbbbbbbbbbbbbbbb",
                Costs {
                    passes: 3,
                    ..small()
                }
            )
            .unwrap()
            .expose()
        );
    }
    #[test]
    fn rfc9106_argon2id_vector() {
        // RFC 9106 section 5.3, including secret and associated data.
        // Tiny memory here is ONLY the published test vector, not a public cost.
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
            .build()
            .unwrap();
        let ctx =
            Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut mem = Zeroizing::new(vec![Block::default(); 32]);
        let mut out = Zeroizing::new([0; 32]);
        ctx.hash_password_into_with_memory(&[1; 32], &[2; 16], &mut *out, mem.as_mut_slice())
            .unwrap();
        assert_eq!(
            *out,
            [
                0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
                0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
                0x6b, 0x01, 0xe6, 0x59
            ]
        );
    }
}
