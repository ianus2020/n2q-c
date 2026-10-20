//! OFFLINE tool. Legacy PW exists here only for explicit bounded recovery.
#![forbid(unsafe_code)]
use n2q_c_ref::{
    keys::SecretKey256,
    modes::{Profile, n128},
    pw::{self, Costs},
};
use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

fn private_parent(path: &Path) -> Result<(), Box<dyn Error>> {
    let info = fs::symlink_metadata(path.parent().ok_or("missing parent")?)?;
    if !info.is_dir() || info.permissions().mode() & 0o077 != 0 {
        return Err("use an owner-only parent directory".into());
    }
    Ok(())
}
fn read_file(
    path: &Path,
    limit: usize,
    secret: bool,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    private_parent(path)?;
    let before = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.nlink() != 1
        || (secret && before.permissions().mode() & 0o077 != 0)
    {
        return Err("input must be a regular private non-hardlinked file".into());
    }
    let file = File::open(path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() || after.len() > limit as u64 {
        return Err("input changed or exceeds limit".into());
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err("input exceeds limit".into());
    }
    Ok(data)
}
fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut data = Zeroizing::new(Vec::new());
    for p in parts {
        data.extend_from_slice(p);
    }
    n128::hash(Profile::Secure, &data)
}
fn legacy(
    password: &[u8],
    salt: &[u8],
    s: usize,
    t: usize,
) -> Result<SecretKey256, Box<dyn Error>> {
    if s == 0
        || s > 32768
        || t > 6
        || s.checked_mul(t.max(1)).ok_or("legacy cost overflow")? > 98304
        || password.len() > 1 << 20
        || salt.len() > 64
    {
        return Err("legacy recovery budget exceeded".into());
    }
    let mut buffer = Zeroizing::new(Vec::<[u8; 32]>::new());
    buffer.try_reserve_exact(s)?;
    let mut count = 0u64;
    buffer.push(h(&[&count.to_le_bytes(), password, salt]));
    count += 1;
    for m in 1..s {
        let previous = Zeroizing::new(buffer[m - 1]);
        buffer.push(h(&[&count.to_le_bytes(), &*previous]));
        count += 1;
    }
    for pass in 0..t as u64 {
        for m in 0..s {
            let previous = Zeroizing::new(buffer[(m + s - 1) % s]);
            let current = Zeroizing::new(buffer[m]);
            buffer[m] = h(&[&count.to_le_bytes(), &*previous, &*current]);
            count += 1;
            for i in 0..3u64 {
                let index = Zeroizing::new(h(&[
                    &count.to_le_bytes(),
                    salt,
                    &pass.to_le_bytes(),
                    &(m as u64).to_le_bytes(),
                    &i.to_le_bytes(),
                ]));
                count += 1;
                let other = (u64::from_le_bytes(index[..8].try_into().unwrap()) as usize) % s;
                let current = Zeroizing::new(buffer[m]);
                let other = Zeroizing::new(buffer[other]);
                buffer[m] = h(&[&count.to_le_bytes(), &*current, &*other]);
                count += 1;
            }
        }
    }
    Ok(SecretKey256::from_bytes(buffer[s - 1]))
}
fn hex(data: &[u8]) -> Zeroizing<String> {
    use std::fmt::Write;
    let mut text = Zeroizing::new(String::new());
    for byte in data {
        write!(&mut *text, "{byte:02x}").unwrap();
    }
    text
}
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "new PASSWORD_FILE BITS OUTPUT_KEY_JSON | legacy PASSWORD_FILE SALT_FILE S_COST T_COST BITS OUTPUT_KEY_JSON --acknowledge-insecure-recovery";
    let (key, salt, algorithm, costs, bits, output) = match args.get(1).map(String::as_str) {
        Some("new") if args.len() == 5 => {
            let password = read_file(Path::new(&args[2]), pw::MAX_PASSWORD_BYTES, true)?;
            let mut salt = vec![0u8; 16];
            getrandom::getrandom(&mut salt).map_err(|_| "secure salt generation failed")?;
            let c = Costs::default();
            let key = pw::derive(&password, &salt, c)?;
            (
                key,
                salt,
                "argon2id-v19",
                format!(
                    "{{\"memory_kib\":{},\"passes\":{},\"lanes\":{}}}",
                    c.memory_kib, c.passes, c.lanes
                ),
                args[3].parse::<usize>()?,
                args[4].clone(),
            )
        }
        Some("legacy") if args.len() == 9 && args[8] == "--acknowledge-insecure-recovery" => {
            let password = read_file(Path::new(&args[2]), pw::MAX_PASSWORD_BYTES, true)?;
            let salt = read_file(Path::new(&args[3]), 64, false)?;
            let (s, t) = (args[4].parse::<usize>()?, args[5].parse::<usize>()?);
            let key = legacy(&password, &salt, s, t)?;
            (
                key,
                salt.to_vec(),
                "legacy-n2q-pw-v1",
                format!("{{\"s_cost\":{s},\"t_cost\":{t}}}"),
                args[6].parse::<usize>()?,
                args[7].clone(),
            )
        }
        Some("restore") if args.len() == 9 => {
            let password = read_file(Path::new(&args[2]), pw::MAX_PASSWORD_BYTES, true)?;
            let salt = read_file(Path::new(&args[3]), 64, false)?;
            let c = Costs {
                memory_kib: args[4].parse()?,
                passes: args[5].parse()?,
                lanes: args[6].parse()?,
            };
            let key = pw::derive(&password, &salt, c)?;
            (
                key,
                salt.to_vec(),
                "argon2id-v19",
                format!(
                    "{{\"memory_kib\":{},\"passes\":{},\"lanes\":{}}}",
                    c.memory_kib, c.passes, c.lanes
                ),
                args[7].parse::<usize>()?,
                args[8].clone(),
            )
        }
        _ => return Err(usage.into()),
    };
    if bits != 128 && bits != 256 {
        return Err("key width must be 128 or 256".into());
    }
    let output = Path::new(&output);
    private_parent(output)?;
    let key_hex = hex(&key.expose()[..bits / 8]);
    let salt_hex = hex(&salt);
    let json = Zeroizing::new(format!(
        "{{\"format\":\"n2q-offline-key-v1\",\"algorithm\":\"{algorithm}\",\"key_bits\":{bits},\"key_hex\":\"{}\",\"salt_hex\":\"{}\",\"costs\":{costs}}}\n",
        &*key_hex, &*salt_hex
    ));
    let mut temporary = tempfile::NamedTempFile::new_in(output.parent().unwrap())?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(json.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output).map_err(|e| e.error)?;
    File::open(output.parent().unwrap())?.sync_all()?;
    println!("private offline key bundle created");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("offline key derivation failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_ambiguity_is_preserved_only_for_recovery() {
        assert_eq!(
            legacy(b"A", b"BC", 1, 0).unwrap().expose(),
            legacy(b"AB", b"C", 1, 0).unwrap().expose()
        );
        assert!(legacy(b"pw", b"s", 0, 3).is_err());
        assert!(legacy(b"pw", b"s", usize::MAX, 3).is_err());
        assert!(legacy(b"pw", b"s", 32768, 6).is_err());
    }
    #[test]
    fn legacy_matches_original_771c1a5_vectors() {
        // Generated by the unmodified historical pw.rs, not by this recovery tool.
        let expected = [
            171, 152, 184, 121, 75, 230, 118, 39, 156, 82, 35, 26, 166, 93, 251, 45, 67, 92, 215,
            82, 195, 14, 140, 120, 196, 199, 238, 178, 241, 144, 202, 69,
        ];
        assert_eq!(
            legacy(b"correct horse", b"salt-16-bytes!!!", 32, 3)
                .unwrap()
                .expose(),
            &expected
        );
        let expected = [
            92, 53, 209, 52, 187, 37, 162, 43, 246, 33, 131, 183, 170, 71, 11, 199, 244, 143, 125,
            223, 55, 151, 6, 182, 83, 60, 34, 36, 103, 13, 152, 91,
        ];
        assert_eq!(legacy(b"pw", b"s", 4, 2).unwrap().expose(), &expected);
    }
}
