//! Explicit-key CLI: cargo run --example file -- encrypt|decrypt KEYFILE INPUT OUTPUT
use n2q_c_ref::{file, modes::Profile};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 || !matches!(a[1].as_str(), "encrypt" | "decrypt") {
        return Err("usage: file encrypt|decrypt KEYFILE INPUT OUTPUT".into());
    }
    let key: [u8; 16] = std::fs::read(&a[2])?
        .try_into()
        .map_err(|_| "key file must contain 16 bytes")?;
    if a[1] == "encrypt" {
        file::encrypt_file(Profile::Secure, &key, &a[3], &a[4])?;
    } else {
        file::decrypt_file(&key, &a[3], &a[4])?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
