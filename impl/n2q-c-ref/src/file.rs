//! Authenticated N2QF v2 container. See docs/n2qf.md; v1 is rejected.
use crate::modes::{Profile, n128};
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
use std::io::{self, Read};
const CHUNK: usize = 65536;
fn bad() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unauthenticated N2QF v2",
    )
}
fn ad(header: &[u8], kind: u8, index: u64, total: u64) -> Vec<u8> {
    [
        b"N2QF/v2".as_slice(),
        header,
        &[kind],
        &index.to_le_bytes(),
        &total.to_le_bytes(),
    ]
    .concat()
}
/// Build a v2 container. Fresh file identity; errors propagate from the OS RNG.
pub fn build(profile: Profile, key: &[u8; 16], chunks: &[&[u8]]) -> io::Result<Vec<u8>> {
    let mut header = vec![
        b'N',
        b'2',
        b'Q',
        b'F',
        2,
        if profile == Profile::Fast { 0x21 } else { 1 },
    ];
    let mut id = [0; 16];
    getrandom::getrandom(&mut id).map_err(|_| io::Error::other("secure RNG unavailable"))?;
    header.extend_from_slice(&id);
    let mut out = header.clone();
    let mut total = 0u64;
    for (index, chunk) in chunks
        .iter()
        .chain(std::iter::once(&b"".as_slice()))
        .enumerate()
    {
        let kind = u8::from(index == chunks.len());
        if kind == 0 && (chunk.is_empty() || chunk.len() > CHUNK) {
            return Err(bad());
        }
        let nonce = (index as u128).to_le_bytes();
        let sealed = n128::seal(
            profile,
            key,
            &nonce,
            &ad(&header, kind, index as u64, total),
            chunk,
        );
        out.push(kind);
        out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed);
        total = total.checked_add(chunk.len() as u64).ok_or_else(bad)?;
    }
    Ok(out)
}
/// Validate every record, including the mandatory final record, before returning.
pub fn parse(key: &[u8; 16], data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut input = data;
    let mut header = [0; 22];
    input.read_exact(&mut header)?;
    if &header[..5] != b"N2QF\x02" || !matches!(header[5], 1 | 0x21) {
        return Err(bad());
    }
    let profile = if header[5] == 0x21 {
        Profile::Fast
    } else {
        Profile::Secure
    };
    let (mut index, mut total) = (0u64, 0u64);
    let mut out = Vec::new();
    loop {
        let mut record = [0; 5];
        input.read_exact(&mut record)?;
        let kind = record[0];
        let len = u32::from_le_bytes(record[1..].try_into().unwrap()) as usize;
        if !((kind == 0 && len > 16 && len <= CHUNK + 16) || (kind == 1 && len == 16))
            || len > input.len()
        {
            return Err(bad());
        }
        let (sealed, rest) = input.split_at(len);
        input = rest;
        let pt = n128::open(
            profile,
            key,
            &(index as u128).to_le_bytes(),
            &ad(&header, kind, index, total),
            sealed,
        )
        .ok_or_else(bad)?;
        if kind == 1 {
            if !input.is_empty() {
                return Err(bad());
            }
            return Ok(out);
        }
        total = total.checked_add(pt.len() as u64).ok_or_else(bad)?;
        index = index.checked_add(1).ok_or_else(bad)?;
        out.push(pt);
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn atomic_write(path: &str, data: &[u8]) -> io::Result<()> {
    let path = std::path::Path::new(path);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt_file(
    profile: Profile,
    key: &[u8; 16],
    in_path: &str,
    out_path: &str,
) -> io::Result<()> {
    let data = std::fs::read(in_path)?;
    atomic_write(
        out_path,
        &build(profile, key, &data.chunks(CHUNK).collect::<Vec<_>>())?,
    )
}
#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt_file(key: &[u8; 16], in_path: &str, out_path: &str) -> io::Result<()> {
    let chunks = parse(key, &std::fs::read(in_path)?)?;
    atomic_write(out_path, &chunks.concat())
}
