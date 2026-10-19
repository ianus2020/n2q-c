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
// File paths use bounded scratch space. Vec build/parse above are explicit
// in-memory conveniences; do not use them for unbounded uploads.
#[cfg(not(target_arch = "wasm32"))]
fn read_chunk(input: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut used = 0;
    while used < buf.len() {
        match input.read(&mut buf[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(used)
}
#[cfg(not(target_arch = "wasm32"))]
fn encrypt_to_staging(
    profile: Profile,
    key: &[u8; 16],
    input: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut header = [0u8; 22];
    header[..5].copy_from_slice(b"N2QF\x02");
    header[5] = if profile == Profile::Fast { 0x21 } else { 1 };
    getrandom::getrandom(&mut header[6..])
        .map_err(|_| io::Error::other("secure RNG unavailable"))?;
    output.write_all(&header)?;
    let mut buf = zeroize::Zeroizing::new(vec![0u8; CHUNK]);
    let (mut index, mut total) = (0u64, 0u64);
    loop {
        let len = read_chunk(input, &mut buf)?;
        let kind = u8::from(len == 0);
        let sealed = n128::seal(
            profile,
            key,
            &(index as u128).to_le_bytes(),
            &ad(&header, kind, index, total),
            &buf[..len],
        );
        output.write_all(&[kind])?;
        output.write_all(&(sealed.len() as u32).to_le_bytes())?;
        output.write_all(&sealed)?;
        if kind == 1 {
            return Ok(());
        }
        total = total.checked_add(len as u64).ok_or_else(bad)?;
        index = index.checked_add(1).ok_or_else(bad)?;
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn decrypt_to_staging(
    key: &[u8; 16],
    input: &mut impl Read,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut header = [0u8; 22];
    input.read_exact(&mut header)?;
    if &header[..5] != b"N2QF\x02" || !matches!(header[5], 1 | 0x21) {
        return Err(bad());
    }
    let profile = if header[5] == 0x21 {
        Profile::Fast
    } else {
        Profile::Secure
    };
    let mut sealed = vec![0u8; CHUNK + 16];
    let (mut index, mut total) = (0u64, 0u64);
    loop {
        let mut record = [0u8; 5];
        input.read_exact(&mut record)?;
        let kind = record[0];
        let len = u32::from_le_bytes(record[1..].try_into().unwrap()) as usize;
        if !((kind == 0 && len > 16 && len <= CHUNK + 16) || (kind == 1 && len == 16)) {
            return Err(bad());
        }
        input.read_exact(&mut sealed[..len])?;
        let pt = zeroize::Zeroizing::new(
            n128::open(
                profile,
                key,
                &(index as u128).to_le_bytes(),
                &ad(&header, kind, index, total),
                &sealed[..len],
            )
            .ok_or_else(bad)?,
        );
        if kind == 1 {
            let mut extra = [0u8; 1];
            if read_chunk(input, &mut extra)? != 0 {
                return Err(bad());
            }
            return Ok(());
        }
        total = total.checked_add(pt.len() as u64).ok_or_else(bad)?;
        index = index.checked_add(1).ok_or_else(bad)?;
        output.write_all(&pt)?;
    }
}
#[cfg(not(target_arch = "wasm32"))]
fn atomic_file(
    path: &str,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let path = std::path::Path::new(path);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    write(tmp.as_file_mut())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
/// Stream to a private temporary file; atomically publish only a complete container.
#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt_file(
    profile: Profile,
    key: &[u8; 16],
    in_path: &str,
    out_path: &str,
) -> io::Result<()> {
    let mut input = std::fs::File::open(in_path)?;
    atomic_file(out_path, |output| {
        encrypt_to_staging(profile, key, &mut input, output)
    })
}
/// Stream bounded records to a private temporary file. Publish only after final
/// authentication AND physical EOF; any error preserves the existing destination.
#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt_file(key: &[u8; 16], in_path: &str, out_path: &str) -> io::Result<()> {
    let mut input = std::fs::File::open(in_path)?;
    atomic_file(out_path, |output| {
        decrypt_to_staging(key, &mut input, output)
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod streaming_tests {
    use super::*;
    struct Short<'a>(&'a [u8]);
    impl Read for Short<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(7).min(self.0.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read"))
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected write"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn streams_short_reads_and_propagates_io_failures() {
        let key = [4; 16];
        let data = vec![0x5a; CHUNK + 9];
        let mut sealed = Vec::new();
        encrypt_to_staging(Profile::Fast, &key, &mut Short(&data), &mut sealed).unwrap();
        let mut pt = Vec::new();
        decrypt_to_staging(&key, &mut Short(&sealed), &mut pt).unwrap();
        assert_eq!(pt, data);
        assert!(encrypt_to_staging(Profile::Fast, &key, &mut Broken, &mut Vec::new()).is_err());
        assert!(encrypt_to_staging(Profile::Fast, &key, &mut &b"data"[..], &mut Broken).is_err());
        assert!(decrypt_to_staging(&key, &mut &sealed[..], &mut Broken).is_err());
        sealed.push(1);
        assert!(decrypt_to_staging(&key, &mut &sealed[..], &mut Vec::new()).is_err());
    }
    #[test]
    fn staging_failure_preserves_destination_and_cleans_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        std::fs::write(&path, b"keep").unwrap();
        assert!(
            atomic_file(path.to_str().unwrap(), |f| {
                f.write_all(b"tentative")?;
                Err(io::Error::other("injected"))
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
