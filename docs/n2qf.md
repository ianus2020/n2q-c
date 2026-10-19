# N2QF v2 file format

This format is experimental, like the underlying N2Q cipher. It fixes container
framing and file integrity defects; it does not establish the security of N2Q.

All integers below are unsigned little endian. The 22-byte header is:

```
"N2QF" || 0x02 || suite:u8 || file_id:16
```

The OS CSPRNG generates a fresh file identity for every encryption. SIV suites
are exactly `01` (128 Secure), `21` (128 Fast), `02` (256 Secure), `22` (256 Fast).
Rust, PHP and Swift file helpers currently support only 128; C, Go and Python
support both. Unsupported suites, reserved bits and versions are rejected.

Each record is `kind:u8 || sealed_length:u32 || tag || ciphertext`.
Data records (`kind=0`) contain 1–65536 plaintext bytes. The last record
(`kind=1`) contains an authenticated empty plaintext, so its sealed length is
exactly the tag size (16/32 bytes). It is mandatory, including for an empty file,
and must be followed by physical EOF. Other record kinds are invalid.

For every record, starting at index zero:

```
nonce = le128(index)
AAD = "N2QF/v2" || header || kind:u8 || le64(index) || le64(total_before)
```

`total_before` counts plaintext bytes in preceding data records. The final tag
binds the file identity, suite, record count and total length. This detects
whole-record truncation and splicing across independently encrypted files. It
cannot detect replacement by an entire older valid file; applications needing
freshness must bind a version externally. Re-encrypting the same file produces
a different container. Core SIV/token KATs remain unchanged.

Readers validate record lengths before allocation, reading or decryption.
File helpers publish output by atomic rename of a private temporary file in the
same directory, only after full validation. On failure the old output remains.
Temporary plaintext uses owner-only permissions and is removed on normal error
paths. Process crashes can leave temporary files; this is not secure erasure.
C/Python stream data to disk; Rust/Go/PHP/Swift currently buffer whole files and
are intended for size-limited local input. Applications accepting uploads must
cap their size before invoking these reference helpers.

The chunk-selection APIs validate the whole container before returning the
requested chunk. They currently prioritize integrity over random-access speed.
C callers must provide `outcap`; Rust/Go builders now return an error result if
randomness or input validation fails.

## Migration from v1

v1 has no authenticated file identity or final marker. A valid per-chunk tag
cannot establish whether the file was truncated or assembled from several files.
All current readers reject v1; there is no automatic or permissive fallback.

Keep trusted backups. If an old file must be recovered, use the old reader only
in an isolated offline environment, verify the recovered length and a separately
trusted hash/signature against the original, then encrypt the verified plaintext
with the v2 writer. Without such independent evidence, integrity of a v1 file
cannot be recovered. Do not label a successful v1 decryption as verified.

## Command-line helpers

C and Go accept binary key files of exactly 16 or 32 bytes. Rust's `file` example,
Swift and `php impl/php/file_cli.php` accept exactly 16 bytes. They encrypt with
Secure, read the profile from v2 on decryption, and never use a built-in demo key:

```
n2qc encrypt KEYFILE INPUT OUTPUT
n2qc decrypt KEYFILE INPUT OUTPUT
```

Keep key files private and outside version control. The deterministic keys in
self-tests and conformance vectors are test data only.
