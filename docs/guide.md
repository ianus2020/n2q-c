# N2Q — developer guide

A practical manual: how to use N2Q in every scenario the library supports.
All signatures are taken from the actual code in this repository.

> **Status:** see [STATUS.md](../STATUS.md) for what is verified, what is not, and where this project is appropriate to use.

Russian version: [guide.ru.md](guide.ru.md).

---

## 1. Core concepts

| Term | What it is | Why it matters |
|---|---|---|
| **Key** | 16 bytes (N2Q-128) or 32 bytes (N2Q-256) | the master secret; from a CSPRNG or a KDF |
| **Nonce** | 16 bytes, the "message number" | uniqueness; in the default mode a repeat is **not** catastrophic |
| **AAD** | data that is authenticated but not encrypted | binds the ciphertext to its context (user id, RTP header) |
| **Profile** | `SECURE` = 16 rounds, `FAST` = 8 rounds | security margin ↔ speed (~2×) |
| **Suite** | N2Q-128 or N2Q-256 | key and state size; 256 for the post-quantum margin |
| **Token** | `nqc.` + base64url | self-describing: profile and suite are read automatically |

**The key property of the default mode (SIV):** an accidental nonce repeat leaks
only "these two messages were identical" — not the key, not a keystream. In
AES-GCM/ChaCha the same mistake is a total break.

### Golden rules

1. **Keys come from a CSPRNG or a KDF.** Never hardcode them (demo keys in the
   examples are for tests only).
2. **Profile and suite must match** on both sides — or use a token, which carries
   them itself.
3. **AAD is context.** If you sealed with `AAD="user:42"`, only the same AAD
   opens it. Use this so a ciphertext cannot be moved into another record.
4. **Check the result.** Decryption returning `None`/`false`/raising is not a
   nuisance — it is a forgery signal. Never use data before it verifies.
5. **Pick 256-bit** if the data must survive a quantum adversary.

---

## 2. Quick start

```bash
# 1. Get the sources
git clone https://github.com/ianus2020/n2q-c && cd n2q-c

# 2. Confirm your build matches the reference (must print ALL PASS)
cd impl/python && python3 test_kat.py
cd ../go        && go run .
cd ../c         && cc -O2 n2qc.c -o n2qc && ./n2qc
cd ../n2q-c-ref && cargo test
```

`ALL PASS` means your build is bit-for-bit identical to the reference.

### Your first encryption

#### Python

```python
import n2qc, os

key   = os.urandom(16)                 # 16 bytes = N2Q-128
nonce = os.urandom(16)

tok = n2qc.seal_token(128, n2qc.FAST, key, nonce, b"ctx", b"secret")
pt  = n2qc.open_token(128, key, b"ctx", tok)      # b"secret"
```

#### Go

```go
tok := n2qc.SealToken(n2qc.Fast, key, nonce, []byte("ctx"), []byte("secret"))
pt, ok := n2qc.OpenToken(key, []byte("ctx"), tok)
if !ok { /* forgery, or wrong key/AAD */ }
```

#### Rust

```rust
use n2q_c_ref::modes::{capsule, Profile};

let tok = capsule::seal128(Profile::Fast, &key, &nonce, b"ctx", b"secret");
let pt  = capsule::open128(&key, b"ctx", &tok).expect("auth failed");
```

#### PHP

```php
$tok = n2q_seal_token(N2Q_FAST, $key, $nonce, "ctx", "secret");
$pt  = n2q_open_token($key, "ctx", $tok);
```

#### Swift

```swift
let tok = sealToken(FAST, key, nonce, [UInt8]("ctx".utf8), [UInt8]("secret".utf8))
let pt  = openToken(key, [UInt8]("ctx".utf8), tok)
```

#### JavaScript (WASM)

See the [complete browser-console example](../impl/n2q-c-wasm/README.md#javascript-example):
load and initialize the WASM module, generate a key and nonce, then call
`seal128(false, keyHex, nonceHex, aad, plaintext)` and `open128(keyHex, aad, token)`.
Here `false` selects Secure (16 rounds). The same instructions cover the 256-bit
bindings, UTF-8 limits and the worker used by the ready-made interface.

---

## 3. Scenario catalogue

Every supported scenario: why, the API, and the pitfalls.

### 3.1. Encrypting a field or a message (default mode)

**When:** anything "hide this data" — a database column, a message, a config.

| Language | API |
|---|---|
| Python | `seal(bits, profile, key, nonce, ad, pt)` → `sealed`; `open(...)` → `None` on forgery |
| Go | `Seal(profile, key, nonce, ad, pt)`; `Open(...) ([]byte, bool)` |
| Rust | `n128::seal(p, &key, &nonce, ad, pt)`; `n128::open(...) -> Option` |
| C | `seal_128(key, nonce, ad, adlen, pt, ptlen, out, rounds)` |
| PHP | `n2q_seal($profile,$key,$nonce,$ad,$pt)`; `n2q_open(...)` → `null` on failure |
| Swift | `seal(profile, key, nonce, ad, pt)`; `openN2Q(...) -> [UInt8]?` |

**Tip:** store the result as a **token** (`seal_token` / `SealToken` /
`capsule::seal128`) — then the receiver need not know the profile; it is in the
token.

**Pitfall:** `sealed` is `tag(16) ‖ ciphertext`. Do not truncate it.

### 3.2. Searching encrypted data (blind index)

**When:** you must find a row by e-mail or phone without decrypting the table.

```python
bi = n2qc.blind_index(128, n2qc.SECURE, key, b"alice@x.com")
# store bi next to the ciphertext; search:  SELECT * FROM t WHERE bi = ?
```
Go: `BlindIndex(Secure, key, value)` · Rust: `n128::blind_index(p, &key, value)` ·
PHP: `n2q_blind_index(N2Q_SECURE, $key, $v)` · Swift: `blindIndex(SECURE, key, v)`

**Pitfalls:**
- A blind index is **deterministic** — the same input gives the same index. That
  is what enables search, and it also reveals **equality**. Do not index
  low-entropy fields (e.g. "gender"): frequency analysis defeats them.
- **Exact match only.** Range queries are deliberately unsupported (see §5).
- Index a normalised value (`lower(trim(email))`), or lookups will miss.

### 3.3. Passwords → keys (Argon2id v19)

```rust
use n2q_c_ref::pw::{self, Costs};
let key32 = pw::derive(password, salt, Costs::default())?; // SecretKey256
// n256::seal(profile, key32.expose(), nonce, ad, plaintext)
```

Generate a fresh 16–64-byte salt with a CSPRNG. Store it with `argon2id-v19`
and the costs. Defaults: 64 MiB, 3 passes, 1 lane. Validate per-call limits
before allocation; servers must also bound concurrency. Password length:
1 byte – 1 MiB. Invalid inputs and allocation failure return `Result`.

This **replaces** the experimental custom N2Q-PW/Balloon KDF and changes
derived keys. Old encrypted data requires an explicit trusted offline migration;
see [stage 4](stage-4-keys-kdf.ru.md). Owned keys have no Copy/Clone/Serialize,
redact Debug and wipe their buffer on Drop. Caller/OS copies remain outside
their control.

### 3.4. Files of any format (the N2QF container)

**When:** documents, photos, archives, video — "encrypt this file".

| Language | API |
|---|---|
| Python | `encrypt_file(bits, profile, key, in, out)` / `decrypt_file(bits, key, in, out)` |
| Go | `EncryptFile(profile, key, in, out) error` / `DecryptFile(key, in, out) error` |
| Rust | `file::encrypt_file(profile, &key, in, out)` / `file::decrypt_file(&key, in, out)` |
| C | `enc_file(profile, key, bits, in, out)` / `dec_file(key, bits, in, out)` |
| PHP | `n2q_encrypt_file($profile,$key,$in,$out)` / `n2q_decrypt_file($key,$in,$out)` |
| Swift | `encryptFile(profile, key, in, out)` / `decryptFile(key, in, out)` |

**N2QF v2** includes a fresh file identity, records of at most 64 KiB and a
mandatory authenticated final record. v1 is rejected. Output is published
atomically after full validation. Rust/PHP/Swift file helpers support N2Q-128;
C/Go/Python support both sizes. See [format, limits and migration](n2qf.md).

### 3.5. Seeking inside encrypted media

**Scope:** reference chunk selection validates the entire file first; it is
not currently an efficient random-access media API.

```python
cont = m.n2qf_build(key, [chunk0, chunk1, chunk2])
data = m.seek_chunk(key, cont, 1)        # validates all records before returning the selected chunk
```
Go: `SeekChunk(key, buf, index)` · Rust: `seek_chunk(&key, &buf, i)` ·
C: `n2q_seek_chunk(key, buf, buflen, index, out, outcap, &outlen)`

**Pitfall:** the index is a **chunk number**, not a byte offset. Mapping
"seconds → chunk" is your container's job.

### 3.6. Real time: calls, video, games (streaming)

**When:** a packet stream where loss and reordering are normal.

```python
tx, rx = m.StreamTx(key), m.StreamRx(key)
pkt = tx.seal(b"rtp-header", frame)        # 1 packet = 1 token, +24 bytes
out = rx.open(b"rtp-header", pkt)          # None → drop the packet
```
Go: `NewStreamTx/NewStreamRx`, `.Seal/.Open` · Rust: `StreamTx::new/.seal`,
`StreamRx::new/.open` · C: `n2q_stream_init/_seal/_open` (see `n2q_stream.h`).

Properties: nonce = packet sequence number (carried in the header), a **64-packet
sliding replay window**, the sequence number is authenticated (forgery is
caught), and a bad packet is dropped locally — the stream keeps flowing.

**Pitfalls:** `Rx` state is per-sender (never share one object across peers); use
`FAST` for the lowest latency.

### 3.7. Forward secrecy: a seized device does not reveal the past (ratchet)

**When:** messengers, calls, anything that must not be readable after the fact.

```python
tx, rx = m.RatchetTx(root), m.RatchetRx(root)   # root: a shared 16-byte root key
pkt = tx.seal(b"hdr", b"message")
out = rx.open(b"hdr", pkt)
```
Go: `NewRatchetTx/NewRatchetRx` · Rust: `RatchetTx::new/RatchetRx::new` ·
C: `n2q_ratchet_tx_init/_rx_init/_seal/_open`.

How it works: each packet's key comes from a chain, and the chain **advances
one-way while the old value is erased**. Skipped keys are cached (window 64), so
reordering and loss are tolerated; a consumed key is erased, so replay is
impossible too.

**Pitfalls:**
- Decryption **irreversibly mutates state** — persist it carefully; restoring an
  old backup breaks the channel.
- `root` must reach both sides securely (outside this library today — see
  [federation.md](federation.md)).

### 3.8. Key rotation without re-encrypting (envelope)

**When:** terabytes of data and a master key that must change.

```python
blob = m.wrap(kek1, dek)               # a small envelope stored next to the data
dek  = m.unwrap(kek1, blob)
blob = m.rewrap(kek1, kek2, blob)      # rotation: the data is untouched
```
Go: `Wrap/Unwrap/Rewrap` · Rust: `wrap/unwrap/rewrap` · C: `n2q_wrap/_unwrap/_rewrap`.

The shape: data is encrypted **once** under `dek`; `dek` is wrapped under `kek`.
Rotation rewrites only the envelope (tens of bytes).

**Pitfall:** use a `dek` per object/tenant, not one for everything — otherwise
one compromised `dek` opens the whole estate.

### 3.9. Deduplicating encrypted storage (convergent)

`master_key` must be exactly **16 bytes**; other lengths are rejected. Rust
requires `&[u8;16]`; the C API also requires output capacities. Historical data
using other key lengths needs an explicit migration decision.

**When:** backups or cloud storage where identical files must not be stored twice.

```python
dek, ct = m.conv_seal(master_key, content)   # identical content → identical ct
data    = m.conv_open(dek, ct)
```

**Pitfall (important):** this mode is **deterministic by design** — that is what
enables dedup, and it also lets anyone holding the same `master_key` test
"do you have this exact file?". Keep `master_key` per tenant so outsiders cannot
run that test.

### 3.10. Hiding the message length (length-hiding)

**When:** private messengers where size betrays content.

```python
tok = m.seal_padded(key, nonce, b"", pt, bucket=256)
pt  = m.open_padded(key, nonce, b"", tok)
```
Go: `SealPadded(..., bucket)` / `OpenPadded` · Rust: `seal_padded/open_padded` ·
C: `n2q_seal_padded/_open_padded`.

The ciphertext size reveals only the bucket. A larger bucket means better privacy
and more traffic.

### 3.11. A log where any edit shows (audit log)

**When:** compliance, supply chain, audit trails.

```python
head = m.log_genesis()
rec, head = m.log_append(head, seq, key, b"user alice login")
ok = m.log_verify(key, [rec, ...], head)     # False on edit/reorder/deletion
```
Go: `LogGenesis/LogAppend/LogVerify` · Rust: same · C: `n2q_log_init/_append/_verify`.

**Pitfall:** the value comes from **storing `head` somewhere trustworthy**
(another service, a signature, publication). If an attacker can rewrite both the
records and `head`, the chain proves nothing.

### 3.12. Abuse reporting in E2E (franking)

**When:** a messenger where a recipient must prove content to a moderator without
revealing the key or anyone else's messages.

```python
tok = m.frank_seal(key, nonce, msg)                 # sender
msg, cf, opening = m.frank_open(key, nonce, tok)    # recipient
ok = m.frank_report_verify(cf, opening, msg)        # moderator: no key needed
```

**Pitfall:** the moderator only ever verifies what was **voluntarily** disclosed
(`msg`, `opening`). The recipient cannot substitute a different message
(binding), but may also choose not to report — that is the intended privacy
balance.

### 3.13. Evading DPI / censorship (stego) — **opt-in**

**When:** traffic must not be identifiable by signature.

```python
blob = m.stego_seal(key, nonce, b"", pt)   # nonce(16)|sealed — no header
pt   = m.stego_open(key, b"", blob)
```

A normal token starts with `nqc.` — a fingerprint. Stego removes it: the output
is indistinguishable from random bytes (verified by a chi-square check).

**Pitfalls:**
- **Off by default** — the developer enables it deliberately.
- The suite and profile are **not** in the data: both sides agree out of band.
- It hides the payload; handshake, sizes and timing are the transport's problem.

### 3.14. Format-preserving encryption (FPE) — **opt-in**

**When:** a legacy database column that must stay a 16-digit number.

```python
ct = m.fpe_encrypt(key, b"tweak", "4111111111111111")   # → another 16 digits
pt = m.fpe_decrypt(key, b"tweak", ct)
```
Go: `FpeEncrypt/FpeDecrypt` · Rust: `fpe_encrypt/fpe_decrypt` ·
C: `n2q_fpe_encrypt/_decrypt`.

The construction is **FF1** (NIST SP 800-38G, a 10-round Feistel) with our PRF as
the round function. We did not invent an FPE of our own.

**Pitfalls:**
- Small domains (a 4-digit PIN = 10,000 values) are **tokenisation**, not strong
  encryption.
- The `tweak` (e.g. an account id) separates domains — use it.
- The native ports (Python/Go/Rust) agree with each other but are **not**
  byte-identical to the C `n2q_fpe.c` (different MAC domain).

### 3.15. Ciphertext bound to its key (key-committing)

**When:** the key may be guessed or substituted (passwords, multi-tenancy).

```python
tok = m.seal_committing(key, nonce, ad, pt)
pt  = m.open_committing(key, nonce, ad, tok)     # None if the key is not "the" key
```

Gives immunity to the **partitioning-oracle** attacks that break AES-GCM/ChaCha.
Cost: +32 bytes.

### 3.16. The post-quantum choice

Nothing to switch on — just **use N2Q-256** (32-byte key): 256 classical bits →
~128 bits against Grover. Details: [post-quantum.md](post-quantum.md).

### 3.17. Cross-language compatibility

All implementations are checked against shared KAT vectors
([impl/conformance/vectors.txt](../impl/conformance/vectors.txt)). Verified: an
N2QF file and every extended mode produced in one language open in the others.

**To keep it that way:** do not change field order, domain bytes or layout — when
writing your own port, check against the vectors ([conformance.md](conformance.md)).

---

## 4. Choosing a profile and suite

| Task | Suite | Profile |
|---|---|---|
| Large media, real time | 128 or 256 | `FAST` |
| Storing sensitive data | 128/256 | `SECURE` |
| Long-lived secrets, PQ risk | **256** | `SECURE` |
| Embedded, tight budget | 128 | `FAST` |

The profiles are **mutually readable**: a token states how it was made.

## 5. What the library does NOT do

- **It does not agree keys between strangers.** Symmetric cryptography requires a
  shared key. Exchange between independent "encryption centres" needs a separate
  layer. The architectures (one-time out-of-band, trusted hub, asymmetric
  exchange) are laid out in **[federation.md](federation.md)**; the rollout plan is
  in [connect.md](connect.md). Do not roll your own key exchange.
- **It does not hide metadata** (who talked to whom, when) — that is a transport
  concern.
- **It does not support range queries** over ciphertext (ORE) — deliberately:
  such schemes have proven leakage.
- **It does not replace TLS** — this is data encryption, not channel security.

## 6. Error handling

| Language | Failure signal |
|---|---|
| Python | `None` (`decrypt_file` raises `ValueError`) |
| Go | second return value `ok == false` |
| Rust | `Option::None` |
| C | `0` or a negative code |
| PHP | `null` |
| Swift | `nil` |

Any failure means one of: wrong key, wrong AAD, corruption, forgery, replay.
**Never** hand a user data obtained before a successful check, and do not reveal
the reason in the error message.

## 7. Pre-flight checklist

- [ ] Your port's self-test/KAT prints `ALL PASS`.
- [ ] Keys come from a CSPRNG or KDF; nothing is hardcoded.
- [ ] You have a key-rotation (see 3.8) and key-storage plan.
- [ ] AAD binds each ciphertext to its record's context.
- [ ] Every "decryption failed" branch is handled and logged.
- [ ] Your 128/256 and `FAST`/`SECURE` choice is justified (see §4).
- [ ] Remember: **until an external audit — pilots only, not real secrets.**
