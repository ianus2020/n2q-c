# Browser tester

This is a research UI, not a production encryption service. Read [STATUS](../../STATUS.md).
It performs no uploads, analytics or browser-storage writes. Keys remain in the
form/worker until cleared or the page closes; browsers cannot guarantee memory
erasure or protect against malicious hosting, extensions or a compromised device.

From the repository root, use the versions exercised by CI: Rust 1.96.1 with
the wasm32-unknown-unknown target, and wasm-pack 0.13.1:

```sh
rustup toolchain install 1.96.1 --profile minimal --target wasm32-unknown-unknown
cargo +1.96.1 install wasm-pack --version 0.13.1 --locked
RUSTUP_TOOLCHAIN=1.96.1 scripts/build-web.sh
python3 scripts/serve-web.py --port 8765
```

Open http://127.0.0.1:8765. Build with the checked-in Cargo.lock; generated `web/pkg`
is deliberately ignored so stale binaries are not shipped alongside changed source.
The loopback test host sends the CSP, isolation and other response headers checked
by the browser regression suite.
Deploy HTML, CSS, JS, worker and the generated package together, over HTTPS.

The UI uses a module worker, fresh OS-random nonce per encryption, strict key
validation, bounded input, text-only output and a CSP without inline scripts.
Changing the suite preserves the key; generating a replacement is explicit.
Generating a replacement clears the old displayed results. Copying transfers
the last successful token and its AAD, and clears the previous decrypted output.
Clear terminates the worker and resets fields; late responses are ignored.

## Example in the interface

1. Select **N2Q-128**, **Secure · 16 rounds**, and click **Новый ключ**. Save the key.
2. In **Шифрование**, enter AAD `demo:v1` and plaintext `Привет 🌍`, then click
   **Зашифровать**. The nonce is generated automatically.
3. Click **В поле дешифрования** to transfer both the token and AAD. Click
   **Расшифровать**; the result is `Привет 🌍`.

Each encryption uses a fresh random nonce, so the token changes. Save the token,
key and original AAD for later decryption. The token carries its size, profile
and nonce; it does not contain the key or AAD. Decryption reads the size/profile
from the token even if the selectors currently show different values.

The UI supports text SIV tokens with the `nqc.` prefix, wire-frame version 1.
File containers use the separate [N2QF v2 tools](../../docs/n2qf.md).
Password derivation uses the separate [Argon2id helpers](../../docs/guide.md) (section 3.3);
the key field accepts an already generated hexadecimal key.

| Parameter | N2Q-128 | N2Q-256 |
|---|---|---|
| Key | 16 bytes / 32 hex characters | 32 bytes / 64 hex characters |
| Automatically generated nonce | 16 bytes / 32 hex characters | 16 bytes / 32 hex characters |
| Hash output | 32 bytes / 64 hex characters | 64 bytes / 128 hex characters |
| Blind-index output | 16 bytes / 32 hex characters | 32 bytes / 64 hex characters |

Secure uses 16 rounds; Fast uses 8. Hashing needs no key; the blind index uses
the key and is deterministic for the same size, profile and input. Input limits
are **1 MiB of UTF-8** for text/hash/index data, **256 KiB** for AAD and **2 MiB**
for a token. These are byte limits; non-ASCII text can use several bytes per character.

## JavaScript example

On a running tester page, this developer-console example exercises the public
WASM bindings with synthetic text. Initialization must finish before API calls:

```js
const n2q = await import(new URL('./pkg/n2q_c_wasm.js', window.location.href).href);
await n2q.default();
const keyHex = n2q.keygen128();
const nonceHex = n2q.gen_nonce();
const aad = 'demo:v1';
const token = n2q.seal128(false /* Secure, 16 rounds */, keyHex, nonceHex, aad, 'Привет 🌍');
const plaintext = n2q.open128(keyHex, aad, token);
if (plaintext !== 'Привет 🌍') throw new Error('roundtrip failed');
```

The 256-bit bindings are `keygen256`, `seal256` and `open256`; `gen_nonce` stays
the same. The ready-made interface runs operations through its worker and
manifest-verified loader. Direct calls to the exported bindings still enforce
Rust input limits but run on the calling thread. Invalid keys, malformed tokens
and authentication failures throw; use `try/catch` in calling code.

## Hosting and browser checks

Set equivalent HTTP response CSP headers in production, plus
`frame-ancestors 'none'` (cannot be enforced by the meta CSP),
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
Correct hosting is part of the trust boundary.

With the server above running, execute browser regressions:

```sh
npm ci
npx playwright install chromium
npm run test:web
```
