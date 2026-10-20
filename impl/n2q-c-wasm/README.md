# Browser tester

This is a research UI, not a production encryption service. Read [STATUS](../../STATUS.md).
It performs no uploads, analytics or browser-storage writes. Keys remain in the
form/worker until cleared or the page closes; browsers cannot guarantee memory
erasure or protect against malicious hosting, extensions or a compromised device.

From the repository root, use Rust with the wasm32-unknown-unknown target and
wasm-pack 0.13.1 (the version tested for this build):

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.13.1 --locked
scripts/build-web.sh
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
Copying uses only the last successful encryption result. Clear terminates the
worker and resets fields; late responses from terminated workers are ignored.

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
