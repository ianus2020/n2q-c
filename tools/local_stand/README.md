# Local HTTPS and CoNe integration stand

This stand uses synthetic data, an explicitly PUBLIC C signer fixture seed and
ephemeral two-day TEST certificates. It does not approve production deployment,
prove the cipher's security, or make the anchor independent of machine rollback.
Private generated files are owner-only, outside the public web directory and
ignored under `.local-stand/`. Never use real secrets in this stand.

Requirements: Python SSL (use a supported Python for ongoing use), OpenSSL CLI,
C compiler/libcurl, Rust/wasm-pack for the web build. Build and start from repo root:

```sh
scripts/build-web.sh
python3 tools/local_stand/run.py --state .local-stand
```

It listens on `https://localhost:9443/` and mTLS `localhost:9444` only. The CA is
not installed into system trust. For explicit verification:

```sh
curl --cacert .local-stand/pki/ca.pem --location https://localhost:9443/
N2Q_WEB_URL=https://localhost:9443 N2Q_LOCAL_TEST_CA=1 npm run test:web
```

The browser test's explicit local-CA flag bypasses Chromium's certificate trust
for this synthetic test. Python integration tests and C clients separately
verify trust/hostname/mTLS with no bypass. It is not an application setting.

Stop with Ctrl-C. Resume existing state without resetting its counter:

```sh
python3 tools/local_stand/run.py --state .local-stand --resume
```

For a one-shot end-to-end HTTPS and actual C signing check, use a NEW directory:

```sh
python3 tools/local_stand/run.py --state /tmp/n2q-stand-check --web-port 19443 --anchor-port 19444 --check
```

Creation refuses an existing state directory. Resume uses the stored ports and
holds an exclusive process lock. Losing the anchor DB fails closed. Certificates
expire after two days: create a new **synthetic** stand to refresh fixtures. Do
not apply that procedure to a real signing identity; real anchor loss/rollback
requires key retirement, not counter reset.

## Publication and serving

`web.py publish` validates the exact JS/WASM build manifest and copies only seven
public files into an immutable content-addressed release. All HTML/worker/pkg
files share `/releases/<digest>/...`; the root redirects to a particular version.
An open page continues to fetch its own release during later publications.
Release installation and current-pointer replacement use staging, fsync and
same-filesystem rename. Symlinks and modified existing releases are rejected;
on failure the previous pointer remains. At most 16 releases / 64 MiB public
assets are retained; quota exhaustion requires explicit operator review, not
automatic removal of files still used by old pages.

```sh
python3 tools/local_stand/web.py publish --source impl/n2q-c-wasm/web --destination .local-stand/web
```

The HTTPS host applies CSP, COOP/COEP/CORP, nosniff, frame denial, no-referrer,
permissions policy and no-store to static responses. WASM has its proper MIME.
Only allowlisted public paths are served; no listing, source tree, PKI or state
is exposed. Socket/handshake timeouts, bounded workers and response sizes bound
this local reference host. CPU/disk quotas of a real OS/service still need
operational enforcement. Linux systemd resource/sandbox examples are in
`ops/local-stand/`; they have not been executed on this macOS host.

## Verified vs open

Local tests cover verified TLS fetches, bad trust/hostname, security headers,
path traversal, MIME, old-page consistency, corrupt builds and symlinks; Chromium
runs the full cipher/worker scenarios over HTTPS. Anchor tests are documented
in `tools/anchor/README.md`. Process termination/restart is not a power-loss
test. This setup has no externally hosted TLS, real KMS, off-host storage,
production backup/restore evidence, load-test capacity claim or real migration.
