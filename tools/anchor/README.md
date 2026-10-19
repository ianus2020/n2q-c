# CoNe local reference anchor

This is a persistent mTLS service and a libcurl C callback provider, exercised
with the real reserved-index signer. It is not an HSM or production deployment.
Use the local-stand runner (stage 13) to generate ephemeral test certificates and
configuration. Keep all generated private keys/state outside Git.

Protocol: POST `/v1/reserve`, JSON `{"key_id":"<64 lowercase hex>","index":0}`.
Only a listed client-certificate SHA256 fingerprint may reserve its configured
key identifiers. Keys are journal identifiers, never signing seeds. Indices
0..15 match the current reference tree. Success: empty HTTP 204 **after** commit;
duplicate/older index: 409; bad auth: TLS failure/403; store failure: 503.
Retries do not return success for the same index. On uncertainty the signer must
burn its reservation. There is no reset/delete endpoint or automatic DB creation.

SQLite WAL + synchronous FULL, and fullfsync where implemented, provide a
reference durability policy. Transactions serialize two service processes using
the same local database. Do not put this database on an unverified network
filesystem. Runtime startup requires an existing private database; init is
exclusive and refuses an existing path. A missing/damaged DB requires operator
investigation, never blind recreation with keys already in use.

**Rollback boundary:** the anchor DB/WAL and its backups must not roll back with
any signer copy/snapshot. The local stand separates directories/processes, not
the whole machine's failure domain. The service cannot detect restoration of
its own old database snapshot. That requires external operational controls,
separate failure/storage domains or stronger trusted monotonic storage. After
anchor rollback/loss, retire affected signing identities; do not reset counters
or restore an old backup and resume those keys. Hardware power-loss and storage
recovery guarantees must be tested separately.

TLS minimum 1.2; TLS 1.2 suites restricted to ECDHE-ECDSA with AES-GCM, TLS 1.3
uses the SSL backend's TLS 1.3 suites. Both peer and hostname validation are
enabled by the C client, with an explicit CA and client certificate/key. No
redirects, URL credentials, proxies or retry on uncertainty. Timeouts are
bounded; the private PEM key is owner-only. Revocation means removing a peer
fingerprint and restarting; no CRL/OCSP infrastructure is configured here.

Run:

```sh
python3 -m unittest discover -s tests -p test_anchor_service.py -v
```

Requires OpenSSL CLI, a C compiler, libcurl headers/library and Python SSL.
`tests/anchor_http_client.c` uses an explicitly public fixture seed and must not
be used for production signing. Tests include mTLS/hostname failures, tenant
binding, exact JSON parsing, process restart, concurrent processes, missing state,
file permissions/links, signer snapshot rollback, unavailable anchor, and a
committed request whose response is dropped before the signer sees success.
