# Explicit offline migration and recovery

Synthetic-tested tools only. No real user data has been inventoried or migrated.
They do not approve N2Q for production or repair the integrity guarantees absent
from historical formats. Normal readers still reject v1; there is no fallback.

## Trust requirements

Before migration, preserve the original and independent trusted backups. Obtain
the source-container SHA256, original plaintext SHA256 AND original byte length
from separately authenticated evidence (signed inventory, known-good backup).
Computing a hash of the file currently under investigation does not establish
its authenticity/completeness. v1 per-record tags cannot detect whole-record
truncation/splicing. Without the independent evidence, this tool refuses a
verified migration. Never fill the required values from an attacker-controlled
copy just to bypass the check.

Inventory only reports observations, known container versions/suites and private
key-bundle algorithm metadata; it never prints key bytes:

```sh
python3 tools/migration/n2q_migrate.py inventory /path/to/offline-copy
```

Raw historical password keys do not identify their KDF/salt/costs. Those need
independent operator records. The inventory cannot infer or recover missing
parameters or password entropy.

## Private key inputs

Use a private recovery directory (`mkdir -m 700 recovery`). Key files must be
regular, owner-only, non-hardlinked files in a private directory. Password files
are read byte-for-byte, including any newline; do not pass passwords as command
arguments. Keep passwords, original keys and new key bundles out of Git/logs.

Raw CSPRNG key files of 16/32 bytes are accepted. For password-derived keys:

```sh
cargo build --release --locked --manifest-path impl/n2q-c-ref/Cargo.toml --example migration_keys
impl/n2q-c-ref/target/release/examples/migration_keys new recovery/new-password.bin 256 recovery/new-key.json
```

`new` uses bounded Argon2id v19 with a fresh 16-byte OS-random salt, default
64 MiB / 3 passes / 1 lane. The owner-only JSON includes the secret key and public
derivation parameters; atomic no-clobber publication preserves existing files.
It is an offline credential, not a public config. The migration result copies
only public derivation parameters into `migration.json`, enabling rederivation.
128/256 is the requested key width, not an independently established N2Q level.

Historical custom PW recovery is isolated in the example binary, never restored
to the library API. Supply the exact old password bytes, salt and costs:

```sh
impl/n2q-c-ref/target/release/examples/migration_keys legacy recovery/old-password.bin recovery/old-salt.bin 32768 3 128 recovery/old-key.json --acknowledge-insecure-recovery
```

This deliberately reproduces the old insecure/ambiguous function, solely to
read known old data. Bounds: password ≤1 MiB, salt ≤64 bytes, s_cost 1..32768,
t_cost 0..6, s_cost×max(t_cost,1) ≤98304. Inputs outside the bounded recovery
model are rejected, not silently adjusted. These limits do not make the old
KDF secure. Two vectors from the unmodified `771c1a5` source are checked.
Legacy bundles cannot be used as new output key bundles.

Restore a new password key using the public salt/costs from `migration.json`:

```sh
impl/n2q-c-ref/target/release/examples/migration_keys restore recovery/new-password.bin recovery/argon-salt.bin 65536 3 1 256 recovery/restored-key.json
```

`argon-salt.bin` must contain the decoded `output_kdf.salt_hex`, and numeric
parameters/key width must match that record. `restore` applies the library's
cost/input validation. Keep the migration record and trusted backups.

## File recovery/rekey

```sh
python3 tools/migration/n2q_migrate.py migrate \
  --source archive/source.n2qf --destination recovery/result \
  --old-key-file recovery/old-key.json --new-key-file recovery/new-key.json \
  --trusted-container-sha256 "$N2Q_TRUSTED_CONTAINER_SHA256" \
  --trusted-plaintext-sha256 "$N2Q_TRUSTED_PLAINTEXT_SHA256" \
  --trusted-plaintext-bytes "$N2Q_TRUSTED_PLAINTEXT_BYTES" \
  --allow-v1-recovery
```

The destination must not exist; its parent must be private. v1 recovery requires
the explicit flag. v2 rekey is also supported without that flag. Both source
widths/profiles are decoded; output is N2QF v2 Secure with a fresh file identity
under the supplied new 128/256-bit key. All chunks, whole-source hash, plaintext
hash/length and a new-container decrypt/read-back are checked before publication.
No plaintext file is written; no source is modified. Python heap copies are not
guaranteed wiped. A trusted offline environment remains required.

Default source budget 1 GiB; explicit `--max-source-bytes` up to 1 TiB. The legacy
plaintext record bound defaults to 64 KiB; `--legacy-record-limit` can explicitly
raise it up to 16 MiB for documented old custom chunk sizes. New records remain
64 KiB. Services still need wall-clock/concurrency/temp-disk limits; this is a
single offline CLI, not an upload endpoint.

The private output bundle (`data.n2qf`, public-parameters `migration.json`) is
staged, fsynced and published with atomic **no-replace** directory rename on
Linux/macOS. A racing existing destination is preserved. Unsupported filesystems
or no-replace APIs fail closed. Normal errors clean staging; crashes can leave
private staged ciphertext requiring explicit cleanup. fsync/process tests are
not physical power-loss proof. Do not delete originals/backups after a smoke run.

If the parent-directory fsync fails after rename, a complete verified destination
may already exist despite a failure result. Preserve it for inspection; retry
will refuse that name. Do not automatically delete it or the original.
