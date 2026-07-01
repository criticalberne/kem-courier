# KEM Courier

[![CI](https://github.com/criticalberne/kem-courier/actions/workflows/ci.yml/badge.svg)](https://github.com/criticalberne/kem-courier/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-2024-orange)
![PQC](https://img.shields.io/badge/PQC-ML--KEM--768-blue)
![Signature](https://img.shields.io/badge/signature-ML--DSA--65-blueviolet)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green)

KEM Courier is a CLI-first post-quantum secure file exchange prototype with enterprise PAM-style key-custody controls.

It encrypts files locally with AES-256-GCM, wraps per-file encryption keys using ML-KEM-768, optionally combines X25519 and ML-KEM-768 for hybrid migration, signs canonical envelope metadata with ML-DSA-65, and adds policy-based decryption, sealed private identities, lease-based checkout, audit logging, revocation checks, and access-review reporting.

This is an educational security engineering project, not production-certified cryptographic software.

## Hiring-manager walkthrough

If you only have a few minutes, review these first:

1. [`src/main.rs`](src/main.rs) — end-to-end CLI, envelope, crypto, policy, audit, and sealed identity implementation.
2. [`tests/cli_integration.rs`](tests/cli_integration.rs) — behavioral integration tests for hybrid round trip, sealed identity controls, access review, audit verification, and tamper rejection.
3. [`docs/threat-model.md`](docs/threat-model.md) — attacker model, goals, non-goals, and operational risks.
4. [`docs/crypto-agility.md`](docs/crypto-agility.md) — suite versioning, downgrade resistance, and migration notes.
5. [`scripts/demo.sh`](scripts/demo.sh) — reproducible local demo of the complete flow.

The project intentionally avoids vendor or employer branding. The enterprise nod is architectural: vaulted identities, lease-based access, policy gates, revocation, auditability, and access-review output.

## What it demonstrates

- **Post-quantum file exchange:** ML-KEM-768 protects the file encryption key.
- **Hybrid migration:** X25519 + ML-KEM-768 models practical crypto-agility adoption.
- **Sender authenticity:** ML-DSA-65 signs canonical envelope metadata.
- **Tamper detection:** signature verification fails before plaintext is written.
- **PAM-style key custody:** sealed identities require passphrase unlock and active checkout leases.
- **IAM-style governance:** policy files control approved senders, recipients, envelope age, key age, mode, and revocation.
- **Auditability:** operations append to a local tamper-evident audit hash chain.

## Cryptographic suite

| Purpose | Default |
| --- | --- |
| Payload encryption | AES-256-GCM |
| PQC key encapsulation | ML-KEM-768 |
| Hybrid classical key agreement | X25519 |
| Sender authenticity | ML-DSA-65 |
| Key derivation | HKDF-SHA256 |
| Sealed identity KDF | Argon2id |
| Fingerprints | SHA-256 over canonical JSON |

Supported exchange modes:

- `pqc-only`
- `hybrid-x25519-mlkem768`

The default mode is `hybrid-x25519-mlkem768`.

## Quick demo

```bash
./scripts/demo.sh
```

The demo:

1. Builds the CLI.
2. Generates sender and recipient identities.
3. Exports public identity bundles.
4. Seals the recipient private identity.
5. Checks out a short-lived lease.
6. Encrypts a sample supplier-contract file with hybrid X25519 + ML-KEM-768.
7. Decrypts under policy and lease control.
8. Generates an access-review report.
9. Tampers with the envelope.
10. Confirms tampered decrypt fails.
11. Verifies the audit hash chain.

## Manual quick start

```bash
cargo build

# Generate identities.
target/debug/kem-courier identity generate --name sender --out sender.identity.json
target/debug/kem-courier identity generate --name recipient --out recipient.identity.json

# Export public bundles.
target/debug/kem-courier identity export-public \
  --identity sender.identity.json \
  --out sender.public.json

target/debug/kem-courier identity export-public \
  --identity recipient.identity.json \
  --out recipient.public.json

# Seal recipient private identity behind a passphrase-derived AES-GCM key.
target/debug/kem-courier identity seal \
  --identity recipient.identity.json \
  --out recipient.identity.sealed.json \
  --passphrase "correct horse battery staple"

# Checkout a short-lived lease for recipient private-key use.
target/debug/kem-courier identity checkout \
  --identity recipient.identity.sealed.json \
  --ttl 15m \
  --reason "authorized decrypt for supplier contract review" \
  --out recipient.lease.json \
  --passphrase "correct horse battery staple"

# Encrypt a file.
target/debug/kem-courier encrypt \
  --sender sender.identity.json \
  --recipient recipient.public.json \
  --mode hybrid-x25519-mlkem768 \
  --in supplier-contract.pdf \
  --out supplier-contract.kemc

# Inspect the envelope.
target/debug/kem-courier inspect supplier-contract.kemc

# Decrypt under a lease.
target/debug/kem-courier decrypt \
  --identity recipient.identity.sealed.json \
  --passphrase "correct horse battery staple" \
  --lease recipient.lease.json \
  --sender sender.public.json \
  --in supplier-contract.kemc \
  --out supplier-contract.decrypted.pdf
```

## Policy example

See [`examples/enterprise-policy.example.yaml`](examples/enterprise-policy.example.yaml).

```yaml
minimum_encryption_mode: hybrid-x25519-mlkem768
require_sender_signature: true
require_signed_metadata: true
allow_unsigned_envelopes: false
max_envelope_age_days: 30
allowed_senders:
  - name: sender
    fingerprint: "sha256:..."
allowed_recipients:
  - name: recipient
    fingerprint: "sha256:..."
key_lifecycle:
  reject_expired_identity_keys: true
  max_identity_age_days: 365
```

Use it during decryption:

```bash
target/debug/kem-courier decrypt \
  --policy enterprise-policy.yaml \
  --identity recipient.identity.sealed.json \
  --passphrase "correct horse battery staple" \
  --lease recipient.lease.json \
  --sender sender.public.json \
  --in supplier-contract.kemc \
  --out supplier-contract.decrypted.pdf
```

## Access review

```bash
target/debug/kem-courier access-review \
  --policy enterprise-policy.yaml \
  --in supplier-contract.kemc \
  --out access-review.md
```

The report explains the envelope suite, sender fingerprint, recipient fingerprint, signature algorithm, and policy controls that passed or failed.

## Tamper demo

```bash
target/debug/kem-courier tamper supplier-contract.kemc \
  --field suite \
  --out tampered.kemc

target/debug/kem-courier decrypt \
  --identity recipient.identity.sealed.json \
  --passphrase "correct horse battery staple" \
  --lease recipient.lease.json \
  --sender sender.public.json \
  --in tampered.kemc \
  --out should-not-exist.pdf
```

Expected result:

```text
Error: envelope signature verification failed
```

## Audit log

Sensitive operations append tamper-evident JSON lines to `kem-courier.audit.jsonl` in the current working directory.

```bash
target/debug/kem-courier audit show
target/debug/kem-courier audit verify
```

Each audit event includes the previous event hash and its own event hash, creating a simple local hash chain for tamper detection.

## Tests

```bash
cargo test --test cli_integration
```

The integration suite covers:

- Hybrid X25519 + ML-KEM round trip under policy.
- Sealed identity passphrase and lease requirements.
- Access-review report controls.
- Audit hash-chain verification.
- Tampered envelope rejection before plaintext write.

## Resume positioning

- Built a CLI-first post-quantum secure file exchange prototype using ML-KEM-768, AES-256-GCM, optional X25519 hybrid key establishment, and ML-DSA-65 signed metadata.
- Modeled enterprise PAM and secrets-management workflows through sealed private identities, lease-based checkout, policy enforcement, key rotation, revocation checks, audit logging, and access-review reporting.
- Designed a crypto-agile, versioned envelope format with authenticated algorithm metadata, key fingerprints, downgrade resistance, and tamper detection.

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md)
- [`docs/crypto-agility.md`](docs/crypto-agility.md)
- [`docs/envelope-format.md`](docs/envelope-format.md)
- [`SECURITY.md`](SECURITY.md)

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))
