# Threat Model

KEM Courier is a local-first post-quantum file exchange prototype. It is designed to demonstrate cryptographic envelope construction, hybrid migration, and enterprise PAM-style operational controls. It is not production-certified cryptographic software.

## Assets

KEM Courier protects or tracks the following assets:

- Plaintext file contents.
- Per-file encryption key.
- Recipient ML-KEM-768 decapsulation seed.
- Recipient X25519 private key.
- Sender ML-DSA-65 signing seed.
- Signed envelope metadata.
- Recipient and sender key fingerprints.
- Decryption policy decisions.
- Private identity checkout leases.
- Local audit log integrity.

## Security goals

### Payload confidentiality

File contents are encrypted locally with AES-256-GCM under a random 256-bit file encryption key. The file encryption key is separately wrapped under a key derived from ML-KEM-768 and, in hybrid mode, X25519.

### Post-quantum key protection

ML-KEM-768 protects the file encryption key against future quantum attacks against classical key establishment. The project targets harvest-now-decrypt-later scenarios where an attacker stores encrypted files today and attempts decryption after quantum capabilities improve.

### Hybrid migration safety

`hybrid-x25519-mlkem768` mode combines ML-KEM-768 and X25519 shared secrets through HKDF-SHA256. This models a migration design where confidentiality does not rely only on a newly deployed PQC primitive or only on a classical primitive.

### Sender authenticity

The sender signs canonical envelope metadata with ML-DSA-65. Recipients verify this signature before decrypting payload content.

### Metadata integrity

The signature covers suite, mode, creation time, sender fingerprint, recipient fingerprint, KEM ciphertext, optional X25519 ephemeral public key, wrapped key, and encrypted payload fields. Tampering with these fields invalidates the signature.

### Downgrade resistance

The algorithm suite and exchange mode are included in signed metadata. Policy can require `hybrid-x25519-mlkem768`, preventing silent downgrade to weaker or unexpected modes.

### PAM-style key custody

Private identities can be sealed behind an Argon2id-derived AES-GCM key and checked out under a time-bound lease. This models enterprise privileged access patterns without binding the prototype to a specific PAM vendor.

### Auditability

Key operations append audit events to a local JSONL hash chain. `audit verify` detects missing or modified entries in the local log.

## Attacker model

The attacker may:

- Read encrypted envelope files.
- Modify envelope files.
- Replace envelope metadata.
- Replace sender or recipient public bundles supplied by an untrusted channel.
- Replay old envelopes.
- Attempt to downgrade algorithm choices.
- Steal encrypted sealed identity files.
- Read or modify local audit logs after the fact.
- Capture encrypted files today for later quantum-enabled attacks.

The attacker does not have:

- The recipient's unsealed ML-KEM decapsulation seed.
- The recipient's unsealed X25519 private key.
- The sender's ML-DSA signing seed.
- The passphrase for sealed identities.
- Full control over the machine while encryption or decryption is running.

## In-scope protections

KEM Courier attempts to detect or prevent:

- Payload modification.
- Wrapped key modification.
- KEM ciphertext modification.
- Algorithm-suite tampering.
- Sender fingerprint tampering.
- Recipient fingerprint tampering.
- Decryption using the wrong recipient identity.
- Decryption without satisfying configured policy.
- Decryption with an expired lease.
- Use of revoked sender or recipient fingerprints when a revocation list is configured.
- Simple local audit-log tampering.

## Non-goals

KEM Courier does not provide:

- Anonymous communication.
- Traffic analysis resistance.
- Secure key discovery.
- Global identity federation.
- Online certificate status checking.
- Hardware-backed key storage.
- Secure deletion guarantees.
- Malware resistance on the local host.
- Protection after private key compromise.
- Protection after sender signing-key compromise.
- Forward secrecy for already-created envelopes after recipient identity compromise.
- Distributed audit-log immutability.
- Production certification, formal verification, or third-party cryptographic audit.

## Important operational risks

### Public-key authenticity

The recipient must obtain sender and recipient public identity bundles through a trusted process. KEM Courier fingerprints identities, but it does not solve first-contact trust.

### Passphrase strength

Sealed identities use Argon2id and AES-GCM, but weak passphrases remain vulnerable to offline guessing if the sealed identity file is stolen.

### Local audit limitations

The audit hash chain detects modification if the log is later verified from a trusted state. It does not prevent an attacker with local write access from deleting the entire log or replacing it with a new chain.

### Identity compromise

If the recipient private identity is compromised, an attacker can decrypt envelopes addressed to that identity. Rotation and revocation help future operations but cannot recover confidentiality for data already exposed to the compromised key.

### Prototype dependency risk

The ML-KEM and ML-DSA Rust crates used here are suitable for a prototype but should not be treated as production-approved without independent review, dependency assessment, and organizational approval.

## Security acceptance checks

A healthy build should demonstrate:

1. Hybrid encrypted files decrypt to exact original bytes.
2. Tampering with signed metadata fails signature verification.
3. Tampering with ciphertext fails authentication or signature verification.
4. A sealed identity cannot be used without the passphrase.
5. A policy requiring hybrid mode rejects PQC-only envelopes.
6. Expired or mismatched leases are rejected.
7. Audit verification succeeds after normal operations and fails if the log is modified.
