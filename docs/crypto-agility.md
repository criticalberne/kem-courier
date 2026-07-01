# Crypto-Agility Notes

KEM Courier intentionally treats algorithm choices as versioned, authenticated envelope metadata. The goal is to demonstrate how a file exchange tool can migrate cryptographic primitives without silent downgrade or ambiguous interpretation.

## Current suites

```text
KEMCOURIER_MLKEM768_AES256GCM_MLDSA65_HKDFSHA256_V1
KEMCOURIER_MLKEM768_X25519_AES256GCM_MLDSA65_HKDFSHA256_V1
```

The suite name is explicit because the security properties depend on the combination, not only on individual algorithms.

## Current primitives

| Component | Primitive |
| --- | --- |
| Payload cipher | AES-256-GCM |
| File key wrapping | AES-256-GCM under HKDF-derived KEK |
| PQC KEM | ML-KEM-768 |
| Classical hybrid | X25519 |
| Signature | ML-DSA-65 |
| KDF | HKDF-SHA256 |
| Sealed identity KDF | Argon2id |
| Fingerprint hash | SHA-256 |

## Agility principles

### Version every envelope

Each envelope contains:

```json
"version": 1
```

Envelope versioning is separate from identity versioning. A future identity format should not force a payload-envelope migration unless the payload format changes.

### Authenticate algorithm metadata

The suite and mode fields are signed as canonical metadata. They are also reflected in associated-data construction for AES-GCM operations. This prevents an attacker from changing the declared algorithm suite without invalidating verification.

### Prefer named suites over loose primitive lists

Good:

```text
KEMCOURIER_MLKEM768_X25519_AES256GCM_MLDSA65_HKDFSHA256_V1
```

Bad:

```text
AES-GCM + KEM
```

Named suites make downgrade detection and policy enforcement simple.

### Make policy stricter than parsing

The parser may understand multiple modes, but policy decides what is acceptable in an enterprise setting.

Example:

```yaml
minimum_encryption_mode: hybrid-x25519-mlkem768
require_sender_signature: true
require_signed_metadata: true
allow_unsigned_envelopes: false
```

This lets the tool read old envelopes while still allowing an organization to reject them operationally.

### Do not silently downgrade

If a recipient expects hybrid mode, a PQC-only envelope should fail policy. If a future version introduces a stronger suite, older tooling should fail closed unless explicitly configured to accept the old suite.

### Separate key identity from key use

Public identities include fingerprints. Envelopes bind sender and recipient fingerprints into signed metadata. This makes key rotation, revocation, and access-review reporting possible without changing the encrypted payload structure.

## Future migration examples

Possible future suites:

```text
KEMCOURIER_MLKEM1024_X25519_AES256GCM_MLDSA87_HKDFSHA384_V2
KEMCOURIER_MLKEM768_X25519_AES256GCMSIV_MLDSA65_HKDFSHA256_V2
KEMCOURIER_MLKEM768_X25519_CHACHA20POLY1305_MLDSA65_HKDFSHA256_V2
```

Potential migrations:

- ML-KEM-768 to ML-KEM-1024 for a higher security category.
- ML-DSA-65 to ML-DSA-87 or another approved signature family.
- AES-GCM to AES-GCM-SIV if nonce-misuse resistance becomes a requirement.
- JSON envelopes to CBOR envelopes for compact binary transport.
- Local sealed identity storage to an enterprise PAM or secrets-management provider.
- Local audit hash chain to externally anchored transparency logs.

## Compatibility rules

A future implementation should follow these rules:

1. Reject unknown mandatory fields.
2. Reject unknown suite strings unless explicitly enabled.
3. Verify signatures before decrypting payloads.
4. Enforce policy after parsing and before private-key operations where possible.
5. Keep old decrypt support read-only; create new envelopes with the preferred suite.
6. Include migration tests for every supported legacy suite.
7. Keep downgrade tests for every policy-controlled mode transition.

## Enterprise policy alignment

Crypto agility is not only a code concern. It also belongs in operational policy:

- Minimum accepted suite.
- Maximum envelope age.
- Maximum identity age.
- Required sender signatures.
- Approved sender fingerprints.
- Approved recipient fingerprints.
- Revocation-list source.
- Whether PQC-only mode is allowed.
- Whether hybrid mode is mandatory.

KEM Courier exposes these controls through `enterprise-policy.yaml` so an operator can demonstrate governance without changing code.
