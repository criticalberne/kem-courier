# Envelope Format

KEM Courier writes encrypted files as JSON envelopes with base64url-encoded binary fields. JSON is used for prototype inspectability; a production design could migrate to CBOR while preserving the same signed field model.

## Envelope fields

```json
{
  "version": 1,
  "suite": "KEMCOURIER_MLKEM768_X25519_AES256GCM_MLDSA65_HKDFSHA256_V1",
  "mode": "hybrid-x25519-mlkem768",
  "created_at": "2026-07-01T18:42:10Z",
  "sender": {
    "name": "sender",
    "fingerprint": "sha256:..."
  },
  "recipient": {
    "name": "recipient",
    "fingerprint": "sha256:..."
  },
  "key_exchange": {
    "mlkem768_ciphertext": "base64url...",
    "x25519_ephemeral_public": "base64url..."
  },
  "wrapped_key": {
    "cipher": "AES-256-GCM",
    "nonce": "base64url...",
    "ciphertext": "base64url..."
  },
  "payload": {
    "cipher": "AES-256-GCM",
    "nonce": "base64url...",
    "ciphertext": "base64url..."
  },
  "signature": {
    "algorithm": "ML-DSA-65",
    "value": "base64url..."
  }
}
```

## Encryption construction

1. Generate random 256-bit file encryption key.
2. Encrypt payload with AES-256-GCM.
3. Encapsulate an ML-KEM-768 shared secret to the recipient public key.
4. In hybrid mode, generate an ephemeral X25519 key and compute X25519 ECDH with the recipient public key.
5. Concatenate ML-KEM shared secret and optional X25519 shared secret.
6. Derive a key-encryption key with HKDF-SHA256.
7. Wrap the file encryption key with AES-256-GCM.
8. Build unsigned envelope metadata.
9. Sign canonical unsigned metadata with ML-DSA-65.
10. Write the signed envelope.

## Decryption construction

1. Parse envelope.
2. Enforce policy and lease checks.
3. Verify the sender public identity matches the envelope sender fingerprint.
4. Verify ML-DSA-65 signature over canonical unsigned metadata.
5. Decapsulate the ML-KEM shared secret.
6. In hybrid mode, compute X25519 shared secret from recipient private key and envelope ephemeral public key.
7. Derive the key-encryption key with HKDF-SHA256.
8. Authenticate and unwrap the file encryption key.
9. Authenticate and decrypt the payload.

## Signed metadata

The ML-DSA-65 signature covers every field except `signature` itself.

Covered fields include:

- Envelope version.
- Suite.
- Mode.
- Created time.
- Sender name and fingerprint.
- Recipient name and fingerprint.
- ML-KEM ciphertext.
- X25519 ephemeral public key when present.
- Wrapped key cipher, nonce, and ciphertext.
- Payload cipher, nonce, and ciphertext.

Changing any of these fields invalidates the signature.

## Identity format

A public identity contains:

```json
{
  "name": "recipient",
  "fingerprint": "sha256:...",
  "mlkem768_public_key": "base64url...",
  "mldsa65_verify_key": "base64url...",
  "x25519_public_key": "base64url...",
  "created_at": "2026-07-01T18:42:10Z"
}
```

A private identity stores ML-KEM, ML-DSA, and X25519 private material. It can be sealed with Argon2id and AES-256-GCM so only public fields remain visible in the identity file.

## Revocation format

```json
{
  "version": 1,
  "revoked_keys": [
    {
      "fingerprint": "sha256:...",
      "revoked_at": "2026-07-01T18:42:10Z",
      "reason": "key rotation"
    }
  ]
}
```

A policy can point to this file with `revocation_list`.
