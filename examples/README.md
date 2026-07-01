# Examples

This directory contains safe template files for exercising KEM Courier without committing generated private material.

## Files

- `enterprise-policy.example.yaml` — baseline policy for hybrid mode, signed metadata, allow-listed identities, and key-age controls.
- `revoked-keys.example.json` — revocation-list shape accepted by policy through the `revocation_list` field.

## Typical flow

1. Generate sender and recipient identities.
2. Export public identity bundles.
3. Copy `enterprise-policy.example.yaml` to a working directory.
4. Replace sender and recipient fingerprints with values from the generated public identity files.
5. Encrypt with `--mode hybrid-x25519-mlkem768`.
6. Decrypt with `--policy enterprise-policy.yaml`.
7. Generate an access-review report.

Generated identities, leases, encrypted envelopes, and audit logs are intentionally ignored by `.gitignore`.
