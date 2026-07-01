# Examples

This directory contains safe template files for exercising the Quantum-Safe AI Trust Gateway and the original KEM Courier file-envelope flow without committing generated private material.

## AI/PQC files

- `ai-trust-policy.example.yaml` — baseline AI trust policy for approved models, prompt-injection patterns, tool governance, control mapping, and PQC evidence requirements.
- `malicious-ai-request.example.json` — confidential request with indirect prompt-injection and exfiltration instructions; expected decision: denied.
- `allowed-ai-request.example.json` — confidential summarization request using an approved model/tool; expected decision: allowed with PQC evidence envelope.

Run:

```bash
../scripts/demo-ai-pqc.sh
```

The demo generates identities, denies the malicious request, allows the safe confidential request, creates signed provenance, writes access-review markdown, creates a hybrid PQC evidence envelope, and verifies the audit chain.

## File-envelope files

- `enterprise-policy.example.yaml` — baseline policy for hybrid mode, signed metadata, allow-listed identities, and key-age controls.
- `revoked-keys.example.json` — revocation-list shape accepted by policy through the `revocation_list` field.

Typical file-envelope flow:

1. Generate sender and recipient identities.
2. Export public identity bundles.
3. Copy `enterprise-policy.example.yaml` to a working directory.
4. Replace sender and recipient fingerprints with values from generated public identity files.
5. Encrypt with `--mode hybrid-x25519-mlkem768`.
6. Decrypt with `--policy enterprise-policy.yaml`.
7. Generate an access-review report.

Generated identities, leases, encrypted envelopes, AI provenance files, access reviews, evidence envelopes, and audit logs are intentionally ignored by `.gitignore`.
