# Examples

This directory contains safe template files for exercising the Quantum-Safe AI Trust Gateway without committing generated private material.

## Local AI/PQC files

- `ai-trust-policy.example.yaml` — baseline AI trust policy for approved models, prompt-injection patterns, tool governance, control mapping, and PQC evidence requirements.
- `malicious-ai-request.example.json` — confidential request with indirect prompt-injection and exfiltration instructions; expected decision: denied.
- `allowed-ai-request.example.json` — confidential summarization request using an approved model/tool; expected decision: allowed with PQC evidence envelope.

Run:

```bash
../scripts/demo-ai-pqc.sh
```

The demo generates identities, denies the malicious request, allows the safe confidential request, creates signed provenance, writes access-review markdown, creates a hybrid PQC evidence envelope, and verifies the audit chain.

## Azure files

- `azure/azure-ai-foundry-policy.example.yaml` — Azure AI Foundry / Azure OpenAI policy using managed identity, Key Vault custody, Azure Monitor export, and private-link control mapping.
- `azure/allowed-foundry-request.example.json` — confidential Azure OpenAI request using an approved deployment-style model ID.

Validate the Azure policy:

```bash
qstg config validate --policy azure/azure-ai-foundry-policy.example.yaml
```

Render an Azure plan:

```bash
qstg azure plan --policy azure/azure-ai-foundry-policy.example.yaml
```

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
