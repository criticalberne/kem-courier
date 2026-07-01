# Azure Deployment Hardening

## Identity

- Use a user-assigned managed identity for qstg runtime workloads.
- Assign `Cognitive Services OpenAI User` on the Azure OpenAI resource for inference-only access.
- Assign `Key Vault Secrets User` on the qstg Key Vault for runtime reads.
- Use a separate admin identity for Key Vault writes, policy publication, and identity rotation.
- Prefer Microsoft Entra ID / managed identity over Azure OpenAI API keys.
- Treat API-key mode as an explicit exception and document owner, expiry, and rotation.

## Azure OpenAI / Foundry

- Approve deployment names, not just base model families.
- Pin policy to deployment IDs such as `azure-openai:gpt-4o-prod`.
- Record endpoint, deployment, content-filter profile, and policy version in provenance.
- Deny unsafe tool requests before invoking Azure OpenAI.
- Keep denied prompt-injection events out of the model path.

## Key Vault

- Store sealed qstg identity material in Key Vault secrets.
- Store active policy as a named/versioned Key Vault secret or signed artifact reference.
- Store public recipient bundles separately from private/sealed identity material.
- Enable purge protection and soft delete.
- Prefer private endpoint access.
- Restrict write permissions to security-admin identities.

## Network

- Use private endpoints for Azure OpenAI / Foundry resources.
- Use private endpoints for Key Vault and Storage.
- Use private DNS zones and validate resolution from the qstg runtime subnet.
- Disable public network access after private endpoint paths are verified.
- Restrict egress to approved Azure service FQDNs/private endpoints.

## Evidence storage

- Store PQC evidence envelopes in a dedicated Storage account/container.
- Enable container immutability policies where retention requirements apply.
- Keep provenance JSON and markdown access reviews alongside the envelope or in a linked evidence index.
- Use envelope fingerprints to bind provenance, review, and stored evidence.

## Logging and monitoring

- Keep the local `qstg.audit.jsonl` hash chain for deterministic local verification.
- Export audit/provenance events to Azure Monitor or Event Hub.
- Route high-severity events to Microsoft Sentinel.
- Alert on prompt-injection denials, blocked tool requests, missing PQC envelope requirements, and policy validation failures.

## Operational checks

Before production rollout:

1. `qstg config validate --policy <policy>` succeeds.
2. `qstg azure plan --policy <policy>` has no validation warnings that violate internal standards.
3. Managed identity can read Key Vault secrets and call the approved Azure OpenAI deployment.
4. Public network access is disabled or explicitly accepted by risk owners.
5. Evidence envelope storage has retention controls.
6. Audit export reaches the monitoring workspace.
7. Incident runbooks cover prompt injection, model misuse, leaked sealed identity material, and policy rollback.
