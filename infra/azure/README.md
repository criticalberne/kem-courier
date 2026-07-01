# Azure Infrastructure Scaffold

This Bicep scaffold creates Azure support resources for qstg:

- User-assigned managed identity for qstg runtime.
- Azure Key Vault with RBAC, soft delete, purge protection, and public network disabled.
- Storage account/container for PQC evidence envelopes.
- Log Analytics workspace for monitor/Sentinel routing.
- Role assignments for Key Vault secret reads and Blob evidence writes.

It intentionally does not create an Azure OpenAI / Foundry deployment because those are commonly provisioned by platform teams with capacity, model approvals, network policy, and content-filter configuration. Assign the qstg managed identity to the existing Azure OpenAI resource with the `Cognitive Services OpenAI User` role.

## Deploy

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file infra/azure/main.bicep \
  --parameters namePrefix=qstg
```

## Configure qstg runtime

Use the deployment outputs to set:

```bash
export AZURE_KEY_VAULT_URL="https://<vault>.vault.azure.net/"
export AZURE_LOG_ANALYTICS_WORKSPACE_ID="<workspace-id>"
export AZURE_OPENAI_ENDPOINT="https://<azure-openai-resource>.openai.azure.com/openai/v1/"
```

Then validate policy:

```bash
qstg config validate --policy examples/azure/azure-ai-foundry-policy.example.yaml
```

Render the deployment plan:

```bash
qstg azure plan --policy examples/azure/azure-ai-foundry-policy.example.yaml
```

## Network hardening

The scaffold disables public network access for Key Vault and Storage. Add private endpoints and private DNS zones matching your platform network design before using this in an isolated environment.
