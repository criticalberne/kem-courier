targetScope = 'resourceGroup'

@description('Azure region for qstg support resources.')
param location string = resourceGroup().location

@description('Short lowercase prefix used for Azure resource names.')
param namePrefix string = 'qstg'

@description('Object ID of the qstg runtime managed identity principal after creation. Leave empty to use the user-assigned identity created by this template.')
param runtimePrincipalObjectId string = ''

var suffix = uniqueString(resourceGroup().id, namePrefix)
var managedIdentityName = '${namePrefix}-runtime-${suffix}'
var keyVaultName = take('${namePrefix}-kv-${suffix}', 24)
var storageName = toLower(take(replace('${namePrefix}evidence${suffix}', '-', ''), 24))
var workspaceName = '${namePrefix}-law-${suffix}'
var keyVaultSecretsUserRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var storageBlobDataContributorRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')

resource runtimeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
}

var runtimePrincipalId = empty(runtimePrincipalObjectId) ? runtimeIdentity.properties.principalId : runtimePrincipalObjectId

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    publicNetworkAccess: 'Disabled'
  }
}

resource evidenceStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
  }
}

resource evidenceBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: evidenceStorage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: evidenceBlobService
  name: 'qstg-evidence'
  properties: {
    publicAccess: 'None'
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

resource keyVaultSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, runtimePrincipalId, keyVaultSecretsUserRole)
  scope: vault
  properties: {
    principalId: runtimePrincipalId
    roleDefinitionId: keyVaultSecretsUserRole
    principalType: 'ServicePrincipal'
  }
}

resource evidenceStorageAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceStorage.id, runtimePrincipalId, storageBlobDataContributorRole)
  scope: evidenceStorage
  properties: {
    principalId: runtimePrincipalId
    roleDefinitionId: storageBlobDataContributorRole
    principalType: 'ServicePrincipal'
  }
}

output managedIdentityClientId string = runtimeIdentity.properties.clientId
output managedIdentityPrincipalId string = runtimeIdentity.properties.principalId
output keyVaultUrl string = vault.properties.vaultUri
output evidenceStorageAccount string = evidenceStorage.name
output evidenceContainerName string = evidenceContainer.name
output logAnalyticsWorkspaceId string = workspace.properties.customerId
