// storage.bicep
// Storage account for honeypot logs and evidence, reachable ONLY over a
// private endpoint inside the VNet. Public internet access is turned off.
//
// Three things work together to make this happen:
//   1. The storage account      - with public access disabled.
//   2. The private endpoint      - a private IP inside your subnet that maps
//                                  to this specific storage account.
//   3. The private DNS zone      - so the storage hostname resolves to that
//                                  private IP instead of the public one.
// Miss any one of them and the VM either can't reach storage, or reaches it
// over the public internet (which the NSG now blocks anyway).

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Subnet (from network.bicep) where the private endpoint is placed.')
param subnetId string

@description('VNet resource ID (from network.bicep) to link the DNS zone to.')
param vnetId string

@description('Prefix for naming.')
param namePrefix string = 'honeypot'

// Storage account names must be globally unique, 3-24 chars, lowercase
// letters and numbers only. uniqueString() derives a stable hash from the
// resource group id so the name is unique but reproducible.
var storageAccountName = take('${namePrefix}log${uniqueString(resourceGroup().id)}', 24)

// Blob is the storage service we use (object storage for files/logs). This is
// the fixed DNS zone name Azure uses for private blob endpoints.
var blobPrivateDnsZoneName = 'privatelink.blob${environment().suffixes.storage}'
var privateEndpointName    = '${namePrefix}-pe-blob'

// ---- Storage account ----

resource storageAccount 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS' // locally redundant; cheapest, fine for a 24h test
  }
  kind: 'StorageV2'
  properties: {
    // Force HTTPS and a modern TLS floor.
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'

    // No access keys; we rely on Azure AD (managed identity) instead. One less
    // secret for an attacker to find if they somehow reach the account.
    allowSharedKeyAccess: false

    // The lockdown: default-deny the network, and turn OFF public access.
    // After this, the ONLY way in is the private endpoint below.
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// A blob container to hold the evidence.
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2024-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2024-01-01' = {
  parent: blobService
  name: 'evidence'
  properties: {
    publicAccess: 'None'
  }
}

// ---- Private DNS zone ----
// Without this, the VM asks DNS for the storage hostname and gets the PUBLIC
// IP back - which the firewall blocks. This zone overrides that lookup so the
// name resolves to the private endpoint's internal IP instead.

resource blobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: blobPrivateDnsZoneName
  location: 'global' // private DNS zones are always global
}

// Link the zone to the VNet, so machines in the VNet actually use it.
resource dnsZoneVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: blobPrivateDnsZone
  name: '${namePrefix}-dnslink'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnetId
    }
  }
}

// ---- Private endpoint ----
// Creates a network interface with a private IP in your subnet that connects
// privately to the storage account's blob service.

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: privateEndpointName
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${privateEndpointName}-conn'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [ 'blob' ] // which sub-service of storage to expose
        }
      }
    ]
  }
}

// Tie the private endpoint's IP into the DNS zone automatically, so the
// correct A record is created and kept in sync by Azure.
resource peDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob-config'
        properties: {
          privateDnsZoneId: blobPrivateDnsZone.id
        }
      }
    ]
  }
}

// ---- Outputs ----

@description('Storage account name, passed to the VM so it knows where to ship logs.')
output storageAccountName string = storageAccount.name

@description('Resource ID of the storage account, used to grant the VM write access.')
output storageAccountId string = storageAccount.id

@description('Name of the evidence container.')
output evidenceContainerName string = evidenceContainer.name
