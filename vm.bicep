// vm.bicep
// The honeypot VM: a small Ubuntu box with a public IP, placed in the locked-
// down subnet from network.bicep. It gets a managed identity that is granted
// write-only access to the evidence container in storage.bicep - so it can
// ship logs with NO stored secret key anywhere on disk.

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Subnet ID (from network.bicep) to place the VM in.')
param subnetId string

@description('Storage account resource ID (from storage.bicep) for the role grant.')
param storageAccountId string

@description('Your SSH PUBLIC key (contents of ~/.ssh/honeypot_key.pub).')
param adminPublicKey string

@description('Admin username for the VM.')
param adminUsername string = 'azureuser'

@description('cloud-init / custom data script, base64-encoded by the caller.')
param customDataBase64 string = ''

@description('Prefix for naming.')
param namePrefix string = 'honeypot'

@description('VM size. B2s is small and cheap, plenty for a 24h sensor.')
param vmSize string = 'Standard_B2s'

var vmName     = '${namePrefix}-vm'
var pipName    = '${namePrefix}-pip'
var nicName    = '${namePrefix}-nic'

// Built-in Azure role "Storage Blob Data Contributor". Lets the identity
// read/write blob data (but not manage the account itself).
var blobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

// ---- Public IP ----
// The honeypot needs a reachable address on the internet. Static so it does
// not change out from under your logging.

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: pipName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// ---- Network interface ----
// Connects the VM to the subnet and attaches the public IP. The subnet's NSG
// (from network.bicep) applies automatically to traffic through this NIC.

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

// ---- The VM ----

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location

  // A system-assigned managed identity: an Azure-managed credential tied to
  // this VM's lifetime. We grant IT access to storage below, so nothing on
  // the box holds a storage key an attacker could steal.
  identity: {
    type: 'SystemAssigned'
  }

  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      // SSH key only - password auth is disabled entirely.
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
      }
      // cloud-init script that configures the box on first boot.
      customData: empty(customDataBase64) ? null : customDataBase64
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

// ---- Role assignment: VM identity -> storage ----
// Grants the VM's managed identity write access to blob data on the storage
// account. This is the keyless link: the VM authenticates to storage as
// itself, using a token Azure rotates automatically.

resource storageAccountRef 'Microsoft.Storage/storageAccounts@2024-01-01' existing = {
  name: last(split(storageAccountId, '/'))
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccountId, vm.id, blobDataContributorRoleId)
  scope: storageAccountRef
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataContributorRoleId)
    principalId: vm.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Outputs ----

@description('Public IP of the honeypot - this is the address attackers hit.')
output publicIpAddress string = publicIp.properties.ipAddress

@description('SSH command to connect (from your allowed IP only).')
output sshCommand string = 'ssh -i ~/.ssh/honeypot_key ${adminUsername}@${publicIp.properties.ipAddress}'

@description('VM name.')
output vmName string = vm.name
