// bastion.bicep
// Azure Bastion: a managed jump host that lets you open an SSH session to the
// honeypot VM through the Azure portal, over the Azure backbone. Because of it,
// the VM needs NO public SSH port - port 22 is reachable only from inside the
// VNet (see Allow-SSH-FromBastion in network.bicep).
//
// Bastion needs two things: a public IP (for the portal connection) and the
// AzureBastionSubnet created in network.bicep.

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Resource ID of the AzureBastionSubnet (output of network.bicep).')
param bastionSubnetId string

@description('Prefix used to name resources.')
param namePrefix string = 'honeypot'

@description('''Bastion SKU.
- Basic: standard managed Bastion, always-on, billed per hour.
- Developer: low-cost/free shared option where available, fewer features.
- Standard: scaling and extra features, more expensive.
Basic is the safe default for a short-lived sandbox.''')
@allowed([
  'Basic'
  'Standard'
  'Developer'
])
param bastionSku string = 'Basic'

var bastionName = '${namePrefix}-bastion'
var bastionPipName = '${namePrefix}-bastion-pip'

// ---- Public IP for Bastion ----
// Bastion requires a Standard-SKU, statically allocated public IP. This is the
// endpoint your browser connects to; it does NOT expose the VM directly.

resource bastionPublicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: bastionPipName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// ---- Bastion host ----
// Lives in the AzureBastionSubnet and brokers SSH/RDP sessions to VMs in the
// same VNet. You connect from the portal; Bastion reaches the VM on its
// private IP, so no VM port is ever published to the internet.

resource bastion 'Microsoft.Network/bastionHosts@2024-05-01' = {
  name: bastionName
  location: location
  sku: {
    name: bastionSku
  }
  properties: {
    ipConfigurations: [
      {
        name: 'bastionIpConfig'
        properties: {
          subnet: {
            id: bastionSubnetId
          }
          publicIPAddress: {
            id: bastionPublicIp.id
          }
        }
      }
    ]
  }
}

// ---- Outputs ----

@description('Name of the Bastion host.')
output bastionName string = bastion.name

@description('Public IP of the Bastion host (the portal connection endpoint).')
output bastionPublicIp string = bastionPublicIp.properties.ipAddress
