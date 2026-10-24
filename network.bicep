// network.bicep
// Virtual network + locked-down NSG for the honeypot, now with a subnet for
// Azure Bastion so you log in over the Azure backbone instead of exposing SSH.
//
// Subnet layout inside 10.50.0.0/24:
//   10.50.0.0/27   honeypot-snet      (the VM)            .0  - .31
//   10.50.0.64/26  AzureBastionSubnet (Bastion, fixed name) .64 - .127

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Prefix used to name resources.')
param namePrefix string = 'honeypot'

// ---- Variables ----

var vnetName       = '${namePrefix}-vnet'
var subnetName     = '${namePrefix}-snet'
var nsgName        = '${namePrefix}-nsg'

var vnetAddressSpace = '10.50.0.0/24'
var subnetPrefix     = '10.50.0.0/27'
var bastionPrefix    = '10.50.0.64/26' // Bastion requires /26 or larger

// ---- Network Security Group (honeypot subnet) ----

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      // --- Inbound ---

      // The honeypot's front door: HTTP from anywhere. This is the ONLY port
      // we expose to the internet now.
      {
        name: 'Allow-HTTP-Honeypot'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }

      // SSH is NO LONGER open to the internet. Bastion connects to the VM from
      // inside the VNet, so we only allow 22 from the VirtualNetwork. Port 22
      // is unreachable from the public internet entirely.
      {
        name: 'Allow-SSH-FromBastion'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }

      // --- Outbound ---

      // Allow traffic inside the VNet (storage private endpoint, Bastion).
      {
        name: 'Allow-VNet-Out'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }

      // Allow HTTPS to Azure Monitor so the VM can send logs to Log Analytics.
      // Scoped to the AzureMonitor service tag only - not the whole internet.
      {
        name: 'Allow-AzureMonitor-Out'
        properties: {
          priority: 210
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureMonitor'
          destinationPortRange: '443'
        }
      }

      // The containment rule: deny every other outbound path. Sits above
      // Azure's default AllowInternetOutBound (65001), so a compromised box
      // cannot reach the internet to attack others or pull second-stage code.
      {
        name: 'Deny-All-Out'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ---- Virtual network + subnets ----

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [ vnetAddressSpace ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        // Name MUST be exactly 'AzureBastionSubnet' or Bastion deployment fails.
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: bastionPrefix
        }
      }
    ]
  }
}

// ---- Outputs ----

@description('Resource ID of the honeypot subnet (VM + private endpoint).')
output subnetId string = vnet.properties.subnets[0].id

@description('Resource ID of the AzureBastionSubnet.')
output bastionSubnetId string = vnet.properties.subnets[1].id

@description('Resource ID of the VNet, for the Private DNS zone link.')
output vnetId string = vnet.id

@description('Name of the VNet.')
output vnetName string = vnet.name
