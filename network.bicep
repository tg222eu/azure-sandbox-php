param location string
param adminSourceIp string
param namePrefix string = 'honeypot'

var vnetName   = '${namePrefix}-vnet'
var subnetName = '${namePrefix}-snet'
var nsgName    = '${namePrefix}-nsg'
var vnetAddressSpace = '10.50.0.0/24'
var subnetPrefix     = '10.50.0.0/27'

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      // --- Inbound ---

      // Allow HTTP from anywhere. This is the honeypot's "front door":
      // the whole point is to let the internet reach the web service.
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

      // Allow SSH (port 22) ONLY from your IP. This keeps management access
      // private while the web port stays open to the world.
      {
        name: 'Allow-SSH-MyIP'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: adminSourceIp
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }

      // --- Outbound ---
      // Containment. By default Azure lets a VM talk to the whole internet.
      // These rules replace that with: reach your own storage privately, and
      // nothing else. The attacker's second-stage download has nowhere to go.

      // Allow traffic to other machines inside this VNet (e.g. the private
      // endpoint for storage, added in the storage module). This is what lets
      // the VM ship its logs out without touching the public internet.
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

      // Deny all other outbound traffic. Sits at priority 300, ABOVE Azure's
      // default AllowInternetOutBound (65001), so it wins: no egress to the
      // internet. This is the single most important containment rule.
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

// =============================================================================
// Virtual network + subnet
// =============================================================================

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
          // Needed so a private endpoint can be created in this subnet later.
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// =============================================================================
// Outputs
// =============================================================================

output subnetId string = vnet.properties.subnets[0].id
output vnetId string = vnet.id
output vnetName string = vnet.name
