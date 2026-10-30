// network.bicep
// Virtual network + locked-down NSG for the honeypot. Login is free direct SSH
// from your IP only (adminSourceIp); port 80 is the only internet-facing port.
//
// Subnet layout inside 10.50.0.0/24:
//   10.50.0.0/27   honeypot-snet   (the VM)   .0 - .31

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Prefix used to name resources.')
param namePrefix string = 'honeypot'

@description('''Your public IP in CIDR form (e.g. 203.0.113.4/32) allowed to
SSH to the VM directly. Keep this to YOUR address only. Put the real value in
main.local.bicepparam, not the committed param file.''')
param adminSourceIp string

@description('''When true (default), the box is SEALED: no outbound internet.
Deploy FIRST with sealed=false so cloud-init can install Docker, pull the image
and install the agent; once /var/log/honeypot-setup.log shows it finished,
redeploy with sealed=true to remove the temporary egress and lock the box down
BEFORE it is worth attacking.''')
param sealed bool = true

// ---- Variables ----

var vnetName       = '${namePrefix}-vnet'
var subnetName     = '${namePrefix}-snet'
var nsgName        = '${namePrefix}-nsg'

var vnetAddressSpace = '10.50.0.0/24'
var subnetPrefix     = '10.50.0.0/27'

// A temporary outbound rule that only exists while sealed=false, so first-boot
// setup can reach the package registries and Docker Hub. Priority 250 sits
// below the VNet/Monitor allows and ABOVE Deny-All-Out (300).
var setupEgressRule = [
  {
    name: 'Allow-Setup-Temp'
    properties: {
      priority: 250
      direction: 'Outbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: 'Internet'
      destinationPortRanges: [ '80', '443' ]
    }
  }
]

// The honeypot's front door (port 80 from anywhere). Added ONLY while
// sealed=true, so the vulnerable box is never reachable during the setup
// window when egress is still open. This guarantees the box is never both
// exploitable AND able to reach the internet at the same time.
var httpRule = [
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
]

// ---- Network Security Group (honeypot subnet) ----

// Permanent rules. Port 80 (httpRule) is added only when sealed; the temporary
// setup-egress rule is added only when NOT sealed (see securityRules below).
var coreRules = [
      // --- Inbound ---

      // SSH allowed ONLY from your IP (direct SSH, free - no Bastion needed).
      // The whole internet still cannot reach port 22; just your address can.
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

      // Allow traffic inside the VNet (reaches the storage private endpoint).
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

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    // sealed=true  -> open port 80 to the world, no internet egress.
    // sealed=false -> port 80 CLOSED, temporary egress open for first-boot setup.
    securityRules: sealed ? concat(coreRules, httpRule) : concat(coreRules, setupEgressRule)
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
    ]
  }
}

// ---- Outputs ----

@description('Resource ID of the honeypot subnet (VM + private endpoint).')
output subnetId string = vnet.properties.subnets[0].id

@description('Resource ID of the VNet, for the Private DNS zone link.')
output vnetId string = vnet.id

@description('Name of the VNet.')
output vnetName string = vnet.name
