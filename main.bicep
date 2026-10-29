// main.bicep
// Orchestrator. Deploys every module in order and passes each module's outputs
// into the next, so the whole honeypot comes up with one command:
//
//   az deployment group create -g <rg> -f main.bicep -p main.bicepparam
//
// DEPLOY IN TWO PASSES (see the 'sealed' parameter):
//   1. sealed=false  -> box can reach the internet so cloud-init installs
//                       Docker, pulls the PHP image, installs the agent.
//      Wait until the VM's /var/log/honeypot-setup.log shows setup finished.
//   2. sealed=true   -> redeploy to remove the temporary egress and lock the
//                       box down BEFORE exposing it as a target.
//
// Paths assume all files live in ONE folder (as in the GitHub repo). If you
// move the modules into subfolders, update the paths below.

targetScope = 'resourceGroup'

// ---- Parameters ----

@description('Azure region for everything, e.g. swedencentral.')
param location string = resourceGroup().location

@description('Your SSH PUBLIC key (contents of ~/.ssh/sandbox_key.pub).')
param adminPublicKey string

@description('Your public IP (CIDR, e.g. 203.0.113.4/32) allowed to SSH in.')
param adminSourceIp string

@description('Admin username on the VM.')
param adminUsername string = 'azureuser'

@description('Prefix used to name all resources.')
param namePrefix string = 'honeypot'

@description('''SEALED state. Deploy with false first (setup needs internet),
then redeploy with true to lock down egress before the box is exposed.''')
param sealed bool = true

// ---- cloud-init: load, fill in the storage names, base64-encode ----
// The script has __STORAGE_ACCOUNT__ / __EVIDENCE_CONTAINER__ placeholders.
// We replace them with the storage module's real outputs, then base64 the
// result for the VM's customData.
var cloudInitRaw = loadTextContent('cloud-init.sh')
var cloudInitFilled = replace(
  replace(cloudInitRaw, '__STORAGE_ACCOUNT__', storage.outputs.storageAccountName),
  '__EVIDENCE_CONTAINER__', storage.outputs.evidenceContainerName
)
var cloudInitBase64 = base64(cloudInitFilled)

// ---- 1. Network (VNet, subnet, locked-down NSG) ----

module network 'network.bicep' = {
  name: 'network'
  params: {
    location: location
    namePrefix: namePrefix
    adminSourceIp: adminSourceIp
    sealed: sealed
  }
}

// ---- 2. Storage (account + private endpoint + DNS) ----

module storage 'storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    namePrefix: namePrefix
    subnetId: network.outputs.subnetId
    vnetId: network.outputs.vnetId
  }
}

// ---- 3. VM (public IP, NIC, VM, managed identity + storage role) ----

module vm 'vm.bicep' = {
  name: 'vm'
  params: {
    location: location
    namePrefix: namePrefix
    subnetId: network.outputs.subnetId
    storageAccountId: storage.outputs.storageAccountId
    adminPublicKey: adminPublicKey
    adminUsername: adminUsername
    customDataBase64: cloudInitBase64
  }
}

// ---- 4. Monitoring (Log Analytics + DCR + agent on the VM) ----
// Login is free direct SSH from your IP (adminSourceIp). No Bastion.

module monitoring 'monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    namePrefix: namePrefix
    vmName: vm.outputs.vmName
  }
}

// ---- Outputs: what you need after deploy ----

@description('Public IP of the honeypot (the address attackers hit).')
output honeypotPublicIp string = vm.outputs.publicIpAddress

@description('Name of the VM (SSH to its public IP from your allowed IP).')
output vmName string = vm.outputs.vmName

@description('Log Analytics workspace for your KQL queries.')
output workspaceId string = monitoring.outputs.workspaceId

@description('Custom table holding the honeypot logs.')
output logsTable string = monitoring.outputs.customTableName

@description('Reminder of the current lockdown state.')
output sealedState string = sealed ? 'SEALED (no internet egress)' : 'OPEN for setup - reseal before exposing!'
