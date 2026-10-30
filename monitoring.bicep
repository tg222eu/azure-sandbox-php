// monitoring.bicep
// The analysis pipeline: a Log Analytics workspace, a custom table for the
// honeypot's text logs, a Data Collection Rule (DCR) that tells the VM which
// files to ship, the Azure Monitor Agent on the VM, and the association that
// binds them. After this, the logs written to /var/log/honeypot/ on the box
// show up in Log Analytics for KQL.
//
// Flow of data:
//   VM writes /var/log/honeypot/*.log  ->  Azure Monitor Agent reads them
//   ->  DCR routes them  ->  Log Analytics (HoneypotLogs_CL)  ->  your KQL.

// ---- Parameters ----

@description('Azure region, e.g. swedencentral.')
param location string

@description('Name of the existing honeypot VM (to attach the agent + DCR).')
param vmName string

@description('Prefix used to name resources.')
param namePrefix string = 'honeypot'

@description('Log retention in days for the workspace.')
param retentionInDays int = 30

var workspaceName = '${namePrefix}-law'
var dcrName       = '${namePrefix}-dcr'
var customTableName = 'HoneypotLogs_CL' // custom tables must end in _CL

// ---- Log Analytics workspace ----
// The store your KQL queries run against.

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
  }
}

// ---- Custom table for the honeypot's text logs ----
// Apache requests, sinkhole hits, DNS lookups, iptables drops - all land here
// as raw lines you parse in KQL. Custom-log tables must end in _CL.

resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: customTableName
  properties: {
    schema: {
      name: customTableName
      columns: [
        {
          name: 'TimeGenerated'
          type: 'datetime'
        }
        {
          name: 'RawData'
          type: 'string'
        }
        {
          name: 'FilePath'
          type: 'string'
        }
      ]
    }
  }
}

// ---- Data Collection Rule ----
// Declares TWO data sources:
//   1. The honeypot's custom log files (/var/log/honeypot/*.log).
//   2. Syslog - which carries auditd (execve) and the iptables drop messages,
//      i.e. the "someone got in / tried to call out" signals.

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Linux'
  properties: {
    streamDeclarations: {
      'Custom-HoneypotTextLogs': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'RawData'
            type: 'string'
          }
          {
            name: 'FilePath'
            type: 'string'
          }
        ]
      }
    }
    dataSources: {
      logFiles: [
        {
          name: 'honeypotTextLogs'
          streams: [ 'Custom-HoneypotTextLogs' ]
          // Top level: sinkhole/DNS/iptables logs. apache/ subfolder: the
          // honeypot's own inbound request log (attacker IPs + URLs).
          filePatterns: [
            '/var/log/honeypot/*.log'
            '/var/log/honeypot/apache/*.log'
          ]
          format: 'text'
          settings: {
            text: {
              recordStartTimestampFormat: 'ISO 8601'
            }
          }
        }
      ]
      syslog: [
        {
          name: 'honeypotSyslog'
          streams: [ 'Microsoft-Syslog' ]
          // auth/authpriv carry sudo + ssh; kern carries the iptables LOG lines;
          // daemon/user carry app messages. auditd is read by the agent too.
          facilityNames: [
            'auth'
            'authpriv'
            'cron'
            'daemon'
            'kern'
            'syslog'
            'user'
          ]
          logLevels: [
            'Info'
            'Notice'
            'Warning'
            'Error'
            'Critical'
            'Alert'
            'Emergency'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'laDestination'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        // Custom log files -> the HoneypotLogs_CL table.
        streams: [ 'Custom-HoneypotTextLogs' ]
        destinations: [ 'laDestination' ]
        transformKql: 'source | extend TimeGenerated = now()'
        outputStream: 'Custom-${customTableName}'
      }
      {
        // Syslog -> the built-in Syslog table.
        streams: [ 'Microsoft-Syslog' ]
        destinations: [ 'laDestination' ]
      }
    ]
  }
  dependsOn: [
    customTable
  ]
}

// ---- Reference the existing VM ----

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

// ---- Azure Monitor Agent on the VM ----
// Reads the files and syslog, and ships them per the DCR. It needs the
// outbound-to-AzureMonitor NSG rule we added in network.bicep.

resource azureMonitorAgent 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// ---- Bind the DCR to the VM ----
// Without this association the agent is installed but collects nothing.

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: '${namePrefix}-dcra'
  scope: vm
  properties: {
    dataCollectionRuleId: dcr.id
    description: 'Bind honeypot DCR to the VM.'
  }
  dependsOn: [
    azureMonitorAgent
  ]
}

// ---- Outputs ----

@description('Resource ID of the Log Analytics workspace.')
output workspaceId string = workspace.id

@description('The workspace customer ID (GUID) used in some queries/config.')
output workspaceCustomerId string = workspace.properties.customerId

@description('Name of the custom logs table for your KQL.')
output customTableName string = customTableName
