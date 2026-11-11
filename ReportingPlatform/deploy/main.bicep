// =====================================================================================
// Identity & Azure reporting platform
//
// Deployed by Deploy-ReportingPlatform.ps1, which asks about the target environment and
// passes these parameters. Everything is private: the Function App and both storage
// accounts have public network access disabled and are reached through private endpoints.
//
// Not in this template (done by the deploy script, because they live outside the resource
// group or in Entra ID):
//   * the outbound integration subnet (created or delegated in the existing VNet)
//   * the sign-in app registration
//   * Microsoft Graph permissions and Azure Reader for the managed identity
// =====================================================================================

targetScope = 'resourceGroup'

// --- Placement & naming -------------------------------------------------------------

@description('Azure region. Must support Flex Consumption.')
param location string = resourceGroup().location

@description('Short prefix used in resource names, e.g. idrpt.')
@minLength(2)
@maxLength(10)
param namePrefix string

@description('Environment name used in resource names, e.g. prd.')
@minLength(2)
@maxLength(5)
param environmentName string = 'prd'

@description('Optional name overrides: functionApp, plan, identity, hostStorage, reportsStorage, appInsights, logAnalytics.')
param names object = {}

@description('Tags for every resource.')
param tags object = {}

// --- Network --------------------------------------------------------------------------

@description('Resource ID of the existing subnet for the private endpoints.')
param privateEndpointSubnetId string

@description('Resource ID of the subnet for outbound VNet integration (delegated to Microsoft.App/environments).')
param integrationSubnetId string

@description('privatelink DNS zone resource IDs: blob, queue, table, sites. Leave one out (or empty) when Azure Policy creates the records.')
param privateDnsZoneIds object = {}

// --- Sign-in --------------------------------------------------------------------------

@description('Client ID of the sign-in app registration.')
param easyAuthClientId string

@description('Optional: only members of these group object IDs may sign in (needs group claims). The main control is assignment required on the enterprise app.')
param easyAuthAllowedGroupIds array = []

// --- Reports --------------------------------------------------------------------------

@description('Tenant to report on.')
param reportTenantId string = tenant().tenantId

@description('NCRONTAB schedules in UTC: leastPrivilege, azureChanges, appSignIns, conditionalAccess, authMethods.')
param schedules object = {}

@description('Move dated report copies to cool storage after this many days.')
param historyCoolAfterDays int = 30

@description('Delete dated report copies after this many days.')
param historyRetentionDays int = 400

// --- Sizing ---------------------------------------------------------------------------

@allowed([512, 2048, 4096])
param instanceMemoryMB int = 2048

@minValue(1)
@maxValue(1000)
param maximumInstanceCount int = 40

@allowed(['Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_GZRS'])
param storageSku string = 'Standard_ZRS'

@description('Existing Log Analytics workspace resource ID. Empty: create one.')
param logAnalyticsWorkspaceId string = ''

param logRetentionDays int = 30

// =====================================================================================

var base = '${namePrefix}-${environmentName}'
var compact = '${namePrefix}${environmentName}'
var n = union({
  functionApp: 'func-${base}-reports'
  plan: 'asp-${base}-reports'
  identity: 'id-${base}-reports'
  hostStorage: take('st${compact}rptfn', 24)
  reportsStorage: take('st${compact}rptdata', 24)
  appInsights: 'appi-${base}-reports'
  logAnalytics: 'log-${base}-reports'
}, names)
var allTags = union({ workload: 'identity-azure-reporting' }, tags)
var sched = union({
  leastPrivilege: '0 0 2 * * *'     // daily 02:00
  azureChanges: '0 30 2 * * *'      // daily 02:30
  appSignIns: '0 0 4 * * 1'         // Mondays 04:00
  conditionalAccess: '0 30 4 * * 1' // Mondays 04:30
  authMethods: '0 0 3 * * *'        // daily 03:00
}, schedules)
var reportsContainerName = 'reports'
var packageContainerName = 'app-package'

var roleIds = {
  blobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  blobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  queueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  tableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
}

// --- Identity -------------------------------------------------------------------------

// The identity everything runs as: report jobs (Graph + ARM), storage, App Insights.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: n.identity
  location: location
  tags: allTags
}

// --- Storage --------------------------------------------------------------------------
// Two accounts: one for the Function App (deployment package, host state), one for report
// data. Both: Entra auth only, no public network access, private endpoints only.

var storageProperties = {
  minimumTlsVersion: 'TLS1_2'
  supportsHttpsTrafficOnly: true
  allowBlobPublicAccess: false
  allowSharedKeyAccess: false
  defaultToOAuthAuthentication: true
  publicNetworkAccess: 'Disabled'
  allowCrossTenantReplication: false
  isLocalUserEnabled: false
  isSftpEnabled: false
  allowedCopyScope: 'PrivateLink'
  networkAcls: {
    defaultAction: 'Deny'
    bypass: 'None'
  }
  encryption: {
    requireInfrastructureEncryption: true
    keySource: 'Microsoft.Storage'
    services: {
      blob: { enabled: true, keyType: 'Account' }
      file: { enabled: true, keyType: 'Account' }
    }
  }
}

resource hostStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: n.hostStorage
  location: location
  tags: allTags
  kind: 'StorageV2'
  sku: { name: storageSku }
  properties: storageProperties
}

resource hostBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: hostStorage
  name: 'default'
}

resource packageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: hostBlob
  name: packageContainerName
  properties: { publicAccess: 'None' }
}

resource reportsStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: n.reportsStorage
  location: location
  tags: allTags
  kind: 'StorageV2'
  sku: { name: storageSku }
  properties: storageProperties
}

resource reportsBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: reportsStorage
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 14 }
    containerDeleteRetentionPolicy: { enabled: true, days: 14 }
  }
}

resource reportsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: reportsBlob
  name: reportsContainerName
  properties: { publicAccess: 'None' }
}

// Dated copies: cool after N days, delete after the retention period. Old versions of
// latest/ and status/ blobs are cleaned up after 30 days.
resource reportsLifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: reportsStorage
  name: 'default'
  dependsOn: [reportsBlob]
  properties: {
    policy: {
      rules: [
        {
          name: 'report-history'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: ['blockBlob'], prefixMatch: ['${reportsContainerName}/history/'] }
            actions: {
              baseBlob: {
                tierToCool: { daysAfterModificationGreaterThan: historyCoolAfterDays }
                delete: { daysAfterModificationGreaterThan: historyRetentionDays }
              }
              version: { delete: { daysAfterCreationGreaterThan: 30 } }
            }
          }
        }
        {
          name: 'old-versions'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: { blobTypes: ['blockBlob'], prefixMatch: ['${reportsContainerName}/latest/', '${reportsContainerName}/status/'] }
            actions: {
              version: { delete: { daysAfterCreationGreaterThan: 30 } }
            }
          }
        }
      ]
    }
  }
}

// --- Monitoring -----------------------------------------------------------------------

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (empty(logAnalyticsWorkspaceId)) {
  name: n.logAnalytics
  location: location
  tags: allTags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

// Entra-only ingestion: the Function App sends telemetry with its managed identity.
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: n.appInsights
  location: location
  tags: allTags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: empty(logAnalyticsWorkspaceId) ? workspace.id : logAnalyticsWorkspaceId
    DisableLocalAuth: true
  }
}

// --- Role assignments for the managed identity ----------------------------------------
// Graph permissions and Azure Reader for the reports are granted by the deploy script.

resource hostBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hostStorage.id, identity.id, roleIds.blobDataOwner)
  scope: hostStorage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.blobDataOwner)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource hostQueueRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hostStorage.id, identity.id, roleIds.queueDataContributor)
  scope: hostStorage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.queueDataContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource hostTableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hostStorage.id, identity.id, roleIds.tableDataContributor)
  scope: hostStorage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.tableDataContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Report data: read/write on the reports container only.
resource reportsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(reportsContainer.id, identity.id, roleIds.blobDataContributor)
  scope: reportsContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.blobDataContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource appInsightsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, identity.id, roleIds.monitoringMetricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.monitoringMetricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// --- Function App ---------------------------------------------------------------------

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: n.plan
  location: location
  tags: allTags
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: n.functionApp
  location: location
  tags: allTags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  // The app needs its host storage roles before it starts.
  dependsOn: [hostBlobRole, hostQueueRole, hostTableRole, packageContainer]
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    // Private only: inbound through the private endpoint, outbound through the VNet.
    // (Re-applying this also closes any temporary deployment access the script opened.)
    publicNetworkAccess: 'Disabled'
    virtualNetworkSubnetId: integrationSubnetId
    siteConfig: {
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
    }
    functionAppConfig: {
      // Deployment package storage, accessed with the managed identity (no keys).
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${hostStorage.properties.primaryEndpoints.blob}${packageContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: identity.id
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
      }
      runtime: {
        name: 'powershell'
        version: '7.4'
      }
    }
  }
}

resource appSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: functionApp
  name: 'appsettings'
  properties: {
    // Host storage with the managed identity
    AzureWebJobsStorage__accountName: hostStorage.name
    AzureWebJobsStorage__credential: 'managedidentity'
    AzureWebJobsStorage__clientId: identity.properties.clientId

    // Application Insights with Entra auth
    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
    APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${identity.properties.clientId};Authorization=AAD'

    // Read by the ReportPlatform module
    AZURE_CLIENT_ID: identity.properties.clientId
    REPORT_TENANT_ID: reportTenantId
    REPORTS_BLOB_ENDPOINT: reportsStorage.properties.primaryEndpoints.blob
    REPORTS_CONTAINER: reportsContainerName

    // Timer schedules (function.json: "schedule": "%SCHEDULE_...%")
    SCHEDULE_LEAST_PRIVILEGE: sched.leastPrivilege
    SCHEDULE_AZURE_CHANGES: sched.azureChanges
    SCHEDULE_APP_SIGNINS: sched.appSignIns
    SCHEDULE_CONDITIONAL_ACCESS: sched.conditionalAccess
    SCHEDULE_AUTH_METHODS: sched.authMethods
  }
}

// App Service authentication (Easy Auth) with Entra ID. No client secret: sign-in uses the
// ID token flow. Who can sign in is controlled by 'assignment required' on the enterprise app.
resource authSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
    }
    httpSettings: { requireHttps: true }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: easyAuthClientId
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [easyAuthClientId, 'api://${easyAuthClientId}']
          defaultAuthorizationPolicy: empty(easyAuthAllowedGroupIds) ? {} : {
            allowedPrincipals: { groups: easyAuthAllowedGroupIds }
          }
        }
      }
    }
    login: { tokenStore: { enabled: false } }
  }
}

// No basic-auth (publishing profile) deployments: code is deployed with Entra auth.
resource scmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: functionApp
  name: 'scm'
  properties: { allow: false }
}

resource ftpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: functionApp
  name: 'ftp'
  properties: { allow: false }
}

// --- Private endpoints ----------------------------------------------------------------

var privateEndpoints = [
  { key: 'host-blob', target: hostStorage.id, group: 'blob', zone: privateDnsZoneIds.?blob ?? '' }
  { key: 'host-queue', target: hostStorage.id, group: 'queue', zone: privateDnsZoneIds.?queue ?? '' }
  { key: 'host-table', target: hostStorage.id, group: 'table', zone: privateDnsZoneIds.?table ?? '' }
  { key: 'reports-blob', target: reportsStorage.id, group: 'blob', zone: privateDnsZoneIds.?blob ?? '' }
  { key: 'function', target: functionApp.id, group: 'sites', zone: privateDnsZoneIds.?sites ?? '' }
]

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = [for pe in privateEndpoints: {
  name: 'pe-${base}-reports-${pe.key}'
  location: location
  tags: allTags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    customNetworkInterfaceName: 'nic-pe-${base}-reports-${pe.key}'
    privateLinkServiceConnections: [
      {
        name: 'psc-${pe.key}'
        properties: {
          privateLinkServiceId: pe.target
          groupIds: [pe.group]
        }
      }
    ]
  }
}]

// Zone groups only for zones we were given: platforms where Azure Policy creates the
// records add their own zone group, and an incremental deployment leaves it alone.
resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = [for (pe, i) in privateEndpoints: if (!empty(pe.zone)) {
  parent: privateEndpoint[i]
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: replace(last(split(pe.zone, '/')), '.', '-')
        properties: { privateDnsZoneId: pe.zone }
      }
    ]
  }
}]

// --- Outputs --------------------------------------------------------------------------

output functionAppName string = functionApp.name
output functionAppHostName string = functionApp.properties.defaultHostName
output functionAppId string = functionApp.id
output managedIdentityName string = identity.name
output managedIdentityPrincipalId string = identity.properties.principalId
output managedIdentityClientId string = identity.properties.clientId
output reportsStorageAccountName string = reportsStorage.name
output hostStorageAccountName string = hostStorage.name
