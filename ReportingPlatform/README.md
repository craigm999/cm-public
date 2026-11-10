# Identity & Azure reporting platform

Runs the reports in [`Entra/`](../Entra) and [`Azure/`](../Azure) on a schedule and publishes them
in a private, Entra-protected web portal with a tab per report.

```mermaid
flowchart LR
  subgraph corp[Corporate network / VPN]
    user([Reader group member])
  end
  subgraph vnet[Existing VNet]
    subgraph pe[Shared private endpoint subnet]
      pefn[PE: Function App]
      pehost[PE: host storage<br/>blob / queue / table]
      perpt[PE: reports storage<br/>blob]
    end
    subgraph integ[Integration subnet<br/>delegated Microsoft.App/environments]
      fn[Function App<br/>Flex Consumption, PowerShell 7.4<br/>user-assigned managed identity]
    end
  end
  user -- HTTPS + Entra sign-in --> pefn --> fn
  fn -- managed identity --> perpt
  fn -- managed identity --> pehost
  fn -- outbound, read-only --> graph[(Microsoft Graph)]
  fn -- outbound, read-only --> arm[(Azure Resource Manager)]
  fn -- Entra auth --> ai[(Application Insights)]
```

| Component | Purpose |
|---|---|
| **Function App** (Flex Consumption) | Timer functions run each report as the managed identity; `Web` serves the portal; `Api` serves stored reports. Public network access off. |
| **User-assigned managed identity** | The only identity: read-only Graph application permissions, Azure Reader, storage data roles. No secrets anywhere. |
| **Reports storage account** | `latest/<id>.csv`, `history/<id>/<date>.csv` (daily, kept beyond the 30-day audit / 90-day activity log retention), `status/<id>.json`. Lifecycle: cool after 30 days, delete after 400. |
| **Host storage account** | Function App deployment package and runtime state. |
| **App Service authentication** | Entra sign-in in front of everything. *Assignment required* on the enterprise app + one reader group = only that group can sign in. |
| **Application Insights** | Function logs and failures, Entra-authenticated ingestion. |

Both storage accounts: no public network access, shared keys disabled (Entra auth only),
private endpoints only, copy scope restricted to Private Link.

## Repository layout

```
ReportingPlatform/
  app/                         Function App source
    reports.json               report registry: one entry per report / tab
    Modules/ReportPlatform/    shared module: runs reports, blob storage, auth checks
    Report*/                   one timer function per report
    Api/  Web/                 HTTP functions (data API, portal)
    www/index.html             portal shell (tabs built from the registry)
  build/Build-FunctionPackage.ps1   assembles the zip: app + report scripts + dashboards + modules
  infra/                       Terraform (+ tests/ run with `terraform test`)
  pipelines/azure-pipelines.yml
  setup/Set-ReportingPrerequisites.ps1   one-off privileged setup
```

The report scripts and dashboards stay in `Entra/` and `Azure/`. They're copied into the package at
build time, so they can still be run locally and the dashboards opened offline with a CSV.

## Prerequisites

1. **Resource providers** registered on the subscription (once, by an owner):
   `Microsoft.App` (needed for the Flex Consumption subnet delegation), `Microsoft.Web`,
   `Microsoft.Storage`, `Microsoft.Network`, `Microsoft.ManagedIdentity`, `Microsoft.Insights`,
   `Microsoft.OperationalInsights`.
2. **Subnets** in the existing VNet:
   * Private endpoints: your existing shared subnet.
   * Function App outbound integration: a subnet **delegated to `Microsoft.App/environments`**, /27 or
     larger, not used for private endpoints or anything else (other Flex Consumption apps may share
     it). Name an existing one (`integration_subnet_name`) or let Terraform create one
     (`integration_subnet_address_prefix`).
3. **Private DNS**: `privatelink.blob`, `privatelink.queue`, `privatelink.table` (`.core.windows.net`)
   and `privatelink.azurewebsites.net` zones linked to the VNet. Pass their IDs in
   `private_dns_zone_ids`, or leave them out if Azure Policy creates the records.
4. **Region** that supports Flex Consumption. Note: a new Function App can fail to create in a
   resource group that already holds incompatible App Service plans; if so, use another group.
5. **Pipeline**: self-hosted agents with network access to the private endpoints and `terraform`
   (1.9+), `pwsh` (7.4+), `az`; the agents also need to reach the PowerShell Gallery (or an internal
   feed: `-ModuleRepository`) to bundle `Microsoft.Graph.Authentication`. Service connection
   permissions are listed at the top of the pipeline file.
6. **Reader group**: a security group for the people who should see the portal.

## First deployment

```powershell
# 1. Sign-in app registration (Cloud Application Administrator)
./setup/Set-ReportingPrerequisites.ps1 -Stage AppRegistration `
    -FunctionAppName func-idrpt-prd-reports -ReaderGroup 'SG-Identity-Reports-Readers'
```

2. Copy `infra/environments/prd.tfvars.example` to `infra/environments/prd.tfvars`, fill it in
   (including `easy_auth_client_id` from step 1) and commit it.
3. Run the pipeline. It validates (including `terraform test`), plans, waits for approval,
   applies, and deploys the code.

```powershell
# 4. Directory + Azure permissions for the managed identity
#    (Privileged Role Administrator; Owner/User Access Administrator on the management group)
./setup/Set-ReportingPrerequisites.ps1 -Stage Permissions `
    -ManagedIdentityPrincipalId <terraform output managed_identity_principal_id>
```

5. Wait for the first scheduled runs (or run them from the portal's Function App blade from a
   machine on the network), then browse to `https://<function_app_hostname>` from the corporate
   network.

## What the managed identity can do

| Where | Permission | Used by |
|---|---|---|
| Microsoft Graph (application) | `Directory.Read.All`, `AuditLog.Read.All`, `Application.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory` | Entra reports, and account status for the Azure report's RBAC review (all read-only) |
| Management group (default: tenant root) | Reader | Azure changes report |
| Reports storage `reports` container | Storage Blob Data Contributor | writing / reading reports |
| Host storage | Blob Data Owner, Queue + Table Data Contributor | Functions runtime |
| Application Insights | Monitoring Metrics Publisher | telemetry |

Optional: `UserAuthenticationMethod.Read.All` (setup script `-IncludeUserAuthenticationMethodRead`),
only if you set `"IncludeDisabledUserMethods": true` in the `auth-methods` entry of `reports.json` so
the authentication methods report also covers disabled accounts.

It deliberately does **not** have `RoleAssignmentSchedule.ReadWrite.Directory`: for an application
that permission can create role assignments, i.e. escalate to Global Administrator. The least
privilege report therefore rebuilds PIM activation history from the audit log (shown as a warning
on that tab).

Anyone who can change the Function App's code or settings can act as this identity, so keep
Contributor on the resource group limited (PIM-eligible rather than standing) and the pipeline the
normal route for changes.

## Schedules

UTC (Flex Consumption doesn't support time zones). Change them with `report_schedules` in the
tfvars; they're app settings referenced by each timer.

| Report | Default |
|---|---|
| Least privilege | Daily 02:00 |
| Azure changes | Daily 02:30 |
| Applications | Mondays 04:00 |
| Conditional Access | Mondays 04:30 |
| Authentication methods | Daily 03:00 |

## Adding a report (= a new tab)

1. Write the script so it accepts `-OutputPath` and writes one CSV. If it uses Graph, rely on an
   existing `Connect-MgGraph` session (as the existing scripts do). If it uses ARM, follow
   `Get-AzureResourceChangeReport.ps1`'s `-ManagedIdentityClientId` pattern rather than loading Az.
2. Write the dashboard as a single HTML file that can `load(csvText, label)`, and include the
   `?src=` loader block from the end of any existing dashboard.
3. Add an entry to `app/reports.json` (`id`, `title`, `description`, `script`, `dashboard`, `auth`,
   `parameters`).
4. Add a timer function folder (copy `app/ReportAppSignIns`, change the id and the schedule
   setting name), and add the schedule to `report_schedules` in `infra/variables.tf` and the
   `SCHEDULE_...` app setting in `infra/function.tf`.
5. Grant any extra read permissions to the managed identity with the setup script, if needed.

The build fails if a registered report is missing its script, dashboard, timer function or `?src=`
support. The portal's tabs come from the registry, so `index.html` doesn't change.

## Operations

* **Run status**: each tab shows the last run time, row count, warnings and errors. A failed run
  keeps the previous successful report visible.
* **History**: pick any stored day from the *Run* list; *Download CSV* downloads the selected run.
* **Logs**: Application Insights (`traces`, `exceptions`) for the Function App.
* **Local testing**: `terraform test` in `infra/`; the report scripts run interactively as before.

## Cost (approximate, list prices)

| Item | Monthly |
|---|---|
| 5 private endpoints (~$7.30 each) | ~$37 |
| Flex Consumption executions (a few runs a day) | usually within the free grant, a few $ at most |
| Storage (2 accounts, ZRS, small) | ~$1-2 |
| Log Analytics / App Insights | depends on log volume; typically a few $ |

Check the [pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your region.

## Known limitations

* Report data is fetched by the browser from the Function App, so readers need network access to
  the private endpoint (corporate network / VPN) and must be able to reach `login.microsoftonline.com`.
* Flex Consumption deployments with both a private endpoint and VNet integration have had reported
  time-out issues ([Azure-Functions#2635](https://github.com/Azure/Azure-Functions/issues/2635)).
  If the deploy step times out, re-run it.
* App Service authentication is configured the standard way (`authsettingsV2`); Microsoft doesn't
  explicitly document it for Flex Consumption, so the API and web functions also reject any request
  without an authenticated Entra principal.
