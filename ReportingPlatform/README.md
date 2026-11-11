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
    RunOnDemand/               runs a report queued by the portal's "Run now" button
    Api/  Web/                 HTTP functions (data API, portal)
    www/index.html             portal shell (tabs built from the registry)
  build/Build-FunctionPackage.ps1   assembles the zip: app + report scripts + dashboards + modules
  deploy/
    Deploy-ReportingPlatform.ps1    interactive deployment (asks, checks, deploys)
    Grant-ReportingAccess.ps1       the privileged steps, for an admin to run separately
    main.bicep                      the Azure resources
    ReportingDeploy.psm1            shared functions
```

The report scripts and dashboards stay in `Entra/` and `Azure/`. They're copied into the package at
build time, so they can still be run locally and the dashboards opened offline with a CSV.

## Deploying

**One PowerShell script, using the Azure CLI and Bicep.** It asks about your environment, checks
you have the rights for each step, shows what will change, then deploys everything: the
infrastructure, the sign-in app, the managed identity's permissions and the code.

Why this approach:

* **Nothing to set up first.** Bicep has no state file to host (a Terraform state backend would be one
  more private storage account), and no pipeline is needed.
* **One sign-in.** The Azure CLI covers Azure Resource Manager, Bicep (it installs Bicep itself) and
  Microsoft Graph, so there are no PowerShell module version clashes between Az and Microsoft Graph.
* **Safe to re-run.** Every step is idempotent, and the Bicep *what-if* shows the changes before
  they're made. Your answers are saved, so updates run without questions (`-NonInteractive`), from
  your machine or, later, from a pipeline.
* **Split duties.** If you don't hold a role a step needs, the step is handed to someone who does,
  with a ready-made command (`Grant-ReportingAccess.ps1`), and the rest of the deployment carries on.

### What you need

* **PowerShell 7.4+** and the **Azure CLI 2.60+** (`az upgrade` to update).
* Access to the **PowerShell Gallery** from the machine, to bundle `Microsoft.Graph.Authentication`
  into the package. Without it, build the package elsewhere (`build/Build-FunctionPackage.ps1`) and
  pass it with `-PackagePath`.
* For the code upload, **network access to the private endpoint** (VPN, ExpressRoute or a jump
  box). If you don't have that, the script can open the deployment endpoint to your public IP address
  only, for the few minutes the upload takes. The portal itself stays private throughout. Or you
  can skip the code and run `-CodeOnly` later from a machine on the network.
* In the target **VNet**: a subnet for the private endpoints with 5 free addresses (your shared one is
  fine), and either a subnet delegated to `Microsoft.App/environments` (/27+, nothing else in it) or
  a free /27 for the script to create one.

### Run it

```powershell
cd ReportingPlatform/deploy
./Deploy-ReportingPlatform.ps1 -WhatIf      # questions, checks and what-if only: changes nothing
./Deploy-ReportingPlatform.ps1              # the real thing
```

It asks the questions below, finding what already exists so most answers are picked from a list.
Answers are saved to `deploy/settings.json`. The file holds no secrets but does hold your tenant,
subscription and resource IDs, so it's git-ignored; keep a copy somewhere private.

| Question | What it finds for you |
|---|---|
| Tenant (and sign-in) | your current Azure CLI sign-in; runs `az login --tenant` if needed |
| Subscription | enabled subscriptions in the tenant |
| Name prefix and environment (e.g. `idrpt`, `prd`) | shows the resulting names; checks the global ones (Function App, storage) are free |
| Virtual network | VNets in the subscription, or a resource ID in another subscription (hub-and-spoke). Resources go in the VNet's region, which must support Flex Consumption |
| Private endpoint subnet | subnets with no delegation, with free addresses |
| Outbound (integration) subnet | an already-delegated subnet, an empty one to delegate, or a new one: it suggests the first free /27 and offers to attach the same NSG / route table as the private endpoint subnet |
| Private endpoint DNS | private DNS zones (searched across all your subscriptions, showing which are linked to the VNet), Azure Policy, or manual (you get the records to create at the end) |
| Outbound firewall? | if yes, you get the addresses to allow |
| Resource group | existing groups, or a new one |
| Sign-in app registration | create one, or use an existing one by client ID |
| Reader group | finds the group by name or ID; offers to create it |
| Graph permissions now or by an admin | defaults to now if you have Privileged Role Administrator active |
| Azure report scope | tenant root management group, a management group, chosen subscriptions, or none |
| Log Analytics | new workspace, or one of your existing workspaces |
| Schedules and tags | defaults, or your own |
| Can this machine reach the private network? | decides how the code is uploaded (see above) |

Then it runs the **pre-flight checks** and lists each one as OK, Missing, Warning or Deferred, with
the fix:

* Your effective Azure permissions at every scope it will touch (resource group, subnets, VNet,
  NSG / route table, DNS zones, workspace, Reader scopes), read from the Azure permissions API.
* Your active Entra roles for the app registration, group and Graph permission steps.
* Resource providers (and whether you can register them), Flex Consumption support in the region,
  name availability, free addresses in the private endpoint subnet, and the Azure CLI version.

**Missing** stops the run before anything changes (or use `-Force`). **Deferred** steps are skipped
and handed over at the end. Then you get a plan, the Bicep what-if, and a final confirmation.

### Permissions needed

The simplest set for one person to do everything: **Owner** on the resource group, **Network
Contributor** on the VNet, **Private DNS Zone Contributor** on the privatelink zones,
**User Access Administrator** at the Azure report scope, and **Cloud Application Administrator** plus
**Privileged Role Administrator** in Entra ID. In detail, with least-privilege alternatives:

**Azure (RBAC)**

| Step | Needs | Least-privilege built-in role | Scope |
|---|---|---|---|
| Create the resource group (only if new) | `Microsoft.Resources/subscriptions/resourceGroups/write` | Contributor | subscription |
| Deploy the template: Function App, plan, storage, identity, private endpoints, App Insights, Log Analytics | `Microsoft.Resources/deployments/write` + write on those types | Contributor | resource group |
| Give the identity its storage and monitoring roles (part of the template) | `Microsoft.Authorization/roleAssignments/write` | Role Based Access Control Administrator, optionally limited to Storage Blob Data Owner / Contributor, Storage Queue / Table Data Contributor and Monitoring Metrics Publisher | resource group |
| Private endpoints and VNet integration | `Microsoft.Network/virtualNetworks/subnets/join/action` | Network Contributor | the two subnets (or the VNet) |
| Create or delegate the integration subnet (only if chosen) | `Microsoft.Network/virtualNetworks/subnets/write` | Network Contributor | VNet |
| Attach an NSG / route table to a new subnet (only if chosen) | `.../networkSecurityGroups/join/action`, `.../routeTables/join/action` | Network Contributor | NSG, route table |
| Register private DNS records (only with DNS zones) | `Microsoft.Network/privateDnsZones/join/action` | Private DNS Zone Contributor | each zone |
| Use an existing Log Analytics workspace (only if chosen) | `Microsoft.OperationalInsights/workspaces/read` | Reader | workspace |
| Register resource providers (once, only if not registered: usually `Microsoft.App`) | `<provider>/register/action` | Contributor | subscription |
| Give the identity **Reader** for the Azure changes report | `Microsoft.Authorization/roleAssignments/write` | User Access Administrator or RBAC Administrator | tenant root management group (or the management group / subscriptions you choose). At the tenant root this usually means a Global Administrator using *elevate access* |

**Entra ID** (activate PIM-eligible roles before running: the script only sees active roles)

| Step | Role |
|---|---|
| Create / update the sign-in app registration and enterprise app, require assignment, assign the reader group, consent to `openid profile email User.Read` | Cloud Application Administrator (or Application Administrator) |
| Create the reader group (only if it doesn't exist) | Groups Administrator or User Administrator, unless your tenant lets users create security groups |
| Grant the identity its read-only Graph application permissions | Privileged Role Administrator (or Global Administrator) |

The Azure CLI must also be allowed to sign in (some tenants block it with Conditional Access).

**Later updates** (`-CodeOnly`, or a re-run with nothing new) need only Contributor (or Website
Contributor for code) on the resource group, and the network path to the private endpoint.

### When someone else holds a role

Run the deployment with what you have. Steps you can't do are listed at the end with the exact
command, which reads everything it needs from your settings file:

```powershell
# Privileged Role Administrator: Graph permissions for the identity
./Grant-ReportingAccess.ps1 -Stage Permissions -GraphOnly -SettingsPath ./settings.json

# Owner / User Access Administrator at the Azure report scope: Reader for the identity
./Grant-ReportingAccess.ps1 -Stage Permissions -AzureOnly -SettingsPath ./settings.json

# Cloud Application Administrator, if you can't create the app registration yourself:
# run this first, then run the deployment and choose "use an existing app registration"
./Grant-ReportingAccess.ps1 -Stage SignInApp -SettingsPath ./settings.json -ReaderGroupId <group object ID>
```

### Updating

```powershell
./Deploy-ReportingPlatform.ps1 -NonInteractive          # infrastructure + code, using the saved answers
./Deploy-ReportingPlatform.ps1 -CodeOnly                # just the code (e.g. after changing a report)
./Deploy-ReportingPlatform.ps1                          # change answers: "Review them", Enter keeps each one
```

To run it from a pipeline later, sign the agent in with `az login` (service connection), keep the
settings file as a secure file, and run `-NonInteractive`. A service principal can't hold Entra
roles the way a person does, so keep the sign-in app and Graph permission steps with an admin
(`Grant-ReportingAccess.ps1`).

### If the code upload returns 403

The package is written into the app's private storage account by the app's **managed identity**
(not by you), through the private endpoints. So:

* **Your permissions:** only the publish permission on the Function App (Website Contributor,
  Contributor or Owner). You need no storage roles.
* **Just deployed?** The identity's storage roles can take ~10 minutes to apply. The script retries a
  403 for about 10 minutes before giving up; if it still fails, run `-CodeOnly` again later.
* **DNS first:** the storage (`blob`, `queue`, `table`) and app names must resolve to the private
  endpoint IPs from the VNet, and (for a direct upload) from your machine. With Azure Policy DNS the
  script waits for the records; with manual DNS it shows the records and uploads only once you
  confirm they exist (or when you run `-CodeOnly`).
* **"Ip Forbidden"** with the temporary upload option means Azure saw a different public IP from
  the one allowed (proxy, VPN split tunnelling): enter the right one, or upload from the network.
* **Deployment Center > Logs** on the Function App shows the platform's side of a failed upload.

### Network requirements

* **Readers** reach the portal at `https://<function app>.azurewebsites.net` through the private
  endpoint, so they need the corporate network / VPN and DNS resolution of `privatelink.azurewebsites.net`.
  They also need to reach `login.microsoftonline.com`.
* **Outbound from the Function App** (through the integration subnet): `login.microsoftonline.com`,
  `graph.microsoft.com`, `management.azure.com`, and Application Insights ingestion
  (`<region>.in.applicationinsights.azure.com`, `<region>.livediagnostics.monitor.azure.com`) on
  HTTPS. Storage traffic stays on the private endpoints.

## What the managed identity can do

| Where | Permission | Used by |
|---|---|---|
| Microsoft Graph (application) | `Directory.Read.All`, `AuditLog.Read.All`, `Application.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory` | Entra reports, and account status for the Azure report's RBAC review (all read-only) |
| Tenant root management group (or the management group / subscriptions you choose) | Reader | Azure changes report |
| Reports storage `reports` container | Storage Blob Data Contributor | writing / reading reports |
| Host storage | Blob Data Owner, Queue + Table Data Contributor | Functions runtime |
| Application Insights | Monitoring Metrics Publisher | telemetry |

Optional: `UserAuthenticationMethod.Read.All` (`Grant-ReportingAccess.ps1 -IncludeUserAuthenticationMethodRead`, or `"includeUserAuthenticationMethodRead": true` in the settings file),
only if you set `"IncludeDisabledUserMethods": true` in the `auth-methods` entry of `reports.json` so
the authentication methods report also covers disabled accounts.

It deliberately does **not** have `RoleAssignmentSchedule.ReadWrite.Directory`: for an application
that permission can create role assignments, i.e. escalate to Global Administrator. The least
privilege report therefore rebuilds PIM activation history from the audit log (shown as a warning
on that tab).

Anyone who can change the Function App's code or settings can act as this identity, so keep
Contributor on the resource group limited (PIM-eligible rather than standing), and make the deploy
script the normal route for changes.

## Schedules

UTC (Flex Consumption doesn't support time zones). Change them when the deployment asks (or edit
`schedules` in the settings file and re-run with `-NonInteractive`); they're app settings
referenced by each timer.

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
   setting name), and add the schedule default to `sched` and the `SCHEDULE_...` app setting in
   `deploy/main.bicep`.
5. Grant any extra read permissions to the managed identity (`Grant-ReportingAccess.ps1` holds the
   list), then re-run the deployment with `-NonInteractive`.

The build fails if a registered report is missing its script, dashboard, timer function or `?src=`
support. The portal's tabs come from the registry, so `index.html` doesn't change.

## Operations

* **Run status**: each tab shows the last run time, row count, warnings and errors. A failed run
  keeps the previous successful report visible.
* **Run now**: the button on each tab (`GET /api/reports/<id>/run`, with an `X-Requested-With` header
  so other sites can't trigger it; GET because some proxies refuse POSTs) queues the report to run straight away, in the background
  (queue `report-runs` in the host storage account, picked up by the `RunOnDemand` function), so it
  isn't limited by browser or HTTP time-outs. The tab shows *Queued* / *Running* and reloads the
  dashboard when the run finishes. A report can't be queued while it's already queued or running, and
  a scheduled run that comes round while a run is in progress is skipped. Any member of the reader
  group can use it. The Azure portal's *Code + Test → Test/Run* doesn't work for this app: it calls
  the app's admin endpoint from your browser, which the private endpoint and sign-in block. Other
  Function App blades that call the app directly (e.g. CORS, Functions list details) may show
  *failed to load* for the same reason; use the Azure CLI for those settings.
* **History**: pick any stored day from the *Run* list; *Download CSV* downloads the selected run.
* **Logs**: Application Insights (`traces`, `exceptions`) for the Function App.
* **Preview a change**: `./Deploy-ReportingPlatform.ps1 -NonInteractive -WhatIf` runs the checks and the Bicep what-if.
* **Local testing**: the report scripts run interactively as before.

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
  If the code upload times out, re-run `-CodeOnly`.
* The temporary code-upload option opens only the deployment (SCM) endpoint, only to your IP, and
  closes it straight after, even if the upload fails. Any full re-deployment also resets public
  access to disabled. Where policy forbids even that, use a machine on the network.
* App Service authentication is configured the standard way (`authsettingsV2`); Microsoft doesn't
  explicitly document it for Flex Consumption, so the API and web functions also reject any request
  without an authenticated Entra principal.
