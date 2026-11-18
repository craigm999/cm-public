# Azure resource change report

Shows every Azure resource created, updated or deleted across all subscriptions in a tenant,
and who did it (person, service principal or managed identity). It also reviews Azure RBAC:
each subscription's direct owners (and orphaned subscriptions), and role assignments that are
more privileged than the changes their holder actually made.

## 1. Generate the CSV

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Connect-AzAccount -TenantId contoso.onmicrosoft.com
.\Get-AzureResourceChangeReport.ps1 -Days 30 -OutputPath .\azure-changes.csv
```

You need **Reader** on the subscriptions (Reader on a management group, e.g. the tenant root group,
covers them all). The RBAC review reads users, groups and service principals from Microsoft Graph
(any member user can; an unattended identity needs `Directory.Read.All`).

| Option | |
|---|---|
| `-Days` | Activity Log period, 1-90 (default 30). The Activity Log is kept for 90 days. |
| `-SubscriptionId` | Only these subscriptions (default: all enabled subscriptions in the tenant). |
| `-IncludeActions` | Also include POST actions such as VM start/stop or `listKeys`. |
| `-IncludeFailed` | Also include failed operations. |
| `-CreatorTagName` | Tag holding a resource's creator, used for resources older than the period (default `CreatedBy`). |
| `-SkipResourceGraphChanges` | Skip the Resource Graph property-level change details. |
| `-SkipRoleAssignments` | Skip the subscription owner and role assignment review. |
| `-BroadScopeResourceGroupLimit` | A subscription-wide Owner / Contributor whose changes touched this many resource groups or fewer is flagged to be scoped down (default 3). |

Where the data comes from:

- **Activity Log** (per subscription): each successful write/delete with the caller. Service
  principal and managed identity IDs are resolved to names. A person's tool (Portal, CLI,
  PowerShell) and IP are recorded, and changes inside an ARM/Bicep deployment are linked to the
  deployment name.
- **Resource inventory** with created/changed times: tells creates from updates and lists who
  created and last changed each resource that exists today.
- **Azure Resource Graph `resourcechanges`** (last 14 days): which properties changed.
- **Role assignments and role definitions** (per subscription, including those inherited from
  management groups and the tenant root), with each principal's account status from Microsoft Graph.

### Subscription owners

Owner assignments made directly on each subscription (not inherited) are listed with each owner's
status. `OwnershipStatus` is:

| Status | Meaning |
|---|---|
| **Orphaned** | Has direct owners, but none is an enabled person: every owner is disabled, deleted, or a service principal, or a group with no enabled members. |
| **No direct owner** | Only owned through a management group / root assignment. |
| **Has disabled owner(s)** | At least one valid owner, plus disabled or deleted ones to clean up. |
| **OK** | All direct owners are enabled. |

### Over-privileged role assignments

Privileged roles (Owner, Contributor, User Access Administrator, Role Based Access Control
Administrator, and custom roles with `*` or role-assignment write) are checked against what the
principal changed in scope during the Activity Log period (for a group, what its members changed):

| Finding | Severity |
|---|---|
| Held by a disabled or deleted account | High (Medium for non-privileged roles) |
| Guest user with a privileged role | High |
| Custom role granting all actions (`*`) | High at subscription scope or wider, else Medium |
| Owner / UAA / RBAC Admin assigned directly to a user at subscription scope or wider | Medium |
| No changes made in scope during the period | Medium |
| Owner-type role but no access-control (`Microsoft.Authorization`) changes: Contributor would do | Medium |
| Privileged role at management group / root scope | Low |
| Subscription-wide Owner / Contributor whose changes touched only a few resource groups | Low |

Each assignment gets a suggestion (remove, make PIM-eligible, use Contributor, scope to the resource
groups used). Use is judged from Activity Log writes and deletes only: reads and data-plane access
(reading blobs, secrets, etc.) aren't there, so check before removing an "unused" assignment. Use
isn't judged for subscriptions whose Activity Log couldn't be read. Only active assignments are
listed; PIM-eligible assignments aren't.

The CSV has `Change`, `Resource`, `Subscription` and `RoleAssignment` rows. Subscriptions that
couldn't be read (e.g. no access) are listed with the error and the script carries on.

## 2. View it

Open `AzureChangeDashboard.html` and drop the CSV onto it (or **Sample data** for a demo).
Filter by subscription, period, people vs. apps, change type, or search. Click any chart, a person,
a resource or a deployment to see the matching changes; click a resource name for its full history.

The **Subscription owners** table shows each subscription's ownership status, its direct owners and
the owners it inherits. **Over-privileged role assignments** charts the findings and severities
(click a bar to list those assignments), with filters for severity and principal type, and
**Export these rows**.

---

# Public exposure report

Finds what in Azure can be reached from the internet, rates the risk of each finding (Critical,
High, Medium, Low, Info) and says what to do about it.

## 1. Generate the CSV

```powershell
Connect-AzAccount -TenantId contoso.onmicrosoft.com
.\Get-AzurePublicExposureReport.ps1 -OutputPath .\exposure.csv                                   # every subscription you can see
.\Get-AzurePublicExposureReport.ps1 -ManagementGroupId mg-landingzones -OutputPath .\exposure.csv # one management group
.\Get-AzurePublicExposureReport.ps1 -SubscriptionId <id>, <id> -OutputPath .\exposure.csv         # chosen subscriptions
```

You need **Reader** on the scope. It reads everything with Azure Resource Graph (one query across
all the subscriptions), plus a few per-resource calls for detail Resource Graph doesn't hold:
database firewall rules, blob container access levels, App Service access restrictions, Firewall
Policy DNAT rules and Front Door security policies (`-SkipDetailChecks` skips them all,
`-SkipAppServiceConfig` just the App Service ones). Nothing is changed.

| Area | What it checks |
|---|---|
| Public IPs | every public IP and what it's attached to; unused ones |
| VMs | for a NIC with a public IP, which ports any internet address can reach, working through the NIC and subnet NSGs in priority order (with the default rules; a Basic public IP without an NSG is open, a Standard one closed) |
| NSG rules | rules letting the internet reach management (SSH, RDP, WinRM), database, file-sharing / RPC or container ports, or every port |
| Load balancers | ports published by public frontends (load-balancing and inbound NAT rules) |
| Application gateways | WAF missing or in detection mode, HTTP listeners not redirecting to HTTPS, old TLS policies |
| Azure Firewall | DNAT rules (classic and Firewall Policy) publishing internal ports |
| Front Door / CDN | endpoints without a WAF policy |
| Databases | SQL, PostgreSQL / MySQL flexible server firewall rules (whole internet, broad ranges, all Azure services), Cosmos DB, Redis |
| Storage, Key Vault, registries, AI services | public network access and firewall default action; anonymous blob containers; anonymous image pull; admin user |
| App Service / Functions | public access and access restrictions, HTTPS only, FTP, remote debugging, TLS |
| AKS | public API server without authorized IP ranges |
| Other PaaS | anything else with public network access enabled |
| Routing | default route (0.0.0.0/0) sent straight to the internet; subnets relying on default outbound access |

Severity in short: **Critical** – reachable now from any address on a sensitive port, or data
readable without signing in; **High** – a likely way in (no WAF, public Kubernetes API, database
open to all networks); **Medium** – public but should be restricted, or a weak setting; **Low** –
restricted exposure or hygiene; **Info** – public by design and set up as expected.

VM reachability reflects what the NSGs allow. It doesn't evaluate application security groups as
sources, service tags other than Internet, or a firewall / NVA in front.

## 2. View it

Open `PublicExposureDashboard.html` and drop the CSV onto it (or **Sample data** for a demo).
Tiles for internet-reachable resources, each severity, open management ports and unused public
IPs; findings by category and sensitive ports open to the internet (click any bar or tile to list
the findings); and the findings table with the exposure, evidence (rule names) and recommended
action, filterable by subscription, severity, category and search, with **Export these rows**.

---

## Running on a schedule

These reports can be run automatically and published in a private, Entra-protected portal: see [ReportingPlatform](../ReportingPlatform/README.md).
