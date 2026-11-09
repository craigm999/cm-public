# Azure resource change report

Shows every Azure resource created, updated or deleted across all subscriptions in a tenant,
and who did it (person, service principal or managed identity).

## 1. Generate the CSV

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Connect-AzAccount -TenantId contoso.onmicrosoft.com
.\Get-AzureResourceChangeReport.ps1 -Days 30 -OutputPath .\azure-changes.csv
```

You need **Reader** on the subscriptions (Reader on a management group, e.g. the tenant root group,
covers them all).

| Option | |
|---|---|
| `-Days` | Activity Log period, 1-90 (default 30). The Activity Log is kept for 90 days. |
| `-SubscriptionId` | Only these subscriptions (default: all enabled subscriptions in the tenant). |
| `-IncludeActions` | Also include POST actions such as VM start/stop or `listKeys`. |
| `-IncludeFailed` | Also include failed operations. |
| `-CreatorTagName` | Tag holding a resource's creator, used for resources older than the period (default `CreatedBy`). |
| `-SkipResourceGraphChanges` | Skip the Resource Graph property-level change details. |

Where the data comes from:

- **Activity Log** (per subscription): each successful write/delete with the caller. Service
  principal and managed identity IDs are resolved to names. A person's tool (Portal, CLI,
  PowerShell) and IP are recorded, and changes inside an ARM/Bicep deployment are linked to the
  deployment name.
- **Resource inventory** with created/changed times: tells creates from updates and lists who
  created and last changed each resource that exists today.
- **Azure Resource Graph `resourcechanges`** (last 14 days): which properties changed.

The CSV has `Change`, `Resource` and `Subscription` rows. Subscriptions that couldn't be read
(e.g. no access) are listed with the error and the script carries on.

## 2. View it

Open `AzureChangeDashboard.html` and drop the CSV onto it (or **Sample data** for a demo).
Filter by subscription, period, people vs. apps, change type, or search. Click any chart, a person,
a resource or a deployment to see the matching changes; click a resource name for its full history.

---

## Running on a schedule

These reports can be run automatically and published in a private, Entra-protected portal: see [ReportingPlatform](../ReportingPlatform/README.md).
