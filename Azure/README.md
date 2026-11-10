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

## Running on a schedule

These reports can be run automatically and published in a private, Entra-protected portal: see [ReportingPlatform](../ReportingPlatform/README.md).
