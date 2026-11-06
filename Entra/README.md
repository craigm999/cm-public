# Entra app sign-in & ownership report

## 1. Generate the CSV

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
.\Get-EntraAppSignInReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\apps.csv
```

Needs `Application.Read.All`, `Directory.Read.All` and `AuditLog.Read.All`, a role that can
read sign-in reports (e.g. Reports Reader / Global Reader) and an Entra ID P1/P2 licence for
the sign-in activity data. See the comment-based help (`Get-Help .\Get-EntraAppSignInReport.ps1 -Full`)
for all options.

Apps created by **Copilot Studio** (formerly **Power Virtual Agents**) are detected from the tags
Copilot Studio puts on their service principals (`AgentCreatedBy:CopilotStudio`,
`power-virtual-agents-<agentId>`, `AIAgentBuilder`) or a display name containing
"Power Virtual Agents" / "Copilot Studio". They are marked in the `IsCopilotStudio` column, or
left out entirely with `-ExcludeCopilotStudio`.

## 2. View it

Open `AppSignInDashboard.html` in a browser and drop `apps.csv` onto it (or use **Load CSV…**).
The file is read locally; nothing is uploaded. **Sample data** loads a generated demo dataset.

The dashboard highlights:

- **Never signed in** – no record in the sign-in activity report
- **No owners**
- **Disabled owner(s)** – at least one owner account is disabled (and how many have *every* owner disabled)
- **Unused > 2 years** – threshold adjustable to 1 or 3 years

Tick **Hide Copilot Studio / PVA apps** to filter those agents out of every chart and the table.

Click any tile, bar or ownership segment to list the matching apps, and use
**Export these rows** to save that list as CSV.

---

# Conditional Access policy review

## 1. Generate the CSV

```powershell
.\Get-EntraCAPolicyReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\ca.csv
```

Optionally add `-SummaryPath .\ca-summary.csv` for a one-row-per-policy CSV that's easier to read in Excel.
Needs `Policy.Read.All`, `Directory.Read.All` and `Application.Read.All`, and a role that can read
Conditional Access (e.g. Security Reader or Global Reader).

The main CSV has one row per policy × condition × include/exclude × object (users, groups, roles,
guests, workload identities, apps, user actions, auth contexts, locations, platforms, client apps,
risk levels, device filters, auth flows), with IDs resolved to names. References to objects that
no longer exist are kept with `Resolved = False`.

## 2. View it

Open `CAPolicyDashboard.html` and drop `ca.csv` onto it (or **Sample data** for a demo).

- **Policy overlap matrix** – which pairs of policies can apply to the same sign-in. A pair is
  *likely redundant* when the scopes are identical, or one policy's scope sits entirely inside the
  other's and both apply the same controls. Click a cell for a side-by-side comparison explaining
  why they overlap.
- **Most-excluded objects** and **exclusions per policy** charts.
- **Inclusions and exclusions by object** – every user, group, role, app, location etc. with the
  policies that include and exclude it.
- **Policies** table – click a row for every include/exclude and its overlaps.
- Deleted / unresolvable references are highlighted in red.

Overlap is calculated from what policies target directly. Group and role membership isn't
expanded, and device/app filters aren't evaluated.
