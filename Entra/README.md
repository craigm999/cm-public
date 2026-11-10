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

Also reported per app:

- **Credential expiry**: client secrets and certificates on the app registration and the enterprise
  app (e.g. SAML signing certificates): count, next expiry, expired ones, and a status (*All expired*,
  *Expiring soon* within `-CredentialWarningDays`, default 30, *OK*, *No credentials*).
- **Recent users** (optional, add `-IncludeRecentUsers`): the last `-RecentUserCount` (default 5)
  distinct people who signed in to the app successfully in the last `-RecentSignInDays` (default 30;
  sign-in logs are kept for 30 days on P1/P2), with the time, interactive / non-interactive and
  MFA / single-factor. It's off by default because sign-in log queries are slow. To keep it as
  quick as possible, only apps with recent user sign-ins are queried, 20 at a time through Graph
  `$batch`, and each search starts with the day before the app's last user sign-in, widening to
  7 days and then the whole period only if it hasn't found enough users. The script prints how
  long this step took. To include it in the scheduled portal report, add
  `"parameters": { "IncludeRecentUsers": true }` to the `app-signins` entry in `reports.json`.

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
- **Credential expiry** – expired, expiring within 30 days, within 90 days, OK, or no credentials;
  each app's next expiry is shown in the table
- **Recent users** column – the last people who signed in, with how they signed in (shown when the
  report was run with `-IncludeRecentUsers`)

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

---

# Least privilege review (admin actions vs. roles held)

## 1. Generate the CSV

```powershell
.\Get-EntraLeastPrivilegeReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\least-privilege.csv
```

Options: `-Days` (default 30), `-UserPrincipalName` to limit to specific admins, `-MapPath` for a
custom activity map, `-IncludeActivationHistoryPermission` (see below).

It also lists **disabled accounts that still hold Entra roles**: active, time-bound and PIM-eligible
assignments, direct or through a role-assignable group, held by an account that's disabled, with the
account's last successful sign-in (needs Entra ID P1/P2; left blank otherwise). These are
`DisabledRoleHolder` rows in the CSV.

Permissions:

| What | Graph permission | Signed-in user's Entra role (delegated) |
|---|---|---|
| Audit log, users, groups, role definitions | `AuditLog.Read.All`, `Directory.Read.All` | Global Reader (or Reports Reader + Directory Readers) |
| Active and eligible role assignments (PIM) | `RoleManagement.Read.Directory` | Global Reader, Security Reader, Security Operator, Security Administrator or Privileged Role Administrator |
| PIM activation history | `RoleAssignmentSchedule.ReadWrite.Directory` or `RoleManagement.ReadWrite.Directory` | as above |

Microsoft Graph has **no read-only permission for PIM activation history**
(`roleAssignmentScheduleRequests`), which is the usual cause of a 403. The script only reads; run it
with `-IncludeActivationHistoryPermission` to request the permission (an admin may need to consent).
Without it, past activations are rebuilt from the audit log instead ("Add member to role completed
(PIM activation)" events), which is close but less exact. **Global Reader** is the simplest role to
run the report with. PIM needs Entra ID P2 or ID Governance; audit logs are kept for 30 days.

If you're already connected to Graph (e.g. from another report), the script checks the session's
scopes and reconnects if any are missing.

How it works:

1. Rebuilds when each admin held each directory role: standing and time-bound assignments, PIM
   activations (from PIM request history, cut short by self-deactivation), assignments removed
   during the period, and roles granted through role-assignable groups.
2. Reads each admin's actions from the Entra audit log.
3. Maps each activity to the permission it needs using **`LeastPrivilegeActivityMap.csv`**, then
   uses the tenant's own role definitions to find which active role granted it and which role
   would have been the least-privileged choice (Microsoft's recommended role where listed).
4. Rates each action (*Least privilege*, *Over-privileged*, *No role needed*, *Not covered by an
   active role*, *Unmapped activity*) and each role assignment or PIM activation (*Appropriate*,
   *Over-privileged*, *Not needed*, *Not used*).

Self-service actions, changes to objects the admin owns, and user (not admin) consent are treated as
needing no role. Activities that aren't in the map show as *Unmapped*; add a row (Activity
supports `*` wildcards, first match wins) and re-run.

## 2. View it

Open `LeastPrivilegeDashboard.html` and drop the CSV onto it (or **Sample data** for a demo).

- Headline: share of admin actions done with more privilege than needed, Global Admin used
  unnecessarily, over-privileged PIM activations, unused privileged standing roles.
- **Role used vs. role needed** heatmap, e.g. Global Administrator used where Groups
  Administrator was enough.
- **Admins** table with a suggested minimal set of roles per admin, worked out from what they
  actually did; roles that weren't needed are struck through.
- **Role assignments and PIM activations**, each with a verdict.
- **Disabled accounts still holding Entra roles**, privileged roles highlighted and listed first.
  Remove these: re-enabling the account would restore the access.
- **Actions** list and an **Unmapped activities** list with template rows for the map.

Audit logs don't record which role was used for an action, so the report assumes the
least-privileged active role that grants the permission was used.

---

# Authentication methods (user registration details)

## 1. Generate the CSV

```powershell
.\Get-EntraAuthMethodsReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\auth-methods.csv
```

Needs `AuditLog.Read.All` and `Directory.Read.All` (as a user: Reports Reader, Security Reader or
Global Reader), and Entra ID P1/P2. One row per user with: account enabled/disabled, member/guest,
admin flag, department, last successful sign-in, every registered method, the strongest method tier,
MFA / passwordless / SSPR registration, and the default MFA method.

Microsoft's registration report doesn't cover **disabled accounts**: they're listed with no method
data unless you add `-IncludeDisabledUserMethods`, which reads their methods from each user's
authentication methods (needs `UserAuthenticationMethod.Read.All`).

Strength tiers: **Phishing-resistant** (FIDO2, passkeys, Windows Hello for Business, macOS platform
credential, certificate-based auth) → **Passwordless** (Authenticator phone sign-in) → **App-based
MFA** (Authenticator push, OTP codes) → **Phone (SMS / voice)** → **No MFA method**.

## 2. View it

Open `AuthMethodsDashboard.html` and drop the CSV onto it (or **Sample data** for a demo).

- Show enabled, disabled or all accounts (enabled only by default); members, guests or both; admins only.
- **Method filter**: click a method once to show only users who have it, twice to hide users who
  have it (e.g. show users *with* SMS but *without* Authenticator), three times to clear.
- Headline figures: MFA and phishing-resistant coverage, phone-only users, users with no MFA method,
  admins without a phishing-resistant method.
- Charts: strongest method per user, default MFA method, users per method; click to drill in.
- User table with every method, sortable, with **Export these rows** for the filtered list.

---

## Running on a schedule

These reports can be run automatically and published in a private, Entra-protected portal: see [ReportingPlatform](../ReportingPlatform/README.md).
