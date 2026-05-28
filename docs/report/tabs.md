# Report Tabs Reference

## Summary

Executive overview. Findings bar chart by severity, clickable summary cards that jump to the corresponding tab.

## Attack Paths

BFS-discovered paths from any object to privileged groups. Each path shows:

- Source → edge type → target chain
- Depth (number of hops)
- Target group (Domain Admins, Enterprise Admins, Backup Operators, etc.)
- Exploit / Fix accordion with bloodyAD / impacket commands

## Graph

Interactive D3.js force-directed graph of the attack path network.

- Node size = number of attack paths through that node
- Red arrows = paths leading to admin groups
- Hover tooltip = object name and path count
- Zoom/pan + Reset Zoom button
- Capped at 80 nodes in large environments; privileged nodes (groups, adminCount=1) are always kept

## Trusts

Domain and forest trusts enumerated from `trustedDomain` objects:

- Trust direction (Inbound / Outbound / Bidirectional)
- Trust type (AD Uplevel / NT4 / MIT Kerberos)
- SID filtering status (enabled = safe; disabled = SID history abuse possible)
- Foreign Security Principals in privileged groups

## Domain filter

All finding tables (Shadow Creds, ADCS, ACL, etc.) include a **Domain** filter dropdown when more than one domain is present. Selecting a domain shows only findings from that source domain.

## Users

Full user table with columns: SAMAccountName, Enabled, Last Logon, Password Last Set, Admin Count, Email, Privileged Groups, Primary Group. Tables with more than 100 rows show the first 100 with a **Show all N rows** button.

The **Group filter** dropdown covers both the `Member Of` column and the `Primary Group` column — filtering by `Domain Users` works correctly.

## Groups

Group list with member count and description.

## Computers

Computer table with: OS version, LAPS status, last logon, domain, description.

## Kerberos

- Kerberoastable accounts (enabled accounts with SPNs)
- AS-REP roastable accounts (no preauth required)
- Each with `GetUserSPNs.py` / `Rubeus` / `hashcat` commands in Exploit accordion

## ACL

Dangerous ACL findings grouped by right type (GenericAll, WriteDACL, DCSync, etc.) by default:

- Source principal → right → target object
- MITRE ATT&CK badges shown once per group header (not repeated per finding row)
- **`?` tooltip** on each group header — hover to see what the right allows and why it's dangerous
- Severity: Critical if target is DA/EA or right is GenericAll/WriteDACL/WriteOwner; High for ForceChangePassword/AddMember/GenericWrite
- Exploit commands (bloodyAD, secretsdump) in accordion
- **Expand All / Collapse All** buttons in the section header
- Filter bar to narrow by principal, target, or right type
- Scoped to high-value targets: `adminCount=1` users and 15 privileged groups

## Delegation

- Unconstrained delegation (excluding DCs — expected there)
- Constrained delegation with allowed SPNs
- RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
- Protocol Transition flag

## Exposure

Collapsible sections — each shows a count badge and severity badge in the header. Use **Expand All / Collapse All** to control all at once.

- **krbtgt** — password age; Critical if > 180 days (Golden Ticket risk)
- **Descriptions** — AD objects with non-empty descriptions (may leak credentials or IPs)
- **Stale Users** — no logon > 90 days
- **Stale Computers** — no logon > 45 days
- **No LAPS** — computers without LAPS (shared local admin password risk)
- **PSO** — Fine-Grained Password Policies with weak settings
- **Protected Users** — DA/EA accounts not in the Protected Users group
- **AdminSDHolder** — orphaned adminCount=1 objects or backdoor ACEs on AdminSDHolder

## GPO

- Default Domain Policy password settings audit
- GPO write ACL — which non-admin principals can modify GPOs
- GPP/MS14-025 — GPOs with cpassword CSE GUIDs linked to OUs/domain

## ADCS

- Certification Authorities table
- ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
- ESC7 — low-priv ManageCA or ManageCertificates
- ESC8 — Web Enrollment endpoint (manual verify)
- ESC11 — ICPR/DCOM relay endpoint (manual verify)
- Certificate template findings: ESC1, ESC2, ESC3, ESC4, ESC9, ESC13 with certipy/bloodyAD commands
- **EnrollableBy** badge on ESC1/ESC13 — Critical only if low-priv can enroll

## Shadow Creds

- Source domain shown as a styled badge (same style as Attack Paths) when findings come from a trusted domain
- Principals with write access to `msDS-KeyCredentialLink` on Domain Admins, Enterprise Admins, Schema Admins, and DC objects
- Severity: Critical (DC target), High (DA/EA), Medium (other)
- pywhisker / certipy shadow commands

## LDAP Security

- Transport (plain LDAP port 389 vs LDAPS port 636)
- Signing enforcement status
- SASL mechanisms advertised
- Supported capabilities OIDs
- Findings: signing not enforced, channel binding not advertised, SASL over plain LDAP, anonymous read
- **SMB Signing** section — SecurityMode from SMB2 Negotiate; High if signing not required (NTLM relay possible)

## Audit

- AD Recycle Bin status (enabled / disabled / not supported)
- Legacy audit policy — per-category Success/Failure flags
- Machine Account Quota (ms-DS-MachineAccountQuota)
- Findings with remediation PowerShell commands

## SYSVOL

Requires `--sysvol` flag — not run by default (slow over SOCKS5 tunnels or low-bandwidth links).

Walks `\\<DC>\SYSVOL\<domain>\` without reading file content and flags:

- **GPP Preferences XML** (`groups.xml`, `services.xml`, `scheduledtasks.xml`, etc.) — may contain `cPassword` (MS14-025); AES-256 key is public
- **Executables** (`.exe`, `.dll`, `.msi`, `.scr`, `.cpl`) — unexpected in SYSVOL; investigate for persistence or unauthorized deployment
- **Archives** (`.zip`, `.7z`, `.tar`, `.gz`, `.rar`) — may contain tools, scripts, or credentials
- **Scripts outside `Scripts\`** (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`) — may contain hardcoded credentials or unauthorized automation

If the scan was not run, the tab shows an opt-in hint with the `--sysvol` flag.

---

## History

The History tab turns individual point-in-time reports into a **remediation timeline**. Load one or more older morok reports as baselines and the tab compares them against the current report — entirely in your browser, with no data sent anywhere.

!!! note "Version requirement"
    Both the current report and every baseline must be generated by **morok v1.1.0 or later**. Each such report embeds a compact JSON snapshot (`<script id="morok-data">`). Reports from older versions do not have this block and will be rejected.

### How to use

1. Open the current report in your browser and switch to the **History** tab.
2. Click **Load baseline reports…** and select one or more older `.html` morok reports.
3. The tab populates automatically — no page reload, no server.

You can load multiple baselines at once (hold Ctrl/Cmd in the file picker). Duplicate timestamps are detected and skipped with a notification.

If baselines come from a different AD domain than the current report, a **domain mismatch warning** appears at the top. This is informational only — the comparison still runs, which is useful when comparing two forest roots side-by-side.

### Hybrid comparison model

The tab uses two different reference points depending on the section:

| Section | Reference |
|---|---|
| Executive Verdict, Summary cards, Findings | **Oldest** loaded baseline vs current |
| Timeline table, Trend chart | **All** loaded reports |

This gives you both the full journey (timeline) and the clearest "where we started → where we are now" story (cards + findings).

### Executive Verdict

The first block auto-generates a one-sentence narrative suitable for a slide deck or status report:

> *Security posture improved from grade D (100) to C (53) over 84 days. 3 categories improved or resolved, 0 regressed, 1 unchanged. Largest remaining exposure: Dangerous ACLs (2 findings).*

The left accent stripe is **green** when the risk score improved, **red** when it regressed, **grey** when unchanged.

### Summary cards

Four metric cards compare the **oldest baseline** against the current report:

| Card | Metric |
|---|---|
| **Risk Score** | Composite score (0–100, lower is better) |
| **Attack Surface** | Weighted sum: critical × 3 + high × 2 + medium × 1 |
| **Attack Paths** | Number of paths to privileged groups |
| **Critical Findings** | Count of Critical-severity findings |

Each card shows the current value prominently, with the percentage delta and "was N" on the right. Cards with a non-zero current value and an improvement also show "N remaining" as a reminder that the work is not done.

### Risk score trend chart

An inline SVG line chart drawn above the timeline table. Each loaded report (baselines + current) becomes a point on the line. The line color reflects overall direction:

- **Green** — score is lower (better) than the oldest baseline
- **Red** — score is higher (worse) than the oldest baseline
- **Grey** — no change

Score labels appear above each point (or below if the point is near the top of the chart). Date labels on the x-axis identify each snapshot.

### Timeline table

One row per loaded report, sorted oldest → newest. The current report is tagged **CURRENT**. Columns: date, domain, grade, score, critical count, high count, medium count.

If a baseline's domain differs from the current report, its domain cell gets a `≠ domain` badge.

### Findings Before → After

Categories are grouped into three sections based on the delta between the oldest baseline and the current report:

**Regressions** — new or worsened findings. Shown first so bad news is never buried.

**Resolved & Improved** — findings eliminated or reduced since the baseline.

**Outstanding** — unchanged since the baseline.

Each category row shows two stacked bars representing the baseline date and the current date, labeled with the actual dates (`now · YYYY-MM-DD`). Bar color encodes magnitude:

- The **larger** bar is red — the worse state
- The **smaller** bar is green — the better state
- Equal values render both bars in neutral grey

A green **✓ Fixed** badge appears in the right column when a category dropped to exactly zero.

Categories link to their corresponding tab — click to navigate directly.

A **NEW** badge marks categories that had zero findings in the baseline but have findings now.

### Error handling

- Loading a file that is not a morok report shows an error message that auto-dismisses after 6 seconds. Close it early with the **×** button.
- Loading the same report twice (same timestamp) is silently ignored with a notification.
- Wrong file type shows a clear error; the rest of the loaded reports are still processed.
