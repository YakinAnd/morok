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
- Severity: Critical if target is DA/EA or right is GenericAll/WriteDACL/WriteOwner; High for ForceChangePassword/AddMember/GenericWrite
- Exploit commands (bloodyAD, secretsdump) in accordion
- **Expand All / Collapse All** buttons in the section header
- Filter bar to narrow by principal, target, or right type

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
