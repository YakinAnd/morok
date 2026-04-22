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

## Trusts

Domain and forest trusts enumerated from `trustedDomain` objects:

- Trust direction (Inbound / Outbound / Bidirectional)
- Trust type (AD Uplevel / NT4 / MIT Kerberos)
- SID filtering status (enabled = safe; disabled = SID history abuse possible)
- Foreign Security Principals in privileged groups

## Users

Full user table with columns: SAMAccountName, Enabled, Last Logon, Password Last Set, Admin Count, Email, Privileged Groups.

## Groups

Group list with member count and description.

## Computers

Computer table with: OS version, LAPS status, last logon, domain, description.

## Kerberos

- Kerberoastable accounts (enabled accounts with SPNs)
- AS-REP roastable accounts (no preauth required)
- Each with `GetUserSPNs.py` / `Rubeus` / `hashcat` commands in Exploit accordion

## ACL

- Dangerous ACL findings grouped by type (GenericAll, WriteDACL, DCSync, etc.)
- Source principal → right → target object
- Severity: Critical if target is DA/EA/DC; High otherwise
- Exploit commands (bloodyAD, secretsdump) in accordion
- **Group button** (⊞) collapses similar findings into a single line

## Delegation

- Unconstrained delegation (excluding DCs — expected there)
- Constrained delegation with allowed SPNs
- RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
- Protocol Transition flag

## Exposure

- **LAPS coverage** — computers without LAPS listed individually
- **Stale users** (no logon > 90 days)
- **Stale computers** (no logon > 45 days)
- **krbtgt password age** — Golden Ticket risk if > 180 days
- **Passwords in descriptions** — any AD object with a non-empty description
- **PSO** — Fine-Grained Password Policies with weak settings

## GPO

- Default Domain Policy password settings audit
- GPO write ACL — which non-admin principals can modify GPOs
- GPP/MS14-025 — GPOs with cpassword CSE GUIDs linked to OUs/domain
- Protected Users coverage

## ADCS

- Certification Authorities table
- ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
- ESC7 — low-priv ManageCA or ManageCertificates
- Certificate template findings (ESC1–ESC5, ESC8) with certipy commands
- **EnrollableBy** badge on ESC1 — shows which principals can actually enroll (Critical only if low-priv can enroll)

## Shadow Creds

- Principals with write access to `msDS-KeyCredentialLink` on Domain Admins, Enterprise Admins, Schema Admins, and DC objects
- Severity: Critical (DC target), High (DA/EA), Medium (other)
- pywhisker / certipy shadow commands

## LDAP Security

- Transport (plain LDAP port 389 vs LDAPS port 636)
- Signing enforcement status
- SASL mechanisms advertised
- Supported capabilities OIDs
- Findings: signing not enforced, channel binding not advertised, SASL over plain LDAP, anonymous read

## Audit

- AD Recycle Bin status (enabled / disabled / not supported)
- Legacy audit policy — per-category Success/Failure flags
- Machine Account Quota (ms-DS-MachineAccountQuota)
- Findings with remediation PowerShell commands
