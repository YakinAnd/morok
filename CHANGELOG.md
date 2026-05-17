# Changelog

## [1.1.0] — 2026-05-15

### New: History tab — remediation tracking across reports

The HTML report now includes a **History** tab that turns individual point-in-time reports into a remediation timeline. Load one or more older morok reports as baselines and compare them against the current report — entirely in the browser, no data sent anywhere.

- **Executive Verdict** — auto-generated one-sentence narrative with grade, score, and delta (suitable for slide decks)
- **Summary metric cards** — Risk Score, Attack Surface, Attack Paths, Critical Findings; each shows current value, % delta, and "was N"
- **Risk score trend chart** — inline SVG line chart across all loaded snapshots; color encodes direction (green = improved, red = regressed)
- **Timeline table** — one row per report, sorted oldest → newest; grade, score, critical/high/medium counts
- **Findings Before → After** — categories split into three groups:
  - **Regressions** — new or worsened findings (shown first)
  - **Resolved & Improved** — findings eliminated or reduced since baseline
  - **Outstanding** — unchanged since baseline
  - Dual date-labeled bars, ✓ Fixed badge for zero-count categories, NEW badge for categories absent in baseline
- Works fully offline — no server, no uploads
- Requires morok v1.1.0+ for both the current report and any baseline (older reports are rejected with a clear error)

### Other changes

- Version string updated to `v1.1.0` in CLI and HTML report
- HTML report embeds a compact JSON snapshot (`<script id="morok-data">`) used by the History tab

## [1.0.0] — 2026-05-09

First public release.

### Analysis modules

- **Attack paths** — BFS graph traversal to DA, EA, Backup Operators, Account Operators, Server Operators, Print Operators, DNSAdmins, GPO Creator Owners
- **Kerberos** — Kerberoastable accounts (SPNs), AS-REP roastable (no preauth); gMSA accounts flagged as Info (240-char random password)
- **ACL** — GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync; non-default owners on privileged objects
- **Delegation** — Unconstrained, Constrained, RBCD; Protocol Transition flag
- **ADCS** — ESC1–ESC9, ESC11, ESC13 certificate template vulnerabilities; CA-level ESC6/ESC7/ESC8/ESC11
- **Shadow Credentials** — write access to `msDS-KeyCredentialLink` on DA/EA/DC/adminCount=1 objects
- **GPO** — password policy audit, GPO write ACL, GPP/MS14-025 cpassword detection via CSE GUIDs
- **Trusts** — trust direction/type, SID filtering, transitive FSP membership in privileged groups
- **Exposure** — stale users/computers, krbtgt age, LAPS coverage, passwords in descriptions, PasswordNotRequired, SmartcardRequired+AdminCount, DnsAdmins members, Pre-Windows 2000 Compatible Access
- **Protected Users** — privileged accounts not in the Protected Users group
- **AdminSDHolder** — orphaned adminCount=1 objects, backdoor ACEs on AdminSDHolder
- **LDAP Security** — signing/channel binding enforcement, SASL mechanisms, anonymous read, SMB signing
- **Audit Policy** — legacy audit categories, AD Recycle Bin status, machine account quota
- **gMSA** — principals that can read managed passwords (`msDS-GroupMSAMembership`)

### CLI

- **`enum`** — full enumeration runs all modules; per-domain `══ domain.local ══` sections when following trusts
- **`--quiet`** — single-line CI verdict, no ANSI codes: `RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium`
- **`--verbose`** — show all findings without per-section truncation
- **`--stealth`** — minimal LDAP footprint, skips ACL/GPO/ADCS/delegation
- **`--report`** — generate self-contained HTML report
- **`--json`** — export AD objects as JSON (BloodHound CE v5 compatible)
- **`--proxy`** — SOCKS5 proxy support for pivoting
- **`--scope`** — restrict enumeration to specific OU/DN
- **Risk score footer** — `RISK CRITICAL (F · 83/100)` + timing after every run
- **Severity prefixes** — `[+++]` critical · `[++]` high · `[+]` medium with color coding
- **Auth methods** — password, Pass-the-Hash (NTLM), Pass-the-Ticket (Kerberos ccache)

### HTML Report

- **Executive tab** — risk grade (A–F), numeric score, risk contribution bars by category
- **Summary tab** — findings chart, attack surface metrics, clickable category cards
- **Attack Paths** — BFS path visualization with depth, target group, bloodyAD/impacket commands
- **Graph** — interactive D3.js force-directed graph; zoom/pan, hover tooltips, 80-node cap
- **Multi-domain tabs** — per-domain filter on all finding tables; domain badge on cross-domain findings
- **Users/Groups/Computers** — searchable/sortable tables; group filter covers both Member Of and Primary Group columns
- **CVSS scores** — click-to-copy vectors on all findings
- **Light/dark theme toggle** — all colors via CSS variables, no hardcoded values
- **Self-contained** — single HTML file, no server needed, works offline
