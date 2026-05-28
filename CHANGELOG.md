# Changelog

## [1.2.0] — 2026-05-28

### New features

- **`--sysvol` flag** — opt-in SYSVOL share scan (GPP cPassword XML, executables, archives, scripts outside `Scripts\`). Off by default — slow over SOCKS5 tunnels, run separately when needed. HTML report shows an opt-in hint when the scan was not performed.

### Bug fixes

- **ACL false positives** — `AnalyzeACL` now scopes analysis to high-value targets only: `adminCount=1` users and 15 privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, DNSAdmins, Account Operators, Backup Operators, Print Operators, Server Operators, GPCO, Domain Controllers, RODC, Key Admins, Enterprise Key Admins, Protected Users). Exchange groups (Organization Management, Exchange Trusted Subsystem) are explicitly excluded — Exchange RBAC installs broad ACEs on them by design; DCSync check already covers the dangerous end.
- **SYSVOL SMB bypassing SOCKS5 proxy** — `ScanSYSVOL` was using `net.DialTimeout` instead of the shared `smbBuildDialer(proxyURL)` helper. Fixed: same dialer as `CheckSMBSigning`.
- **GC (port 3268) bypassing SOCKS5 proxy** — Global Catalog connections were made directly regardless of `--proxy`. Fixed: routed through the SOCKS5 dialer.
- **Double error output** — when a command failed, cobra printed `Error: <msg>` and `main()` also printed the same error. Fixed: `rootCmd.SilenceErrors = true`; `main()` now prints the error once in red.
- **Usage shown on runtime errors** — cobra printed the full usage block on auth/connection failures. Fixed: `SilenceUsage = true` on all `RunE` commands — usage is not shown for runtime errors (wrong password, DC unreachable).
- **Auth error reveals too much** — `authentication failed — wrong password` and `authentication failed — wrong username or password` simplified to `authentication failed`.
- **ADCS Vulnerable Templates section expanded on load** — `exp-body` was missing `display:none`; section now starts collapsed.
- **ACL paging** — ACL search was limited to the default LDAP page size. Fixed: paging enabled, all entries retrieved.
- **ADCS ESC1 accuracy** — ESC1 detection improved to reduce false positives.

### Human-readable LDAP error messages

All LDAP and connection errors are now translated into actionable messages instead of raw codes:

| Condition | Message |
|---|---|
| Wrong credentials | `authentication failed` |
| Account locked | `authentication failed — account is locked out` |
| Account disabled | `authentication failed — account is disabled` |
| Password expired | `authentication failed — password has expired` |
| LDAP signing required | `DC requires LDAP signing — connect via LDAPS (port 636) or use Kerberos` |
| Channel binding required | `DC requires channel binding / confidentiality — connect via LDAPS (port 636)` |
| Null session disabled | `null sessions are disabled on this DC — provide credentials` |
| DC unreachable (refused) | `DC unreachable — connection refused (check DC IP and firewall on port 389/636)` |
| DC unreachable (timeout) | `DC unreachable — connection timed out (check network path, firewall, or proxy)` |
| DNS resolution failure | `DC hostname not resolved — check --dc value or DNS` |
| TLS handshake failure | `LDAPS TLS handshake failed — check that port 636 is reachable` |
| Base DN not found | `base DN not found — check domain spelling or use --scope` |
| Size limit exceeded | `LDAP result size limit exceeded — try --scope to narrow the search` |

### HTML report — UI improvements

- **Collapsible sections** — all expandable sections (`exp-section`, Kerberos, delegation cards, ACL groups) start **collapsed** by default (`▶`). Click to expand.
- **Delegation cards** — chevron moved to left side (consistent with all other tabs); risk reason always on the second line.
- **Delegation tab** — Expand all / Collapse all buttons added.
- **ACL tab** — `?` tooltip icons on each right-type group header (DCSync, WriteDACL, WriteOwner, GenericAll, ForceChangePassword, AddMember) explaining what the right allows.
- **Shadow Credentials table** — removed unintended left red border on table rows.
- **Audit findings** — CVSS scores shown on Medium/High findings.
- **GPO tab** — removed unused Expand all / Collapse all buttons from the section header.
- **Findings overview chart** — removed the `Info` bar (misleading in severity distribution).
- **SYSVOL tab** — shows opt-in hint with `--sysvol` instructions when scan was not run; shows error details when SMB is unreachable.

## [1.1.1] — 2026-05-19

### Bug fixes

- **kerb-enum `--proxy` silently ignored** — the `--proxy socks5://...` flag was registered on the `kerb-enum` command but the value was never passed into the dialer; all AS-REQ connections were made directly regardless of the flag. Fixed: `proxyURL` is now forwarded to the SOCKS5 dialer.
- **`smb` command has no proxy support** — `CheckSMBSigning` connected to port 445 via `net.DialTimeout` with no proxy path. Fixed: `--proxy` now routes SMB2 Negotiate traffic through the SOCKS5 proxy, consistent with all other commands.

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
