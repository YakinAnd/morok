# Changelog

## [1.2.2] — 2026-06-07

### Bug fixes

- **LDAPS auto-upgrade** — when the DC is configured with LDAP signing enforced (`signing:Enforced`), plain LDAP binds were rejected with "DC requires LDAP signing" and morok stopped. Now: on result code 8 (strongerAuthRequired) or 13 (confidentialityRequired), morok automatically reconnects on port 636 (LDAPS) and retries the bind. Simple bind (`-u/-p`) and Pass-the-Hash (`-H`) both handle the auto-upgrade. No user action required — the existing command works unchanged on signing-enforced DCs.
- **`--ldaps` flag** — forces LDAPS (port 636) from the start, skipping the plain LDAP attempt entirely. Useful when you know the DC enforces signing, or to avoid any plaintext LDAP traffic.

## [1.2.1] — 2026-06-02

### Security fixes

- **Trust SID filtering direction-aware (H-1)** — SID filtering risk is now split by trust direction. Outbound/bidirectional trusts with SID filtering off are `High` (attacker in trusted domain can forge SIDs to escalate here). Inbound-only trusts are `Medium` (our principals could forge SIDs in the remote domain). Previously all were treated identically.
- **Object ACE scoping (H-2, H-5)** — `GENERIC_ALL` and `GENERIC_WRITE` in Object ACEs (`ACCESS_ALLOWED_OBJECT_ACE`, type 0x05/0x0B) with a non-null `ObjectType` are now correctly scoped to that attribute only, not treated as full object takeover. Affects ACL, Shadow Credentials, and AdminSDHolder checks. Eliminates a class of false positives.
- **ACL parser cursor desync (H-3)** — Variable-length SID fields in ACEs were not consumed correctly; remaining ACEs in a DACL could be mis-parsed. Fixed: cursor advances past the full SID length.
- **Deny callback ACE types (H-5)** — Shadow Credentials check now skips ACE types 0x0A and 0x0C (deny callback Object ACEs) in addition to 0x01 and 0x06.
- **DCSync domain owner check (H-6)** — Owner check now correctly compares against the domain root DN rather than a hardcoded string.
- **ESC1 authentication EKU gate (M-15)** — ESC1 now requires at least one authentication-capable EKU. Server Authentication (`1.3.6.1.5.5.7.3.1`) added to the allowed set — certipy/Certify treat it as sufficient for S4U2Self/PKINIT abuse. Fixes a regression where WebServer-class templates were missed.
- **ACE size validation** — Malformed ACEs shorter than their declared type's minimum size are now skipped rather than causing a parser panic.
- **AdminSDHolder Object ACE scoping** — AdminSDHolder backdoor ACE check applies the same Object ACE scoping rules as the main ACL scan.

### Performance

- **O(1) DN→SID cache (H-4)** — `AnalyzeACL` now builds a single `map[string]string` (DN→SID) once per run instead of doing an O(N) linear scan per ACE. Large environments (10 k+ objects) see a significant speedup.

### SOCKS5 proxy fixes (C-1)

- **Cross-domain LDAP** — `SearchDomain` (used for child-domain computer enumeration) was using `net.DialTimeout` instead of the shared SOCKS5 dialer. Fixed.
- **DNS lookup bypass** — `queryChildDomainComputers` resolved child-domain IPs via `net.LookupHost` even when `--proxy` was set, leaking DNS outside the tunnel. Fixed: when a proxy is configured the call goes through `SearchDomain` and hostname resolution is delegated to the SOCKS5 proxy.

### HTML report — UI fixes

- **Table filter hides non-matching rows** — clicking a group filter or typing in search now hides rows that don't match (previously rows were sorted to top but non-matching rows remained visible).
- **Show all button re-applies filter** — "Show all N rows" now re-runs the active filter after revealing hidden rows, so non-matching rows stay hidden.
- **Show all button hidden during active filter** — the button is suppressed while any filter is active to avoid confusion; it reappears when filters are cleared.
- **Primary group highlights correctly** — users whose Primary Group is a privileged group (e.g. Domain Admins) are now highlighted red. AD does not include the primary group in `memberOf`, so a separate check on `PrimaryGroup` was added.

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
