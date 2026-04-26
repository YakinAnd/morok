# Roadmap

## Current: v0.9.9

### v0.9.9
- **HTML report redesign** — ACL grouped by right type by default (Group button removed); MITRE badges on group headers only (not per-row)
- **Exposure tab** — 8 collapsible sections with count + severity badges (krbtgt, Descriptions, Stale Users, Stale Computers, No LAPS, PSO, Protected Users, AdminSDHolder)
- **Expand All / Collapse All** — added to ACL and Exposure section headers
- **Global search overhaul** — results shown as clickable tab buttons (`ACL (5)  Kerberos (2)`); Enter navigates to best tab; auto-expands collapsed sections that contain matches; ✕ Clear button visible only when field has text; highlight color changed to blue (was amber — conflicted with badge-medium background)
- **Scale improvements** — tables truncated at 100 rows with Show All button; D3 graph capped at 80 nodes (privileged nodes always kept)
- **CLI Risk Summary** — `enum` output ends with a RISK SUMMARY block showing Critical/High/Medium counts across all modules

### v0.9.8
- **ADCS ESC9** — CT_FLAG_NO_SECURITY_EXTENSION detection in msPKI-Enrollment-Flag; Medium — requires GenericWrite over victim account to change UPN; next steps: bloodyAD UPN change + certipy req + certipy auth
- **ADCS ESC11** — ICPR/DCOM relay hint (CA-level finding, manual verify); High — same technique as ESC8 but via RPC instead of HTTP
- **ADCS ESC13** — issuance policy OID linked to privileged group via msDS-OIDToGroupLink; Critical if low-priv enrollment possible; queries CN=OID container

### v0.9.7
- **`adpath smb`** — SMB signing check via raw SMB2 Negotiate (no credentials); SecurityMode field parsing; High finding if signing not required; integrated into `adpath enum` output and HTML report (LDAP Security tab)

### v0.9.6
- **`adpath kerb-enum`** — username enumeration without credentials via Kerberos AS-REQ; classifies responses: EXISTS / AS-REP roastable / DISABLED / EXPIRED; wordlist with `#` comment support; not-found suppressed by default
- **`--stealth` flag** on `adpath enum` — minimal LDAP footprint: only users+groups (no GC, no computers); skips ACL, Delegation, GPO, ADCS, PSO, ProtectedUsers, AdminSDHolder, ShadowCredentials, Hygiene, LDAP Security, Audit; always runs: RootDSE, Kerberos, Trusts, Graph/AttackPaths; STEALTH SUMMARY printed at end

### v0.9.5
- **`adpath users`** — targeted user enumeration with colored table (AS-REP red, adminCount yellow, disabled dim); columns: username, display name, enabled, adminCount, AS-REP, pwd-never-expires, last logon, SPN count
- **`adpath computers`** — targeted computer enumeration via forest-wide GC; table: hostname, full OS + version, enabled; summary shows LAPS count and unconstrained delegation count
- **CLI table improvements** — ADCS vulnerable templates and Protected Users findings now use aligned column tables with separator lines
- **Bug fix** — `OBJECTS COLLECTED` and `QUICK FINDINGS` sections now only appear in `enum`, not in targeted commands (acl, shadow, trust, etc.)

### v0.9.4
- **MITRE ATT&CK mapping** — 17 technique keys, purple T-code badges in HTML report on section headers and per-row findings; all badges link to attack.mitre.org
- **Audit Policy / Blue Team** — `adpath audit` command; AD Recycle Bin check, legacy `auditingPolicy` attribute parse (9 categories), `ms-DS-MachineAccountQuota`; HTML Audit tab; High if no audit, Medium if Recycle Bin disabled or MAQ > 0
- **Unit tests** — `go test ./...` coverage: audit parsing, LDAP security, full HTML report render with fake data

### v0.9.3
- **Anonymous LDAP check** — `ProbeAnonymousRead()` detects if anonymous bind can read AD objects beyond RootDSE; Medium finding "Anonymous LDAP read enabled"
- **Improved anonymous output** — CLI shows "RootDSE ✓ readable" + hint when no credentials provided

### v0.9.2
- **`--scope` filtering** — override base DN for scoped OU/container audits on all commands

### v0.9.1 / v0.9.0
- **Shadow Credentials** — `adpath shadow`; DACL parse for `msDS-KeyCredentialLink` write on DA/EA/DC objects; HTML Shadow Creds tab
- **JSON export** — `--json` flag; users/groups/computers/domains.json; compatible with BloodHound CE v5
- **ADCS enrollment rights** — ESC1 Critical only if low-priv principal can actually enroll; Medium otherwise
- **HTML fixes** — severity badge fix, EnrollableBy badge

### v0.9.0
- **SOCKS5 proxy** — `--proxy socks5://host:port`; remote DNS; TLS-over-SOCKS5; PTT+proxy blocked
- **LDAP signing + channel binding** — `internal/analysis/ldap_security.go`; OID check; SASL over plain LDAP; HTML LDAP Security tab

---

## Released

### v0.8.2
- Trust analysis — `trustedDomain` enumeration, SID filtering, FSPs in privileged groups, `adpath trust`, HTML Trusts tab

### v0.8.1
- Protected Users group check
- RootDSE enumeration without authentication
- AdminSDHolder — orphaned adminCount=1, backdoor ACEs
- GPO ACL analysis — real nTSecurityDescriptor parsing
- Global search in HTML report

### v0.7
- ADCS module — ESC1–ESC8 with certipy next steps
- LAPS coverage detection
- GPP/MS14-025 detection via CSE GUIDs
- HTML: ADCS tab, Exposure tab, finding grouping, section tooltips

### v0.6
- DCSync detection
- Exposure module — stale accounts, krbtgt age, passwords in descriptions
- PSO (Fine-Grained Password Policy) analysis
- Extended attack paths to 8 privileged groups

### v0.5
- Forest-wide computer enumeration via Global Catalog (port 3268)
- Clickable summary cards in HTML
- D3.js graph redesign: node size = path count, edge labels, tooltips, red admin arrows

### v0.4
- Pass-the-Hash (NTLM) — `--hashes` flag
- Pass-the-Ticket (Kerberos ccache) — `--ccache` flag; SPNEGO/GSSAPI implementation

### v0.3
- Delegation checks (unconstrained, constrained, RBCD)
- GPO enumeration + password policy audit

### v0.2
- `adpath kerberos` — Kerberoasting / AS-REP detection
- `adpath acl` — dangerous ACL analysis with bloodyAD hints

### v0.1
- LDAP connection + authentication
- User/group/computer enumeration
- BFS attack paths to Domain Admins
- CLI output with colors
- HTML report with D3.js graph

---

## Planned

### Next
- **ADCS ESC10** — weak certificate mapping (registry-based, requires manual DC registry check)

### v1.0 — Public release
- README with demo GIF
- Blog post, r/netsec, conference (UISGCON)
- Pre-built binaries for Linux/macOS/Windows
