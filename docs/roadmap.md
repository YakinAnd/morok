# Roadmap

## Current: v0.9.5

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
- **Username enumeration via Kerberos AS-REQ** — `adpath enum-users --wordlist users.txt`; PRINCIPAL_UNKNOWN vs PREAUTH_REQUIRED without credentials
- **MITRE ATT&CK mapping** — technique tags (T1558.003, T1484.001, etc.) on each finding; badge with link to attack.mitre.org in HTML report

### v1.0 — Public release
- README with demo GIF
- Blog post, r/netsec, conference (UISGCON)
- Pre-built binaries for Linux/macOS/Windows
