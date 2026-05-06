# morok

**Active Directory Attack Path Enumerator**

morok is a lightweight, single-binary CLI tool for enumerating Active Directory environments, identifying attack paths to privileged groups, and detecting security misconfigurations — without requiring BloodHound, Neo4j, or any additional infrastructure.

```
       ·
    ·     ·
       ◇        morok  v1.0
    ·     ·      AD attack path enumerator
       ·          see through the fog
```

---

## What morok does

adpath connects to a Domain Controller over LDAP and runs a comprehensive security analysis across multiple domains:

| Category | What it checks |
|---|---|
| **Attack paths** | BFS graph traversal to Domain Admins, Enterprise Admins, Backup Operators, DNSAdmins, and 4 other privileged groups |
| **Kerberos** | Kerberoastable accounts (SPNs), AS-REP roastable accounts (no preauth) |
| **ACL** | GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync (replication rights) |
| **Delegation** | Unconstrained, constrained, RBCD misconfigurations |
| **ADCS** | Certificate template vulnerabilities ESC1–ESC9, ESC11, ESC13 |
| **SMB Signing** | SMB signing status on DC (port 445) — NTLM relay risk, no credentials needed |
| **Shadow Credentials** | Write access to `msDS-KeyCredentialLink` on privileged objects |
| **Trusts** | SID filtering, trust direction/type, Foreign Security Principals in privileged groups |
| **GPO** | Password policy, GPO write ACL, GPP/MS14-025 cpassword |
| **Exposure** | Stale accounts, krbtgt age, LAPS coverage, passwords in descriptions |
| **Protected Users** | Privileged accounts not in Protected Users group |
| **AdminSDHolder** | Orphaned adminCount=1 objects, backdoor ACEs |
| **LDAP Security** | Signing/channel binding enforcement, SASL mechanisms, anonymous read |
| **Audit Policy** | Legacy audit categories, AD Recycle Bin, machine account quota |

Every finding includes **next steps** (exploit commands) and **remediation guidance**.

---

## Key features

- **Single binary** — no Neo4j, no Python, no BloodHound required
- **Any privilege level** — works with any valid domain account; low-privilege is enough for most checks
- **Multiple auth methods** — password, Pass-the-Hash (NTLM), Pass-the-Ticket (Kerberos ccache)
- **SOCKS5 proxy** — route all LDAP traffic through a proxy (`--proxy socks5://127.0.0.1:1080`)
- **Scoped audit** — restrict enumeration to a specific OU (`--scope "OU=Finance,DC=corp,DC=local"`)
- **JSON export** — export AD objects as JSON (`--json ./json_out/`); format compatible with BloodHound CE v5
- **Self-contained HTML report** — single file, dark/light theme, global search, D3.js attack path graph
- **CI mode** — `--quiet` prints a single-line verdict with no ANSI codes, safe for Jenkins/GitHub Actions/GitLab

---

## Install

```bash
# Build from source (requires Go 1.21+)
git clone https://github.com/YakinAnd/morok
cd morok
go build -o adpath ./cmd/adpath/
./morok version
```

Pre-built binaries are available on the [Releases](https://github.com/YakinAnd/morok/releases) page.

---

## Quick start

```bash
# Full enumeration + HTML report
morok enum -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --report report.html

# CI/automation — single line verdict (no interactive output)
morok enum --quiet -d corp.local -u svc_audit -p '...' --dc 10.0.0.1
# Output: RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium

# Verbose — show all findings without truncation
morok enum --verbose -d corp.local -u administrator -p '...' --dc 10.0.0.1

# Pass-the-Hash
morok enum -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1

# Pass-the-Ticket (Kerberos ccache)
morok enum -d corp.local --ccache /tmp/administrator.ccache --dc 10.0.0.1

# SOCKS5 proxy (pivoting through a compromised host)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --proxy socks5://127.0.0.1:1080

# Restrict scope to specific OU
morok enum -d corp.local -u administrator -p '...' --scope 'OU=Finance,DC=corp,DC=local'

# JSON export (compatible with BloodHound CE v5)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --json ./json_out/

# Stealth mode — minimal LDAP footprint (SIEM-heavy environments)
morok enum --stealth -d corp.local -u administrator -p '...' --dc 10.0.0.1

# Username enumeration without credentials (Kerberos AS-REQ)
morok kerb-enum -d corp.local --dc 10.0.0.1 --wordlist users.txt

# SMB signing check (no credentials required)
morok smb -d corp.local --dc 10.0.0.1
```

---

## Commands

| Command | Description |
|---|---|
| `enum` | Full enumeration — runs all modules, generates HTML report |
| `kerberos` | Kerberoastable + AS-REP roastable accounts |
| `acl` | Dangerous ACL permissions (GenericAll, WriteDACL, DCSync…) |
| `delegation` | Unconstrained, constrained, RBCD delegation |
| `gpo` | GPO security analysis + password policy |
| `adcs` | ADCS certificate template vulnerabilities (ESC1–ESC9, ESC11, ESC13) |
| `trust` | Domain/forest trust analysis, Foreign Security Principals |
| `shadow` | Shadow Credentials — write access to msDS-KeyCredentialLink |
| `audit` | Audit policy, AD Recycle Bin, machine account quota |
| `users` | Enumerate AD users — summary table with AS-REP, adminCount, last logon |
| `computers` | Enumerate AD computers — forest-wide, OS, LAPS, delegation summary |
| `kerb-enum` | Username enumeration via Kerberos AS-REQ — no credentials required |
| `smb` | SMB signing check on DC port 445 — no credentials required |
| `version` | Print version |

---

## enum flags

```
  -d, --domain      Target domain (required)
  -u, --username    Username
  -p, --password    Password
  -H, --hashes      NT hash for Pass-the-Hash
      --ccache      Kerberos ccache file path (Pass-the-Ticket)
      --dc          Domain controller IP or hostname
      --proxy       SOCKS5 proxy (socks5://host:port) — PTT not supported
      --scope       Restrict to OU/DN
      --report      Save HTML report (e.g. report.html)
      --json        Export objects as JSON to directory
      --verbose     Show all findings without truncation
      --quiet       Print only risk verdict line (for CI/scripting)
      --stealth     Minimal queries — no ACL/GPO/ADCS/delegation
      --max-depth   BFS depth for attack path search (default 10)
```

---

## HTML Report

The `--report` flag generates a full interactive HTML report with:

- **Executive** tab — risk score (A–F grade), risk contribution bars by category
- **Summary** tab — findings overview chart, attack surface metrics
- **Attack Paths** — directed graph visualization (D3.js)
- **Kerberos**, **ACL**, **Delegation**, **ADCS**, **Trusts**, **Shadow Creds**, **GPO**, **LDAP Security**, **Audit**, **SYSVOL**
- **Users**, **Groups**, **Computers** — searchable/sortable tables
- Light/dark theme toggle
- CVSS scores with click-to-copy vectors

---

## CI Integration

```bash
# Exit non-zero on CRITICAL or HIGH risk
result=$(morok enum --quiet -d corp.local -u svc -p '...' --dc 10.0.0.1)
echo "$result"
if echo "$result" | grep -qE "RISK (CRITICAL|HIGH)"; then
  echo "AD compliance check failed"
  exit 1
fi
```

The `--quiet` output is plain ASCII with no ANSI color codes — safe for Jenkins, GitHub Actions, GitLab CI log parsers.

---

## Authentication

| Method | Flags |
|--------|-------|
| Password | `-u user -p 'pass'` |
| Pass-the-Hash | `-u user -H NT_HASH` |
| Pass-the-Ticket | `--ccache /path/to/file.ccache` |
| Anonymous | (no credentials — limited data) |

---

## Scoring & Severity Ratings

Severity scores and risk ratings in adpath are based on empirical
research and known attack patterns, but should be treated as
**indicative estimates**, not definitive measurements.

Current limitations:
- Scores may vary depending on environment and configuration
- Some attack paths lack sufficient real-world data for precise calibration
- Weightings are subject to change as research matures

We encourage practitioners to use these ratings as a **starting point**
for their own assessment, not as a final verdict.

Inaccuracies or edge cases? → open an issue or contact us.

---

## License

adpath is released under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

---

> morok is a security research and auditing tool. Use only against systems you own or have explicit written permission to test.
