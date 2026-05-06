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

morok connects to a Domain Controller over LDAP and runs a comprehensive security analysis across multiple domains:

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

- **Single binary** — no Neo4j, no Python, no Bloodhound required
- **Any privilege level** — works with any valid domain account; low-privilege is enough for most checks
- **Multiple auth methods** — password, Pass-the-Hash (NTLM), Pass-the-Ticket (Kerberos ccache)
- **SOCKS5 proxy** — route all LDAP traffic through a proxy (`--proxy socks5://127.0.0.1:1080`)
- **Scoped audit** — restrict enumeration to a specific OU (`--scope "OU=Finance,DC=corp,DC=local"`)
- **JSON export** — export AD objects as JSON (`--json ./json_out/`); format compatible with BloodHound CE v5
- **Self-contained HTML report** — single file, dark/light theme, global search, D3.js attack path graph

---

## Quick start

```bash
# Full enumeration + HTML report
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
morok enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1

# Pass-the-Ticket
morok enum -d corp.local --ccache admin.ccache --dc dc01.corp.local

# With SOCKS5 proxy (pivoting)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --proxy socks5://127.0.0.1:1080

# JSON export (compatible with BloodHound CE)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --json ./json_out/

# Scoped audit (Finance OU only)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --scope "OU=Finance,DC=corp,DC=local"

# ADCS vulnerabilities only
morok adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Audit policy + AD Recycle Bin check
morok audit -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Stealth mode — minimal LDAP footprint (SIEM-heavy environments)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --stealth

# Username enumeration without credentials (Kerberos AS-REQ)
morok kerb-enum -d corp.local --dc 10.0.0.1 --wordlist users.txt

# SMB signing check without credentials
morok smb -d corp.local --dc 10.0.0.1
```

---

## Installation

```bash
# Build from source (requires Go 1.21+)
git clone https://github.com/YakinAnd/morok
cd morok
go build -o morok ./cmd/morok/...
./morok version
```

Pre-built binaries are available on the [Releases](https://github.com/YakinAnd/morok/releases) page.

---

## Commands overview

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
