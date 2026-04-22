# adpath

**Active Directory Attack Path Enumerator**

adpath is a lightweight, single-binary CLI tool for enumerating Active Directory environments, identifying attack paths to privileged groups, and detecting security misconfigurations — without requiring BloodHound, Neo4j, or any additional infrastructure.

```
    _      ____    ____      _      _____   _   _
   / \    |  _ \  |  _ \    / \    |_   _| | | | |
  / _ \   | | | | | |_) |  / _ \     | |   | |_| |
 / ___ \  | |_| | |  __/  / ___ \    | |   |  _  |
/_/   \_\ |____/  |_|    /_/   \_\   |_|   |_| |_|

  v0.9.4  //  AD Attack Path Enumerator
```

---

## What adpath does

adpath connects to a Domain Controller over LDAP and runs a comprehensive security analysis across multiple domains:

| Category | What it checks |
|---|---|
| **Attack paths** | BFS graph traversal to Domain Admins, Enterprise Admins, Backup Operators, DNSAdmins, and 4 other privileged groups |
| **Kerberos** | Kerberoastable accounts (SPNs), AS-REP roastable accounts (no preauth) |
| **ACL** | GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync (replication rights) |
| **Delegation** | Unconstrained, constrained, RBCD misconfigurations |
| **ADCS** | Certificate template vulnerabilities ESC1–ESC8 |
| **Shadow Credentials** | Write access to `msDS-KeyCredentialLink` on privileged objects |
| **Trusts** | SID filtering, trust direction/type, Foreign Security Principals in privileged groups |
| **GPO** | Password policy, GPO write ACL, GPP/MS14-025 cpassword |
| **Hygiene** | Stale accounts, krbtgt age, LAPS coverage, passwords in descriptions |
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
- **BloodHound export** — generate CE v5 JSON for import into BloodHound (`--bloodhound ./bh_out/`)
- **Self-contained HTML report** — single file, dark/light theme, global search, D3.js attack path graph

---

## Quick start

```bash
# Full enumeration + HTML report
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
adpath enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1

# Pass-the-Ticket
adpath enum -d corp.local --ccache admin.ccache --dc dc01.corp.local

# With SOCKS5 proxy (pivoting)
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --proxy socks5://127.0.0.1:1080

# Export for BloodHound CE
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --bloodhound ./bh_out/

# Scoped audit (Finance OU only)
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --scope "OU=Finance,DC=corp,DC=local"

# ADCS vulnerabilities only
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Audit policy + AD Recycle Bin check
adpath audit -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

---

## Installation

```bash
# Build from source (requires Go 1.21+)
git clone https://github.com/YakinAnd/adpath
cd adpath
go build -o adpath ./cmd/adpath/...
./adpath version
```

Pre-built binaries are available on the [Releases](https://github.com/YakinAnd/adpath/releases) page.

---

## Commands overview

| Command | Description |
|---|---|
| `enum` | Full enumeration — runs all modules, generates HTML report |
| `kerberos` | Kerberoastable + AS-REP roastable accounts |
| `acl` | Dangerous ACL permissions (GenericAll, WriteDACL, DCSync…) |
| `delegation` | Unconstrained, constrained, RBCD delegation |
| `gpo` | GPO security analysis + password policy |
| `adcs` | ADCS certificate template vulnerabilities (ESC1–ESC8) |
| `trust` | Domain/forest trust analysis, Foreign Security Principals |
| `shadow` | Shadow Credentials — write access to msDS-KeyCredentialLink |
| `audit` | Audit policy, AD Recycle Bin, machine account quota |
| `version` | Print version |
