# adpath

**Active Directory Attack Path Enumerator**

adpath is a lightweight CLI tool for enumerating Active Directory environments, identifying attack paths to privileged groups, and detecting common misconfigurations — without requiring BloodHound or a Neo4j instance.

```
    _      ____    ____      _      _____   _   _
   / \    |  _ \  |  _ \    / \    |_   _| | | | |
  / _ \   | | | | | |_) |  / _ \     | |   | |_| |
 / ___ \  | |_| | |  __/  / ___ \    | |   |  _  |
/_/   \_\ |____/  |_|    /_/   \_\   |_|   |_| |_|

  v0.8.3  //  AD Attack Path Enumerator
```

## What adpath does

- Enumerates users, groups, computers, GPOs, certificate templates, and trusts over LDAP
- Finds attack paths to Domain Admins and other privileged groups via BFS graph traversal
- Detects Kerberoastable, AS-REP roastable, and delegation-misconfigured accounts
- Analyzes dangerous ACLs (GenericAll, WriteDACL, DCSync, etc.)
- Checks ADCS for ESC1–ESC8 vulnerabilities
- Audits domain trusts and SID filtering configuration
- Generates a self-contained HTML report with dark/light theme toggle

## Quick example

```bash
# Full enumeration + HTML report
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Find Kerberoastable accounts
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
adpath enum -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8dCT... --dc 10.0.0.1
```

## Design goals

- **No dependencies** — single binary, no Neo4j, no Python, no Bloodhound
- **Any privilege level** — useful with any valid domain account, even low-privilege
- **Actionable output** — every finding includes exploit commands and remediation steps
- **Self-contained report** — single HTML file, works offline

## Installation

Download the latest binary from [Releases](https://github.com/YakinAnd/adpath/releases) or build from source:

```bash
git clone https://github.com/YakinAnd/adpath
cd adpath
go build -o adpath ./cmd/adpath/...
```
