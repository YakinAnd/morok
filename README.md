# adpath

Active Directory attack path enumerator and security auditing tool.

```
adpath enum -d corp.local -u administrator -p 'P@ssw0rd' --dc 10.0.0.1 --report report.html
```

## Install

```bash
git clone https://github.com/YakinAnd/adpath
cd adpath
go build -o adpath ./cmd/adpath/
```

Or download a pre-built binary from [Releases](https://github.com/YakinAnd/adpath/releases).

## Quickstart

```bash
# Full enumeration + HTML report
adpath enum -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --report report.html

# CI/automation — single line verdict (no interactive output)
adpath enum --quiet -d corp.local -u svc_audit -p '...' --dc 10.0.0.1
# Output: RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium

# Verbose — show all findings without truncation
adpath enum --verbose -d corp.local -u administrator -p '...' --dc 10.0.0.1

# Pass-the-Hash
adpath enum -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1

# Pass-the-Ticket (Kerberos ccache)
adpath enum -d corp.local --ccache /tmp/administrator.ccache --dc 10.0.0.1

# SOCKS5 proxy
adpath enum -d corp.local -u administrator -p '...' --proxy socks5://127.0.0.1:1080

# Restrict scope to specific OU
adpath enum -d corp.local -u administrator -p '...' --scope 'OU=Finance,DC=corp,DC=local'

# Stealth mode — minimal LDAP queries
adpath enum --stealth -d corp.local -u administrator -p '...' --dc 10.0.0.1
```

## Commands

| Command | Description |
|---------|-------------|
| `enum` | Full enumeration: attack paths, ACLs, Kerberos, delegation, ADCS, shadow creds, GPO, trusts |
| `acl` | Dangerous ACL permissions (GenericAll, WriteDACL, WriteOwner, ForceChangePassword) |
| `adcs` | ADCS misconfigurations (ESC1–ESC8) |
| `audit` | Audit policy, AD Recycle Bin, blue-team visibility |
| `computers` | Enumerate computers with summary table |
| `delegation` | Unconstrained, constrained, resource-based constrained delegation |
| `gpo` | Group Policy Object security analysis |
| `kerb-enum` | Username enumeration via Kerberos AS-REQ (no credentials) |
| `kerberos` | Kerberoastable and AS-REP roastable accounts |
| `shadow` | Principals that can write msDS-KeyCredentialLink |
| `smb` | SMB signing status on domain controller |
| `trust` | Domain/forest trusts and foreign security principals |
| `users` | Enumerate users with summary table |

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

## HTML Report

The `--report` flag generates a full interactive HTML report with:

- **Executive** tab — risk score (A–F grade), risk contribution bars by category
- **Summary** tab — findings overview chart, attack surface metrics
- **Attack Paths** — directed graph visualization (D3.js)
- **Kerberos**, **ACL**, **Delegation**, **ADCS**, **Trusts**, **Shadow Creds**, **GPO**, **LDAP Security**, **Audit**, **SYSVOL**
- **Users**, **Groups**, **Computers** — searchable/sortable tables
- Light/dark theme toggle
- CVSS scores with click-to-copy vectors

## CI Integration

```bash
# Exit non-zero on CRITICAL or HIGH risk
result=$(adpath enum --quiet -d corp.local -u svc -p '...' --dc 10.0.0.1)
echo "$result"
if echo "$result" | grep -qE "RISK (CRITICAL|HIGH)"; then
  echo "AD compliance check failed"
  exit 1
fi
```

The `--quiet` output is plain ASCII with no ANSI color codes — safe for Jenkins, GitHub Actions, GitLab CI log parsers.

## Authentication

| Method | Flags |
|--------|-------|
| Password | `-u user -p 'pass'` |
| Pass-the-Hash | `-u user -H NT_HASH` |
| Pass-the-Ticket | `--ccache /path/to/file.ccache` |
| Anonymous | (no credentials — limited data) |

## License

adpath is released under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

**Commercial use** (SaaS, managed services, enterprise redistribution) requires a separate commercial license.
Contact: yakinanrey@gmail.com

---

> adpath is a security research and auditing tool. Use only against systems you own or have explicit written permission to test.
