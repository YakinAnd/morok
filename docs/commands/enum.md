# adpath enum

Full AD enumeration — runs all analysis modules and generates a self-contained HTML report.

## Usage

```bash
adpath enum -d <domain> -u <user> -p <pass> --dc <dc> [flags]
```

## Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--domain` | `-d` | Target domain FQDN (required) | |
| `--username` | `-u` | Username | |
| `--password` | `-p` | Password | |
| `--hashes` | `-H` | NT hash for Pass-the-Hash (`LM:NT` or `:NT`) | |
| `--ccache` | | Path to Kerberos ccache file | |
| `--dc` | | DC IP or hostname | |
| `--proxy` | | SOCKS5 proxy URL (`socks5://host:port`) | |
| `--scope` | | Restrict enumeration to specific OU/DN | |
| `--report` | | HTML report output path | `<domain>_<timestamp>.html` |
| `--json` | | Export AD objects as JSON to directory (e.g. `json_out/`) | |
| `--max-depth` | | BFS depth for attack path search | `10` |
| `--verbose` | `-v` | Verbose LDAP output | |

## What it runs

`enum` executes every module in sequence and prints a summary for each. Use standalone commands (e.g. `adpath acl`) to see full output with exploit next steps.

| Module | What it checks |
|--------|----------------|
| **RootDSE** | Domain, forest, functional level, responding DC — no auth required |
| **LDAP Security** | Signing/channel binding, SASL mechanisms, anonymous read |
| **Audit Policy** | Legacy audit categories, AD Recycle Bin, machine account quota |
| **Enumeration** | Users, groups, computers (forest-wide via Global Catalog) |
| **Graph** | In-memory attack path graph |
| **Attack Paths** | BFS to DA, EA, Backup Ops, Account Ops, Server Ops, Print Ops, DNSAdmins, GPO Creator Owners |
| **Kerberos** | Kerberoastable + AS-REP roastable accounts |
| **ACL** | GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync |
| **Delegation** | Unconstrained, constrained, RBCD |
| **GPO** | Password policy audit, GPO write ACL, GPP cpassword |
| **Exposure** | Stale accounts, krbtgt age, LAPS coverage, passwords in descriptions |
| **PSO** | Fine-Grained Password Policy (msDS-PasswordSettings objects) |
| **ADCS** | ESC1–ESC8 certificate template vulnerabilities |
| **Protected Users** | Privileged accounts not in Protected Users group |
| **AdminSDHolder** | Orphaned adminCount=1, custom backdoor ACEs |
| **Trusts** | Trust direction/type, SID filtering, FSPs in privileged groups |
| **Shadow Credentials** | Write access to msDS-KeyCredentialLink on DA/EA/DC objects |

## HTML report

The report is saved to `<domain>_<timestamp>.html` by default (next to the binary). Specify a custom path with `--report`.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html
```

The report is a **self-contained single HTML file** — no server needed, works offline, can be emailed or archived.

## JSON export

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --json ./json_out/
```

Generates `users.json`, `groups.json`, `computers.json`, `domains.json`. The format is compatible with **BloodHound CE v5** — import via: BloodHound CE → Administration → File Ingest.

## Examples

```bash
# Standard run
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
adpath enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c \
  --dc 10.0.0.1 --report /tmp/corp.html

# Pass-the-Ticket
adpath enum -d corp.local --ccache admin.ccache --dc dc01.corp.local

# Through SOCKS5 proxy
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080

# Scoped to Finance OU
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local"

# Full run + JSON export
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html --json ./json_out/
```
