# morok enum

Full AD enumeration — runs all analysis modules and generates a self-contained HTML report.

## Usage

```bash
morok enum -d <domain> -u <user> -p <pass> --dc <dc> [flags]
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
| `--sysvol` | | Scan SYSVOL share for GPP cPassword XML, executables, archives, scripts outside `Scripts\` — off by default (slow over proxy/tunnels) | |
| `--stealth` | | Stealth mode — minimal LDAP queries, no GC, no ACL/ADCS/GPO/delegation | |
| `--verbose` | | Show all findings without truncation (disables 5-item limit per section) | |
| `--quiet` | | Quiet mode — print only risk verdict line (for CI/scripting) | |

## What it runs

`enum` executes every module in sequence and prints a summary for each. Use standalone commands (e.g. `morok acl`) to see full output with exploit next steps.

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
| **ADCS** | ESC1–ESC9, ESC11, ESC13 certificate template vulnerabilities |
| **Protected Users** | Privileged accounts not in Protected Users group |
| **AdminSDHolder** | Orphaned adminCount=1, custom backdoor ACEs |
| **Trusts** | Trust direction/type, SID filtering, FSPs in privileged groups |
| **Shadow Credentials** | Write access to msDS-KeyCredentialLink on DA/EA/DC objects |
| **SMB Signing** | SMB signing status on the DC (port 445) — NTLM relay risk |
| **SYSVOL** | GPP Preferences XML (cPassword/MS14-025), executables, archives, scripts outside `Scripts\` — only with `--sysvol` |

## Multi-domain / trust following

`enum` automatically follows trusted domains in the same forest. For each trusted domain it can reach, it runs a full enumeration and merges results:

- CLI output prints a `══ domain.local ══` separator before each domain's findings
- HTML report shows a domain tab per domain on all finding tables
- Computers and users are deduplicated by ObjectSID — no duplicates when the GC query and trusted-domain enumeration overlap

To enumerate a specific secondary domain only, target its DC with `--dc`.

## HTML report

The report is saved to `<domain>_<timestamp>.html` by default (next to the binary). Specify a custom path with `--report`.

```bash
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html
```

The report is a **self-contained single HTML file** — no server needed, works offline, can be emailed or archived.

## JSON export

```bash
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --json ./json_out/
```

Generates `users.json`, `groups.json`, `computers.json`, `domains.json`. The format is compatible with **BloodHound CE v5** — import via: BloodHound CE → Administration → File Ingest.

## Examples

```bash
# Standard run
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
morok enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c \
  --dc 10.0.0.1 --report /tmp/corp.html

# Pass-the-Ticket
morok enum -d corp.local --ccache admin.ccache --dc dc01.corp.local

# Through SOCKS5 proxy
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080

# Scoped to Finance OU
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local"

# Full run + JSON export
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html --json ./json_out/

# Quiet mode — single line output for CI pipelines
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --quiet

# Verbose — show all findings without 5-item truncation
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --verbose

# SYSVOL scan (opt-in — slow over proxy/tunnels)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --sysvol
```
