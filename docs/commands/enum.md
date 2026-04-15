# adpath enum

Full AD enumeration — runs all analysis modules and generates an HTML report.

## Usage

```bash
adpath enum -d <domain> -u <user> -p <pass> --dc <dc> [--report <path>]
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain (required) | |
| `-u, --username` | Username | |
| `-p, --password` | Password | |
| `-H, --hashes` | NT hash for Pass-the-Hash | |
| `--ccache` | Path to Kerberos ccache | |
| `--dc` | Domain controller IP or hostname | |
| `--report` | HTML report output path | `<domain>_<timestamp>.html` |
| `--max-depth` | BFS depth for attack path search | `10` |
| `-v, --verbose` | Verbose LDAP output | |

## What it runs

| Module | Description |
|--------|-------------|
| RootDSE | Domain, forest, functional level, responding DC |
| Enumeration | Users, groups, computers (forest-wide via GC) |
| Attack paths | BFS to DA, EA, Backup Operators, DNSAdmins, and 5 other privileged groups |
| Kerberos | Kerberoastable + AS-REP roastable accounts |
| ACL | GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync |
| Delegation | Unconstrained, constrained, RBCD |
| GPO | Password policy, GPO write ACL |
| Hygiene | Stale accounts, krbtgt age, passwords in description, LAPS coverage |
| PSO | Fine-grained password policies |
| ADCS | ESC1–ESC8 certificate template vulnerabilities |
| Protected Users | Privileged accounts not in Protected Users group |
| AdminSDHolder | Orphaned adminCount=1, backdoor ACEs |
| Trusts | Trust direction/type, SID filtering, Foreign Security Principals |

## Output

CLI prints a summary for each module. Next steps (exploit commands) are omitted from `enum` output — use the individual commands (e.g. `adpath acl`) to see full output including next steps.

The HTML report contains all findings with exploit/fix accordions, interactive graph, global search, and a dark/light theme toggle.

## Examples

```bash
# Standard enumeration
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash, custom report path
adpath enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c \
  --dc 10.0.0.1 --report /tmp/corp.html

# Pass-the-Ticket
adpath enum -d corp.local --ccache admin.ccache --dc dc01.corp.local
```
