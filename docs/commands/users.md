# adpath users

Enumerate all AD users and display a summary table.

## Usage

```bash
adpath users -d <domain> -u <username> -p <password> [--dc <dc>]
```

## Output

**Summary section** (always shown):

- Total user count
- Enabled / disabled counts
- `adminCount=1` accounts (yellow)
- AS-REP roastable accounts (red — no Kerberos pre-auth required)
- Accounts with password-never-expires set (yellow)

**Per-user table** with dynamic column widths:

| Column | Description |
|---|---|
| USERNAME | sAMAccountName |
| DISPLAY NAME | displayName attribute |
| ENABLED | Account active status |
| ADMINCOUNT | adminCount=1 (protected by AdminSDHolder) |
| AS-REP | No pre-auth required (roastable without creds) |
| PWD NEVER EXP | Password never expires flag |
| LAST LOGON | lastLogonTimestamp |
| SPNS | Number of service principal names (Kerberoastable if > 0) |

**Row colors:**

- Red — AS-REP roastable accounts
- Yellow — adminCount=1 accounts
- Dim — disabled accounts

## Examples

```bash
# Basic enumeration
adpath users -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
adpath users -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1

# Scoped to specific OU
adpath users -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --scope "OU=Finance,DC=corp,DC=local"
```

## Flags

All standard connection flags apply — see [Authentication](../getting-started/auth.md).

## Notes

- Uses domain-only LDAP search (not forest-wide GC). For multi-domain forests, run per domain.
- For full analysis including Kerberoasting and AS-REP detection, use [`adpath kerberos`](kerberos.md).
