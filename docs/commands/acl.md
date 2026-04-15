# adpath acl

Analyzes dangerous ACL permissions on AD objects.

## Usage

```bash
adpath acl -d <domain> -u <user> -p <pass> --dc <dc>
```

## Detected rights

| Right | Impact |
|-------|--------|
| `GenericAll` | Full control — reset password, add to groups, modify attributes |
| `WriteDACL` | Modify object's ACL — grant yourself GenericAll |
| `WriteOwner` | Take ownership — then grant yourself WriteDACL |
| `ForceChangePassword` | Reset account password without knowing current |
| `AddMember` | Add members to a group |
| `GenericWrite` | Write arbitrary attributes — set SPN for Kerberoasting |
| `DCSync` | Replicate directory data — dump all password hashes |

## Severity

- **Critical** — right on Domain Admins, DA member, or DCSync on domain object
- **High** — right on privileged account or group
- **Medium** — right on standard account

## Output includes

- Principal (who has the right) → Target (what object)
- Exploit command (bloodyAD / dacledit.py / owneredit.py)
- Remediation advice

## Example

```bash
adpath acl -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
