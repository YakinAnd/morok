# adpath audit

Check blue-team visibility settings: legacy audit policy configuration, AD Recycle Bin status, and machine account quota.

## Usage

```bash
adpath audit -d <domain> -u <user> -p <pass> --dc <dc>
```

## Flags

Standard auth flags apply. See [Authentication](../getting-started/auth.md).

## What it checks

### AD Recycle Bin

Checks whether the AD Recycle Bin Optional Feature is enabled by reading `msDS-EnabledFeature` on the Partitions object in the Configuration NC.

| Status | Severity |
|--------|----------|
| Enabled | ✓ No finding |
| Disabled (forest FFL ≥ 2008 R2) | Medium |
| Not supported (forest FFL < 2008 R2) | Informational |

**Why it matters:** Without the Recycle Bin, accidentally or maliciously deleted objects (user accounts, computer accounts, GPOs, OUs) cannot be recovered without an authoritative restore from backup. Attackers who delete accounts or GPOs to cause disruption leave no easy recovery path.

### Legacy Audit Policy

Reads the `auditingPolicy` binary attribute from the domain object. This 9-byte attribute controls which event categories generate Security Event Log entries on DCs.

Checked categories:

| Category | What it covers |
|----------|----------------|
| Account Logon | Kerberos/NTLM authentication events (4768, 4769, 4776) |
| Account Management | User/group creation, modification, deletion |
| Logon/Logoff | Interactive and network logons (4624, 4625, 4648) |
| Directory Service Access | LDAP reads/writes on AD objects (4662) |
| Object Access | File/registry access (not AD-specific) |
| Policy Change | Audit policy changes |
| Privilege Use | Use of sensitive privileges (SeDebugPrivilege, etc.) |
| Detailed Tracking | Process creation (4688) |
| System Events | System startup/shutdown |

| Status | Severity |
|--------|----------|
| Not configured at all | High |
| Missing critical categories (Account Logon, Account Management, Logon/Logoff, Directory Service Access) | Medium |
| All critical categories enabled | ✓ No finding |

!!! note
    This checks the **legacy basic audit policy** via LDAP. Advanced Audit Policy (subcategory-level control) is configured via GPO and stored in SYSVOL, which requires SMB access to read fully. Enabling the legacy policy here is a baseline — Advanced Audit Policy provides finer control.

### Machine Account Quota

Reads `ms-DS-MachineAccountQuota` from the domain object. Default value is **10**.

| Value | Severity |
|-------|----------|
| 0 | ✓ Safe |
| > 0 | Medium |

**Why it matters:** Any authenticated domain user can add up to `MachineAccountQuota` computer accounts to the domain. This is a well-known **RBCD (Resource-Based Constrained Delegation) abuse vector**:

1. Attacker creates a computer account using their low-privilege domain account
2. Attacker sets `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target machine to allow their computer account
3. Attacker requests a service ticket impersonating a Domain Admin

## Output

```
  AUDIT POLICY / BLUE TEAM
  AD Recycle Bin               DISABLED ⚠
  legacy audit policy          configured
    Account Management         Success
    Account Logon              Success+Failure
  machine account quota        10 ⚠

  [High]   Legacy audit policy not configured
  [Medium] AD Recycle Bin disabled
  [Medium] Machine account quota = 10 (any user can add computers)
```

## Remediation

**AD Recycle Bin:**
```powershell
Enable-ADOptionalFeature 'Recycle Bin Feature' \
  -Scope ForestOrConfigurationSet \
  -Target corp.local
```

**Legacy Audit Policy (GPO):**
Computer Configuration → Windows Settings → Security Settings → Local Policies → Audit Policy → Enable "Success" for at minimum: Account Logon, Account Management, Logon Events, Directory Service Access.

**Machine Account Quota:**
```powershell
Set-ADDomain -Identity corp.local \
  -Replace @{"ms-DS-MachineAccountQuota"="0"}
```
