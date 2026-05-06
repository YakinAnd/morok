# morok gpo

Analyzes Group Policy Objects — password policy audit and GPO write ACL detection.

## Usage

```bash
morok gpo -d <domain> -u <user> -p <pass> --dc <dc>
```

## What it checks

**Default password policy** — reads the domain object attributes:

| Check | Threshold |
|-------|-----------|
| Minimum length | < 8 chars → Critical |
| Complexity | Disabled → Critical |
| Max age | Never expires → Critical |
| Reversible encryption | Enabled → Critical |
| Lockout threshold | 0 (disabled) → Critical |

**GPO write ACL** — parses `nTSecurityDescriptor` on each GPO object. If a low-privilege principal has write rights:

- GPO linked to Domain Controllers OU → **Critical**
- GPO linked to Domain root → **Critical**
- GPO linked to any other OU → **High**

GPO write access = code execution on all machines in the linked scope via scheduled tasks or startup scripts.

**GPP passwords (MS14-025)** — detects Group Policy Preferences extensions (CSE GUIDs) that historically stored encrypted passwords in SYSVOL.

## Output includes

- Password policy table with pass/fail for each control
- GPO ACL findings: principal → GPO → linked scope
- Severity per finding

## Example

```bash
morok gpo -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
