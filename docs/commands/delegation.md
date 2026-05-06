# morok delegation

Detects dangerous Kerberos delegation configurations.

## Usage

```bash
morok delegation -d <domain> -u <user> -p <pass> --dc <dc>
```

## Delegation types

**Unconstrained delegation** — the account caches TGTs of any connecting user. If compromised, all TGTs can be extracted and replayed. DCs have unconstrained delegation by design and are excluded.

**Constrained delegation** — the account can only delegate to specific services. Still dangerous if the target service is critical (LDAP, CIFS, HOST) or if Protocol Transition (`TrustedToAuthForDelegation`) is enabled.

**Resource-Based Constrained Delegation (RBCD)** — controlled by the target resource. An attacker who can write `msDS-AllowedToActOnBehalfOfOtherIdentity` can add their own machine account and impersonate any user.

## Severity

| Type | Condition | Severity |
|------|-----------|----------|
| Unconstrained | User account (not DC) | Critical |
| Unconstrained | Computer account (not DC) | High |
| Constrained | Delegation to LDAP/CIFS/HOST | High |
| Constrained | Protocol Transition enabled | High |
| RBCD | Any | Medium |

## Output includes

- Account name, object type, delegation target services
- getST.py / Rubeus exploit commands
- Remediation steps

## Example

```bash
morok delegation -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
