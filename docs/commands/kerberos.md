# adpath kerberos

Finds Kerberoastable and AS-REP roastable accounts with severity assessment and hashcat cracking hints.

## Usage

```bash
adpath kerberos -d <domain> -u <user> -p <pass> --dc <dc>
```

## What it detects

**Kerberoastable** — accounts with a Service Principal Name (SPN). Any authenticated user can request a Kerberos TGS ticket for them and crack the hash offline. Risk increases significantly if the account has `adminCount=1` or is in a privileged group.

**AS-REP roastable** — accounts with `Do not require Kerberos pre-authentication` enabled. An attacker can request an AS-REP without a password and crack the encrypted portion offline.

## Severity

| Condition | Severity |
|-----------|----------|
| Kerberoastable + adminCount=1 | Critical |
| Kerberoastable + privileged group | Critical |
| Kerberoastable, enabled | High |
| AS-REP roastable + adminCount=1 | Critical |
| AS-REP roastable, enabled | High |

## Output includes

- Account name, last logon, password last set
- SPNs (for Kerberoastable)
- Hashcat mode hints (`-m 13100` for TGS, `-m 18200` for AS-REP)
- GetUserSPNs.py / GetNPUsers.py commands

## Example

```bash
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
