# Quick Start

## 1. Full enumeration

The `enum` command runs all checks and generates an HTML report.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

Output includes:

- Domain info (functional level, forest, responding DC)
- Collected objects (users, groups, computers)
- Attack paths to privileged groups
- Kerberoastable / AS-REP roastable accounts
- Dangerous ACLs
- Delegation misconfigurations
- GPO findings
- ADCS vulnerabilities (ESC1–ESC8)
- Protected Users coverage
- AdminSDHolder backdoor ACEs
- Domain trust configuration

```bash
# Save report to a specific path
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --report /tmp/corp_report.html
```

The report is a self-contained HTML file with a dark/light theme toggle and a global search bar.

## 2. Targeted checks

Run individual modules when you only need specific data:

```bash
# Kerberoastable + AS-REP roastable accounts
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Dangerous ACLs (GenericAll, WriteDACL, DCSync...)
adpath acl -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Delegation misconfigurations
adpath delegation -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# GPO analysis + password policy
adpath gpo -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# ADCS (ESC1–ESC8)
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Domain trusts + Foreign Security Principals
adpath trust -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

Standalone commands print full output including next steps (exploit commands). The `enum` command shows a summary without next steps to keep output clean.

## 3. Low-privilege account

adpath works with any valid domain account. You do not need Domain Admin or local admin rights for enumeration — AD's default security model allows all authenticated users to read most LDAP attributes.

```bash
adpath enum -d corp.local -u helpdesk -p 'Summer2024!' --dc 10.0.0.1
```
