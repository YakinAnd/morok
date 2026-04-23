# Quick Start

## 1. Full enumeration

The `enum` command runs all analysis modules and generates an HTML report.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

CLI output:

```
  DOMAIN INFO
  domain                       DC=corp,DC=local
  forest                       DC=corp,DC=local
  domain level                 7  (Windows Server 2016/2019/2022)
  responding DC                dc01.corp.local

  GRAPH
  nodes        47
  edges        123

  ATTACK PATHS
  [CRITICAL] jdoe → MemberOf → IT Admins → MemberOf → Domain Admins  (depth 2)

  KERBEROS
  kerberoastable               3
  as-rep roastable             1

  ACL
  dangerous ACLs               12
  DCSync rights                2
  ...

  report saved to: corp_2026-04-22_10-00-00.html
```

## 2. Save to specific path

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp_report.html
```

## 3. Targeted checks

Run individual modules when you need specific data. Standalone commands show **full output** including exploit next steps — `enum` only shows a summary.

```bash
# Kerberoastable + AS-REP roastable accounts (with hashcat commands)
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Dangerous ACLs
adpath acl -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Delegation misconfigurations
adpath delegation -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# GPO analysis + password policy
adpath gpo -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# ADCS — ESC1 through ESC8
adpath adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Domain trusts + Foreign Security Principals
adpath trust -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Shadow Credentials
adpath shadow -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Audit policy + AD Recycle Bin
adpath audit -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# All users — colored table with AS-REP, adminCount, last logon, SPN count
adpath users -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# All computers — forest-wide via GC, table with hostname, OS, enabled status
adpath computers -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

## 4. JSON export

Export AD objects as JSON files (users, groups, computers, domains):

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --json ./json_out/
```

The format is compatible with BloodHound CE v5 — import via: **BloodHound CE → Administration → File Ingest**

## 5. Scoped enumeration

Audit only a specific OU or container instead of the entire domain. Useful for large environments or when you want to focus on a specific business unit.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local"
```

## 6. Low-privilege account

adpath works with **any valid domain account**. AD's default security model allows all authenticated users to read most LDAP attributes — you do not need Domain Admin or local admin rights for enumeration.

```bash
adpath enum -d corp.local -u helpdesk -p 'Summer2024!' --dc 10.0.0.1
```

## 7. Stealth mode

Reduce your LDAP footprint in SIEM-heavy environments. `--stealth` is available only on `enum` — it skips ACL, Delegation, GPO, ADCS, PSO, ProtectedUsers, AdminSDHolder, ShadowCredentials, Hygiene, LDAP Security, and Audit. Only basic enumeration, Kerberos, Trusts, and attack paths run.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --stealth
```

## 8. Username enumeration (no credentials)

Enumerate valid AD usernames via Kerberos AS-REQ — only port 88 access to the DC is required:

```bash
adpath kerb-enum -d corp.local --dc 10.0.0.1 --wordlist users.txt
```

## 9. SMB signing check (no credentials)

Check if SMB signing is required on the DC — only port 445 access needed:

```bash
adpath smb -d corp.local --dc 10.0.0.1
```

## 11. Pivoting through SOCKS5

Route all LDAP traffic through a proxy — useful when the DC is only reachable via a pivot:

```bash
# Start your SOCKS5 proxy (e.g. via SSH tunnel or Chisel)
# Then run adpath with --proxy
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080
```

DNS is resolved on the proxy side (remote DNS). See [Proxy & Scope](proxy-scope.md) for details.
