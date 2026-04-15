# Roadmap

## Released

### v0.8.3 (current)
- Light/dark theme toggle in HTML report (persisted to localStorage)
- Next steps suppressed in `enum` output — shown only in standalone commands

### v0.8.2
- Trust analysis — `trustedDomain` enumeration, SID filtering status, Foreign Security Principals
- `adpath trust` standalone command
- HTML Trusts tab

### v0.8.1
- Protected Users group check — privileged accounts not in group
- RootDSE enumeration without auth — domain, forest, functional level, responding DC
- AdminSDHolder analysis — orphaned adminCount=1, backdoor ACEs
- GPO ACL analysis — real SD parsing, write access on GPOs
- Global search bar in HTML report

### v0.7
- ADCS module — ESC1–ESC8 detection with certipy next steps
- LAPS coverage detection
- GPP/MS14-025 detection via CSE GUIDs

### v0.6
- DCSync detection
- Hygiene / Exposure module — stale accounts, krbtgt age, passwords in descriptions
- PSO (Fine-Grained Password Policy) analysis
- Extended attack paths to 8 privileged groups

### v0.5
- Forest-wide computer enumeration via Global Catalog

### v0.4
- Pass-the-Hash (NTLM)
- Pass-the-Ticket (Kerberos ccache)

### v0.3
- Delegation checks (unconstrained, constrained, RBCD)
- GPO enumeration + password policy

### v0.2
- Kerberoasting / AS-REP roasting detection
- Dangerous ACL analysis

### v0.1
- LDAP enumeration, attack paths, HTML report

---

## Planned

### v0.9
- **SOCKS5 proxy** — `--proxy socks5://127.0.0.1:1080` with remote DNS resolution
- **Stealth mode** — `--stealth`: minimal LDAP queries, no GC/SMB, reduced noise for engagements with SIEM
- **Shadow Credentials** — detect write access to `msDS-KeyCredentialLink` on privileged objects

### v0.9.1
- **MITRE ATT&CK mapping** — technique badges on every finding with links to attack.mitre.org

### v0.9.2
- **--scope filtering** — limit enumeration to a specific OU: `--scope "OU=Finance,DC=corp,DC=local"`

### v0.9.3
- **Anonymous LDAP check** — detect if anonymous bind exposes more than RootDSE (security finding)
- **Username enumeration** — `adpath enum-users --wordlist users.txt` via Kerberos AS-REQ without credentials

### v1.0 — Public release
- README with demo GIF
- Blog post, r/netsec, conference presentations
