# adpath — Project Context

## Загальна інформація
- **Репо:** github.com/YakinAnd/adpath
- **Мова:** Go
- **Поточна версія:** v0.9.9
- **Ціль:** Open source CLI інструмент для AD security analysis. В майбутньому — платна Pro версія (модель Burp Suite, ~$300-500/рік)
- **Аудиторія:** Solo пентестери, MSSP, blue team, SMB компанії

---

## Архітектура

```
adpath/
├── cmd/adpath/main.go              # CLI entrypoint, Cobra команди
├── internal/
│   ├── ldap/
│   │   ├── client.go               # TCP підключення, bind, LDAP search з paging
│   │   └── enumerate.go            # Users, groups, computers enumeration + objectSid
│   ├── graph/
│   │   ├── model.go                # Node, Edge, Graph, AttackPath structs
│   │   ├── builder.go              # Будує граф з EnumerationResult
│   │   └── paths.go                # BFS пошук attack paths до Domain Admins
│   ├── analysis/
│   │   ├── kerberos.go             # Kerberoastable + AS-REP roastable detection
│   │   ├── acl.go                  # Dangerous ACL (GenericAll, WriteDACL, ForceChangePassword...)
│   │   ├── delegation.go           # Unconstrained, Constrained, RBCD delegation
│   │   ├── gpo.go                  # GPO enumeration + password policy audit
│   │   ├── adcs.go                 # ADCS ESC1-ESC13 detection
│   │   ├── trusts.go               # Domain/forest trust analysis + SID filtering
│   │   ├── shadow_credentials.go   # msDS-KeyCredentialLink write ACE detection
│   │   ├── ldap_security.go        # LDAP signing/channel binding/anonymous check
│   │   ├── audit.go                # AD Recycle Bin, auditingPolicy, MAQ
│   │   ├── mitre.go                # MITRE ATT&CK technique mapping (17 keys)
│   │   ├── hygiene.go              # Stale accounts, krbtgt age, LAPS, GPP
│   │   ├── adminsdholder.go        # AdminSDHolder orphans + custom ACEs
│   │   ├── protected_users.go      # Protected Users group membership check
│   │   ├── pso.go                  # Fine-Grained Password Policy (PSO)
│   │   ├── smb_signing.go          # SMB signing check via raw SMB2 Negotiate (port 445)
│   │   ├── sysvol.go               # SYSVOL audit via SMB2 — non-standard file detection
│   │   ├── laps_acl.go             # LAPS ACL — who can read ms-Mcs-AdmPwd
│   │   └── severity_counts.go      # SeverityCounts struct — shared by CLI + HTML for aligned counts
│   ├── spinner/
│   │   └── spinner.go              # CLI spinner — adpath logo rotating during analysis
│   ├── bloodhound/                 # BloodHound CE v5 JSON export
│   └── report/
│       ├── html.go                 # Single-file HTML звіт з D3.js графом; CountRiskTotals (exported)
│       ├── score.go                # RiskScore, CalculateRiskScore, SortedBreakdown, BreakdownEntry
│       └── executive.go           # TopIssue, BuildTopIssues, plural() helper
├── docs/                           # MkDocs Material documentation (private, workflow_dispatch)
│   └── assets/logo.svg             # SVG graph icon (7 spokes + center node)
└── mkdocs.yml                      # MkDocs config
```

## Залежності
```
github.com/go-ldap/ldap/v3
github.com/spf13/cobra
github.com/fatih/color
github.com/olekukonko/tablewriter
github.com/anthropics/anthropic-sdk-go  # --ai-report (Pro)
github.com/joho/godotenv
golang.org/x/net/proxy                  # --proxy SOCKS5
github.com/hirochachacha/go-smb2        # SYSVOL audit (SMB2 file listing)
```

---

## CLI команди

```bash
# Повний enumeration + attack paths (термінальний вивід)
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1

# З HTML звітом (opt-in через --report)
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 --report report.html

# Verbose: показати всі findings без truncation
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 --verbose

# Quiet: один рядок для CI/scripting
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 --quiet
# → RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium

# З фільтрацією scope, proxy, JSON export
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local" \
  --proxy socks5://127.0.0.1:1080 \
  --json ./bh_out/ \
  --report report.html

# Kerberoastable і AS-REP акаунти
./adpath kerberos -d corp.local -u admin -p Pass --dc 10.0.0.1

# Небезпечні ACL
./adpath acl -d corp.local -u admin -p Pass --dc 10.0.0.1

# Delegation checks
./adpath delegation -d corp.local -u admin -p Pass --dc 10.0.0.1

# GPO analysis + password policy
./adpath gpo -d corp.local -u admin -p Pass --dc 10.0.0.1

# ADCS ESC1-ESC8 detection
./adpath adcs -d corp.local -u admin -p Pass --dc 10.0.0.1

# Domain/forest trust analysis
./adpath trust -d corp.local -u admin -p Pass --dc 10.0.0.1

# Shadow Credentials (msDS-KeyCredentialLink)
./adpath shadow -d corp.local -u admin -p Pass --dc 10.0.0.1

# Audit Policy / Blue Team visibility
./adpath audit -d corp.local -u admin -p Pass --dc 10.0.0.1

# Автентифікація: Pass-the-Hash
./adpath enum -d corp.local -u admin --hash <NT_hash> --dc 10.0.0.1

# Автентифікація: Pass-the-Ticket
./adpath enum -d corp.local --ccache /tmp/admin.ccache --dc kingslanding.sevenkingdoms.local

# Тільки користувачі (targeted)
./adpath users -d corp.local -u admin -p Pass --dc 10.0.0.1

# Тільки комп'ютери (targeted, forest-wide GC)
./adpath computers -d corp.local -u admin -p Pass --dc 10.0.0.1

# Username enumeration без credentials (Kerberos AS-REQ)
./adpath kerb-enum -d corp.local --dc 10.0.0.1 --wordlist users.txt

# Stealth enumeration (мінімальні LDAP-запити, без GC, без ACL/ADCS/GPO)
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 --stealth

# SMB signing check (без credentials, тільки порт 445)
./adpath smb -d corp.local --dc 10.0.0.1

# Версія
./adpath version
```

---

## Ключові технічні деталі

### LDAP
- Автоматичний fallback 389 → 636 (LDAPS)
- Simple bind з двома форматами: UPN і NT
- Paging (1000 об'єктів за раз) для великих AD
- objectSid збирається для ACL маппінгу

### Graph
- In-memory граф (adjacency list), без Neo4j
- BFS від кожного вузла до Domain Admins
- Ліміт 200 attack paths, глибина до 10

### ACL аналіз
- Парсинг Windows Security Descriptor (raw bytes)
- Object ACE (0x05) з GUID для extended rights
- ForceChangePassword GUID: 00299570-246d-11d0-a768-00aa006e0529
- AddMember GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
- SID маппінг через objectSid атрибут

### Delegation
- Unconstrained: UAC біт 0x80000, виключає DC (0x2000)
- Constrained: msDS-AllowedToDelegateTo атрибут
- RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity атрибут
- Protocol Transition: UAC біт 0x1000000

### GPO
- Password policy через атрибути domain об'єкта
- GPO links через gPLink атрибут на OU і domain
- maxPwdAge конвертація: 100ns інтервали → дні

### HTML звіт
- Single file (CSS + D3.js inline)
- Tabs: Summary, Attack Paths, Graph, Kerberos, ACL, Delegation, GPO, ADCS, Trusts, Shadow Creds, LDAP Security, Audit, Exposure, Users, Groups, Computers, SYSVOL
- D3.js force-directed граф для attack paths
- Summary: findings chart по severity + категорії (числа з Go template, не JS)
- SVG adpath logo в header (7 spokes + center node)
- Light/dark theme toggle
- Global search через всі tabs
- MITRE ATT&CK badges (purple T-code, linked до attack.mitre.org) на section headers і per-finding rows
- Per-finding Exploit/Fix accordion з контекстними командами
- CVSS scores клікабельні: hover показує вектор, click копіює `CVSS:3.1/AV:N/...`; `data-copied` attr для zero-layout-shift flash
- Help icons (?) на всіх section titles з tooltips
- Collapsible sections (.chevron CSS rotate, не character swap)
- DCSync findings інтегровані в ACL grouped list (не окрема секція)
- LAPS Password Read Access секція в Computers tab
- Severity colors уніфіковані через CSS vars: `--text-sev-critical: #e53e3e`, `--text-sev-high: #dd6b20`, `--text-sev-medium: #d69e2e`
- Nav tabs: `overflow-x: auto` + `::after` spacer pseudo-element (fixes right-padding clip in scroll containers)
- Risk Score breakdown: `barWidthAbsolute` (absolute contribution, не % of cap) + `barColor` (% of own cap) + `SortedBreakdown()` (descending, deterministic); score column shows `30/30` format
- `CountRiskTotals` exported — CLI footer та HTML header використовують ідентичне counting

### CLI Spinner
- `internal/spinner` — 8-frame анімація, · обертається навколо ⊙ по годинниковій (N→NE→E→SE→S→SW→W→NW)
- 100ms/frame, 3-line ANSI block, ⊙ — purple, · — dim white
- Ховає/показує курсор (`\033[?25l` / `\033[?25h`)
- Запускається під час silent Analyze* фази в `runEnum`

### MITRE ATT&CK Mapping (`internal/analysis/mitre.go`)
- 17 ключів: kerberoasting, asrep, dcsync, acl_abuse, force_change_password, add_member, unconstrained_delegation, constrained_delegation, rbcd, adcs, gpo_abuse, shadow_credentials, ldap_relay, anon_ldap, trust_abuse, audit_defense, machine_account_quota
- `LookupTechniques(key MitreKey) []MitreTechnique`
- `MitreTechnique.URL()` → `https://attack.mitre.org/techniques/TXXXX/`

---

## Тестова лаба
- **GOAD-Light** на VMware Fusion
- Workspace: ~/Downloads/projects/GOAD/workspace/458cf1-goad-light-vmware/provider
- DC01: 192.168.56.10 (sevenkingdoms.local, admin/8dCT-DJjgScp)
- DC02: 192.168.56.11 (north.sevenkingdoms.local, jon.snow/iknownothing)
- SRV02: 192.168.56.22

```bash
# Запустити лабу
cd ~/Downloads/projects/GOAD/workspace/458cf1-goad-light-vmware/provider
vagrant resume

# Зупинити лабу
vagrant suspend

# Ansible provisioning
cd ~/Downloads/projects/GOAD
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ansible-playbook -i ~/Downloads/projects/GOAD/workspace/458cf1-goad-light-vmware/inventory ansible/build.yml
```

---

## Roadmap

### v0.1 ЗАВЕРШЕНО
- LDAP підключення і автентифікація
- Enumeration users/groups/computers
- BFS attack paths до Domain Admins
- CLI output з кольорами
- HTML звіт з D3.js графом

### v0.2 ЗАВЕРШЕНО
- kerberos команда — Kerberoastable/AS-REP detection
- acl команда — небезпечні ACL з bloodyAD hints

### v0.3 ЗАВЕРШЕНО
- delegation команда — Unconstrained/Constrained/RBCD
- gpo команда — GPO enumeration + password policy
- HTML звіт оновлено: нові вкладки + findings chart

### v0.4 ЗАВЕРШЕНО
- ✅ Pass-the-Hash (NTLM) — `--hash <NT_hash>` — протестовано на GOAD, працює
- ✅ Pass-the-Ticket (Kerberos ccache) — `--ccache <path>` — протестовано на GOAD, працює

#### Технічні деталі реалізації PTT:
- `KerberosGSSAPIClient` (`internal/ldap/kerberos_auth.go`) — реалізує go-ldap GSSAPIClient через gokrb5
- SPNEGO NegTokenInit обгортка AP-REQ (Windows вимагає SPNEGO, не raw KRB5)
- `saslConn` (`internal/ldap/sasl_conn.go`) — обгортка net.Conn для SASL wrap/unwrap
- Після GSSAPI bind Windows шифрує всі LDAP PDU через Kerberos session key
- **Race condition вирішено**: go-ldap's reader goroutine блокується в `c.Conn.Read()` до виклику `Activate()`. Рішення — 5ms deadline polling + читання в tmp buffer з перевіркою `active` ПІСЛЯ повернення даних. Якщо `active=true` — байти йдуть в `rawBuf` і обробляються як SASL frame.
- **Write bug вирішено**: `gssapi.NewInitiatorWrapToken` обчислює checksum з `SndSeqNum=0`. Для seqNum>0 checksum невалідний → DC reset. Фікс: будуємо `WrapToken` вручну з правильним seqNum перед `SetCheckSum`.

#### Ключові технічні деталі:
- Кредси: `--ccache <path> --dc FQDN` (DC треба FQDN, не IP)
- Якщо `--dc` IP — автоматичний reverse DNS lookup до FQDN
- `KRB5_CONFIG` env var → `/etc/krb5.conf` → мінімальний inline config
- Отримати TGT на macOS: `getTGT.py sevenkingdoms.local/administrator:'pass' -dc-ip 192.168.56.10`
- GOAD: DC01 = `kingslanding.sevenkingdoms.local` (192.168.56.10)
- Тест PTH: `--hash c66d72021a2d4744409969a581a1705e` (admin/8dCT-DJjgScp)
- `LdapServerIntegrity=0` на DC01 для тестування (дозволяє SASL без примусового signing)

### v0.5 ЗАВЕРШЕНО
- Forest-wide computer enumeration через Global Catalog (порт 3268)
  - Видно всі комп'ютери в усіх доменах лісу (не тільки поточний домен)
  - Запит до child domain DC напряму через DNS-резолвінг для повних атрибутів
  - Fallback на GC partial data якщо child domain недоступний
  - `LDAPComputer` тепер має: LAPS, OS Service Pack, description, whenCreated, domain label
- HTML звіт — Summary cards клікабельні (перехід до відповідної вкладки)
- HTML звіт — Accordion "🔴 Exploit / 🛡 Fix" для кожного файдінгу в ACL, Delegation, Kerberos, Attack Path вкладках
- HTML звіт — Exploit команди контекстно залежні (bloodyAD, getST.py, GetUserSPNs, Rubeus, hashcat)
- HTML звіт — D3.js граф перероблений: розмір ноди = кількість шляхів, tooltip при hover, підписи ребер, червоні стрілки для admin-шляхів, кнопка Reset Zoom
- HTML звіт — вкладка Computers розширена: Domain, LAPS, Version, Created, Description

### v0.6 ЗАВЕРШЕНО
Протестовано на GOAD-Light. Результати: 5 attack paths, 12 stale users, DCSync built-ins excluded.

- ✅ DCSync detection — перевірка обох replication GUID на domain object, виключення built-ins
- ✅ Hygiene module (`internal/analysis/hygiene.go`) — stale users (90d), stale computers (45d), krbtgt age + Golden Ticket risk, passwords in description
- ✅ PSO analysis (`internal/analysis/pso.go`) — Fine-Grained Password Policy (msDS-PasswordSettings), weak policy flags
- ✅ Extended attack paths — BFS до всіх 8 привілейованих груп (DA, EA, Backup Ops, Account Ops, Server Ops, Print Ops, DNSAdmins, GPO Creator Owners)
- ✅ HTML звіт — новий Hygiene tab, DCSync секція в ACL tab, TargetGroup badge на кожному attack path
- ✅ ldap: `SearchBase()` для PSO, `SearchGC()` для forest-wide запитів

**Залишились на v0.7 (з оригінального v0.6 TODO):**
- Username enumeration через Kerberos AS-REQ — `adpath kerb-enum --wordlist users.txt`
- RootDSE enumeration без bind (domain, forest, AD version)
- GPP passwords (MS14-025) — cpassword в SYSVOL\...\Groups.xml
- SMB signing перевірка — якщо не required → NTLM relay можливий
- LDAP signing + channel binding статус
- Protected Users group — чи DA/EA додані
- Summary finding grouping — 72 ACL findings → "1 Critical: ACL Privilege Escalation"
- Offline KB (`internal/kb/findings.go`) — map[finding_type]KBEntry
- LAPS readability — хто може читати ms-MCS-AdmPwd; машини без LAPS

### v0.7 ЗАВЕРШЕНО

- ✅ ADCS module (`internal/analysis/adcs.go`) — ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8 detection
  - ESC1: ENROLLEE_SUPPLIES_SUBJECT bitmask + auth EKU → Critical
  - ESC2: Any Purpose EKU або no EKUs
  - ESC3: Certificate Request Agent EKU + msPKI-RA-Signature == 0
  - ESC4: low-priv principal has WriteDACL/WriteOwner/GenericAll/GenericWrite on template object
  - ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
  - ESC7: low-priv has ManageCA (→ can enable ESC6) or ManageCertificates on CA
  - ESC8: Web Enrollment hint (no HTTP probe)
  - `adpath adcs` команда — повний вивід + certipy next steps для кожного ESC типу
  - `adpath enum` — summary ADCS без next steps (щоб не засмічувати вивід)
- ✅ LAPS detection — `NoLAPSComputers` у Hygiene/Exposure module
- ✅ GPP/MS14-025 detection — CSE GUIDs в gPCMachineExtensionNames/gPCUserExtensionNames (без SMB)
- ✅ HTML звіт — ADCS tab (CA table, ESC6, template findings з Exploit/Fix accordion)
- ✅ HTML звіт — Exposure tab (LAPS section з таблицею машин без LAPS)
- ✅ HTML звіт — Users tab розширено: Email + Privileged Groups колонки
- ✅ HTML звіт — Finding grouping в ACL tab (⊞ Group кнопка)
- ✅ HTML звіт — Section tooltips (? hover) на всіх major секціях
- ✅ HTML звіт — Accordion arrow fix (▶/▼ анімація)
- ✅ Rename: HYGIENE → EXPOSURE скрізь (CLI + HTML)
- ✅ CLI: next steps для ESC1-ESC8 з контекстними certipy командами
- ✅ CLI banner відновлено (великі літери ADPATH)
- ✅ -H/--hashes flag на всіх командах

### v0.8.1 ЗАВЕРШЕНО

- ✅ Protected Users group (`internal/analysis/protected_users.go`) — перевірка DA/EA/Schema Admins в Protected Users; виводить список privileged accounts що не захищені (NTLM/RC4/delegation можливі)
- ✅ RootDSE enumeration — `client.QueryRootDSE()` зчитує domain/forest/DC functional level/responding DC без auth; показується в CLI при `enum`
- ✅ AdminSDHolder (`internal/analysis/adminsdholder.go`) — orphaned adminCount=1 (не в прив. групі), custom ACEs на CN=AdminSDHolder (persistence backdoor)
- ✅ GPO ACL (`internal/analysis/gpo.go`) — реальний парсинг nTSecurityDescriptor кожного GPO через SD control; low-priv write = High, GPO linked to DC OU = Critical
- ✅ Global search в HTML — рядок над табами, шукає по всіх tab-panes, підсвічує matches (`<mark class="gs-match">`), показує кількість per-tab, автоматично переходить на tab з найбільшою кількістю matches

### v0.8.2 ЗАВЕРШЕНО

- ✅ **Trust analysis** (`internal/analysis/trusts.go`) — enumeration `trustedDomain` об'єктів, SID filtering статус (ON/OFF/Internal), trust direction/type, Foreign Security Principals в привілейованих групах, `adpath trust` команда + HTML Trusts tab
  - Within-forest trusts (parent-child, tree-root) — показуються як "Internal" (SID filtering OFF там нормально)
  - Зовнішні трасти без SID filtering → High; bidirectional external без SID filter → Critical; RC4 → Low
  - Next steps: ticketer.py SID history abuse команди контекстно для кожного ризикового трасту
  - Протестовано на GOAD-Light: north.sevenkingdoms.local → Bidirectional, AD (Uplevel), Internal, Info ✅

### v0.9 TODO
- ✅ JSON export — `--json` flag (перейменовано з --bloodhound), сумісність з BH CE v5 (users/groups/computers/domains.json)
- ✅ Audit Policy / Blue Team — `internal/analysis/audit.go`: AD Recycle Bin status, legacy auditingPolicy attribute парсинг, ms-DS-MachineAccountQuota; `adpath audit` команда; HTML Audit tab; findings: High якщо audit не налаштовано, Medium якщо Recycle Bin відключений або MAQ > 0
- Username enumeration через Kerberos AS-REQ — `adpath kerb-enum --wordlist users.txt`
- ✅ LDAP signing + channel binding статус — `internal/analysis/ldap_security.go`: перевірка plain vs LDAPS, supportedCapabilities OID (1.2.840.113556.1.4.1791), SASL механізми; HTML tab "LDAP Security"; summary рядок в enum
- SMB signing статус — окрема задача (ADP-14), потребує SMB2 Negotiate парсинг
- ESC9, ESC10, ESC11, ESC13 — залишились не реалізовані
- ✅ Enrollment rights перевірка як qualifier для ESC1 — DACL парсинг enrollment GUID, ESC1 Critical тільки якщо low-priv може записатись; інакше Medium
- ✅ **SOCKS5 proxy** — `--proxy socks5://127.0.0.1:1080` на всіх командах; DNS резолвиться на proxy-стороні; замінено LDAP dialer через `golang.org/x/net/proxy`; `--proxy + --ccache` — заблоковано з помилкою (PTT не підтримується через proxy)
- ✅ **Stealth mode** — `--stealth` flag на `adpath enum`: мінімальна кількість LDAP запитів (тільки users+groups), без GC (порт 3268), без ACL/Delegation/GPO/ADCS/PSO/ProtectedUsers/AdminSDHolder/ShadowCredentials/Hygiene/LDAPSecurity/Audit. Завжди запускається: RootDSE, Kerberos, Trusts, Graph/AttackPaths. STEALTH SUMMARY в кінці CLI.
- ✅ **Shadow Credentials** — `internal/analysis/shadow_credentials.go`: DACL парсинг msDS-KeyCredentialLink (GUID 5b47d60f-...) на DA/EA/DC об'єктах; окрема команда `adpath shadow`; next steps з pywhisker/certipy; HTML tab Shadow Creds з таблицею findings
- ✅ **HTML report fixes (v0.9.0)** — Shadow Credentials tab в HTML звіті; EnrollableBy badge в ADCS tab для ESC1; виправлено severity badge (Medium більше не показує badge-critical)

### v0.9.1 ЗАВЕРШЕНО

- ✅ **MITRE ATT&CK mapping** (`internal/analysis/mitre.go`) — 17 ключів, purple T-code badges в HTML звіті на section headers і per-row (ACL по типу права, Delegation по типу делегування). Всі badges клікабельні → attack.mitre.org.

### v0.9.2 ЗАВЕРШЕНО

- ✅ **--scope фільтрація** — `--scope "OU=Finance,DC=corp,DC=local"` підмінює base DN для всіх LDAP queries; доступно на всіх командах (enum, acl, kerberos, shadow, adcs, delegation, gpo, trust)

### v0.9.3 ЗАВЕРШЕНО

- ✅ **Anonymous LDAP check** — `ProbeAnonymousRead()` перевіряє чи anonymous bind може читати AD objects (не тільки RootDSE); `LDAPSecurityResult.AnonReadEnabled` + finding "Anonymous LDAP read enabled" (Medium); CLI при anonymous bind показує "RootDSE ✓ readable" + підказку для повного enumeration

### v0.9.4 ЗАВЕРШЕНО

- ✅ **CLI Spinner** (`internal/spinner`) — adpath logo обертається під час silent analysis фази в `runEnum`; 8-frame, 100ms/frame, ⊙ purple + · dim white
- ✅ **HTML report — SVG logo** — adpath graph icon у header (7 outer nodes + spokes + center); light/dark theme adaptive
- ✅ **--json flag** — перейменовано з --bloodhound; docs оновлено; BH CE v5 сумісність задокументована
- ✅ **MkDocs Material docs** — повна документація на `docs/`; auto-deploy вимкнено (workflow_dispatch); приватна до публічного релізу
- ✅ **MITRE ATT&CK mapping** (`internal/analysis/mitre.go`) — 17 ключів, purple T-code badges в HTML звіті

### v0.9.5 ЗАВЕРШЕНО

- ✅ **`adpath users`** — targeted enumeration тільки юзерів; зведення + colored table (AS-REP червоний, adminCount жовтий, disabled dim); колонки: username, display name, enabled, adminCount, AS-REP, pwd-never-expires, last logon, SPN count
- ✅ **`adpath computers`** — targeted enumeration тільки комп'ютерів; forest-wide GC (як `enum`); зведення LAPS/delegation + таблиця: hostname, OS (з версією), enabled; dynamic column widths
- ✅ **CLI table improvements** — ADCS vulnerable templates і Protected Users findings тепер відображаються у вирівняних таблицях з заголовками та separator line
- ✅ **Bug fix** — `OBJECTS COLLECTED` і `QUICK FINDINGS` виводяться тільки в `enum`, не в targeted командах (acl, shadow, trust тощо); `EnumerateAll()` більше не друкує автоматично

### v0.9.6 ЗАВЕРШЕНО

- ✅ **`adpath kerb-enum`** — username enumeration без credentials через Kerberos AS-REQ (TCP порт 88); класифікація відповідей KDC: EXISTS / AS-REP roastable / DISABLED / EXPIRED; `internal/kerberos/enumusers.go`; wordlist формат (# коментарі, пусті рядки); not-found results приховані за замовчуванням
- ✅ **`--stealth` flag** на `adpath enum` — мінімальні LDAP-запити: тільки users+groups (без комп'ютерів, без GC); пропускаються: ACL, Delegation, GPO, ADCS, PSO, ProtectedUsers, AdminSDHolder, ShadowCredentials, Hygiene, LDAPSecurity, Audit; завжди виконується: RootDSE, Kerberos, Trusts, Graph/AttackPaths; STEALTH SUMMARY в кінці CLI

### v0.9.8 ЗАВЕРШЕНО

- ✅ **ADCS ESC9** — `CT_FLAG_NO_SECURITY_EXTENSION` (0x00080000) в `msPKI-Enrollment-Flag`; сертифікат без SID-binding; потребує GenericWrite для зміни UPN жертви; Severity: Medium; next steps: bloodyAD UPN change → certipy req → certipy auth
- ✅ **ADCS ESC11** — ICPR/DCOM enrollment relay (CA-level finding, як ESC8 але через RPC/DCOM); Severity: High; next steps: certipy relay -target 'rpc://...'
- ✅ **ADCS ESC13** — issuance policy OID linked to privileged group via `msDS-OIDToGroupLink`; queries `CN=OID,CN=Public Key Services`; Critical якщо low-priv може записатись; next steps: certipy req + certipy auth

### v0.9.7 ЗАВЕРШЕНО

- ✅ **`adpath smb`** — SMB signing check через raw SMB2 Negotiate (TCP/445); читає SecurityMode поле з відповіді; High якщо signing не required, Medium якщо enabled але не required; summary line в `adpath enum`; секція в HTML LDAP Security tab; без credentials — тільки порт 445; `internal/analysis/smb_signing.go`

### v0.9.9 ЗАВЕРШЕНО

- ✅ **HTML report redesign** — великий UI overhaul (`internal/report/html.go`):
  - ACL tab тепер згрупований за замовчуванням; MITRE badges тільки на group headers
  - DCSync merged into ACL grouped list (`data-right="DCSync"` acl-card, не окрема секція)
  - Exposure tab: 8 collapsible секцій з count + severity badges
  - "Expand All / Collapse All" кнопки на ACL і Exposure tabs
  - Tables capped at 100 rows; D3 graph capped at 80 nodes (scale fix для великих AD)
  - Unified severity colors: CSS vars `--text-sev-critical/high/medium` скрізь
  - Yes/No badges → plain colored text (`.txt-yes`, `.txt-no`, `.txt-warn`)
  - Collapsible section chevrons: CSS rotate замість character swap
  - Column resize: видимий separator `th { border-right: 1px solid var(--border) }`
  - Findings Overview chart: числа з Go template (`{{.TotalCritical}}`), не JS
  - Users table: видалено колонку "Privileged Groups"; привілейовані рядки підсвічені `.row-priv` (red left border)
- ✅ **Global search overhaul** — clickable tab buttons в результатах; Enter → navigate; auto-expand collapsed sections; Clear кнопка прихована коли порожньо
- ✅ **CLI Risk Summary** — рахує criticals/highs/mediums по всіх модулях; загальний рейтинг з кольором
- ✅ **Help icons** — `?` з tooltip на всіх section titles (Attack Path Graph, Users, Groups, Computers, krbtgt, Description Notes, No LAPS, PSO, Password Policy, Certificate Authorities + всі попередні)
- ✅ **CVSS click-to-copy** — `CVSSVector string` додано до всіх finding structs (14 типів в 10 файлах); click копіює `CVSS:3.1/AV:N/...`; hover показує вектор
- ✅ **SYSVOL audit** (`internal/analysis/sysvol.go`) — SMB2/NTLM підключення; рекурсивний обхід SYSVOL без читання вмісту; виявляє GPP XML, executables, archives, scripts поза Scripts\; новий SYSVOL tab в HTML; залежність `go-smb2`
- ✅ **LAPS ACL detection** (`internal/analysis/laps_acl.go`) — динамічний resolve schemaIDGUID ms-Mcs-AdmPwd зі схеми; парсинг nTSecurityDescriptor кожного LAPS-комп'ютера; виявляє GenericAll/GenericRead/ReadProperty(ms-Mcs-AdmPwd)/ReadProperty(all)/WriteDACL/WriteOwner; секція "LAPS Password Read Access" в Computers tab

### P3 UI fixes (post-v0.9.9, на гілці feat/adp-72-73)

- ✅ **ZgotmplZ fix** — `GradeColor()` повертає `template.CSS` → grade letter "F" тепер яскраво-червоний
- ✅ **Exploit commands** — `pathExploitData` struct з `Description` (prose, без copy) + `Commands []string` (реальні shell-команди з copy button) + `Fix` + `AuditCmd`; copy button тільки на виконуваних командах
- ✅ **ADCS duplicate ESC** — demo template names виправлені: `UserTemplate`, `WebServer`
- ✅ **Version sync** — header logo `v{{.Version}}`
- ✅ **plural() helper** — прибрані всі `(s)` суфікси в executive.go і html.go
- ✅ **Executive quick stats** — замінені дублюючі findings-counters на environment size (Users/Computers/Groups/KrbtgtAge)
- ✅ **Policy anchor scroll** — `TopIssue.Anchor` field; "Weak password policy" View button scrolls до `#policy-section`
- ✅ **SYSVOL tab trailing space** — прибраний
- ✅ **Risk Score breakdown bars** — `barColor/barWidth/capFor` helpers: колір залежить від % заповнення (critical≥75%, high≥40%, medium<40%)
- ✅ **Print CSS** — `:not(:first-of-type)` page-break (Executive+Summary разом, Paths з нової сторінки)
- ✅ **GPCO is-admin node** — `isPrivilegedGroup()` FuncMap; Group Policy Creator Owners отримує червоний бордер у path chain
- ✅ **UI polish** — Attack Path severity badges уніфіковані (`badge-*`); DangerousACLCount включає DCSync; CVSS copy без layout shift; "Unconstrained Delegation" повна назва колонки; жирний лічильник прибрано з ACL group headers
- ✅ **Nav tab overflow** — `padding: 0 0 0 28px` + `.nav::after { min-width: 28px }` spacer pseudo-element (padding-right ігнорується в overflow scroll containers на Chrome/Safari)

### P4 CLI improvements (на гілці feat/adp-72-73)

- ✅ **Single source of truth для severity counts** — `report.CountRiskTotals()` (exported) використовується і CLI footer, і HTML header; рахує однаковий набір модулів (ACL, Kerberos, ADCS, Delegation, Trust, Shadow, LDAP, SMB, GPO, AdminSDHolder); attack paths більше не рахуються як "critical" в severity totals (узгоджено з HTML)
- ✅ **Risk score в CLI footer** — `RISK CRITICAL (F · 83/100)` замість просто `CRITICAL`; `riskVerdict(RiskScore)` маппить grade → verbal label
- ✅ **ACL grouped по principal** — `addGroup()` будує `map[principal]→{rights: map[right]→[]targets}`; principal виводиться один раз, права з відступом:
  ```
  [!!]  lord.varys
          WriteDACL    → Administrators, Print Operators
          GenericAll   → Administrators, Print Operators
  ```
- ✅ **Shadow Creds grouped по principal** — аналогічно ACL; `(detection only — exploit: pywhisker / certipy shadow)` підказка в заголовку
- ✅ **Domain summary one-liner** — перед USERS/COMPUTERS секціями: `sevenkingdoms.local · 16 users · 3 computers · 55 groups · 4 admins`; рядок 2: `5 attack paths · 72 ACL findings · 1 ADCS · krbtgt: 51d`
- ✅ **Timing footer** — `enumeration completed in 12.3s` після всіх секцій
- ✅ **`--quiet` flag** — одна лінія `RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium`; banner, connection messages, REPORT section приховані; для CI/grep
- ✅ **`--verbose` flag** — вимикає per-section truncation (5-item limit); показує всі findings; без `-v` shorthand (щоб не конфліктувало з cobra root `-v`)
- ✅ **Stale threshold footnotes** — "CIS: 90d threshold" / "CIS: 45d threshold" поруч із stale рядками
- ✅ **`adpath version` command** — `rootCmd.Version` прибрано щоб cobra не дублював `-v/--version` у Flags; `version` тільки як subcommand

### P5 Risk bars (на гілці feat/adp-72-73)

- ✅ **Proportional bars** — `barWidthAbsolute(score int) int`: ширина відносно найбільшого cap (30 = Attack Paths); score 30 → 100%, score 5 → ~17%; shadow creds (9pts) більше не виглядає так само як attack paths (30pts)
- ✅ **barColor оновлений** — приймає `(score int, cat string)` замість `(score, cap int)`; колір кодує % від власного cap категорії (≥75% → red, ≥40% → orange, <40% → yellow)
- ✅ **SortedBreakdown()** — `RiskScore.SortedBreakdown() []BreakdownEntry` повертає відсортований slice (desc by value, stable тай-брейк за name); map iteration більше не дає рандомний порядок між запусками
- ✅ **Score format** — `30/30`, `9/10`, `5/15` (value/cap) в правій колонці; `tabular-nums` для вирівнювання
- ✅ **Subtitle** — "Bar length = absolute points contributed. Color = % of category cap." під заголовком секції

### P6 CLI fixes (на гілці feat/adp-72-73)

- ✅ **Quiet mode повний** — `printBanner()` пропускається; REPORT секція мовчить; залишається тільки один RISK рядок
- ✅ **Word-aware truncation** — `truncateTargets(targets []string, maxLen int) string` → `+N more` замість `Replic...`; ніколи не ріже посередині слова; verbose показує всі targets без обрізання
- ✅ **Empty target filter** — ACL findings з порожнім TargetName (unresolved SID) відфільтровуються на двох рівнях: при grouping (`addGroup`) і при render; principals де всі targets порожні — пропускаються цілком

### v1.0 ПУБЛІЧНИЙ РЕЛІЗ
- README з GIF демо
- Стаття, пости на r/netsec, UISGCON

---

## Як використовувати цей файл

На початку кожної нової сесії з Claude — скинь вміст цього файлу в чат.
Після кожної версії — оновлюй файл і пушь в репо.

*Останнє оновлення: P6 (feat/adp-72-73) — CLI quiet/verbose/truncation fixes, P5 risk bars, P4 CLI improvements, P3 HTML UI polish.*