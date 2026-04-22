# adpath — Project Context

## Загальна інформація
- **Репо:** github.com/YakinAnd/adpath
- **Мова:** Go
- **Поточна версія:** v0.9.4
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
│   │   └── gpo.go                  # GPO enumeration + password policy audit
│   └── report/
│       └── html.go                 # Single-file HTML звіт з D3.js графом
```

## Залежності
```
github.com/go-ldap/ldap/v3
github.com/spf13/cobra
github.com/fatih/color
github.com/olekukonko/tablewriter
```

---

## CLI команди

```bash
# Повний enumeration + attack paths + HTML звіт
./adpath enum -d corp.local -u admin -p Pass --dc 10.0.0.1 --report report.html

# Kerberoastable і AS-REP акаунти
./adpath kerberos -d corp.local -u admin -p Pass --dc 10.0.0.1

# Небезпечні ACL
./adpath acl -d corp.local -u admin -p Pass --dc 10.0.0.1

# Delegation checks
./adpath delegation -d corp.local -u admin -p Pass --dc 10.0.0.1

# GPO analysis + password policy
./adpath gpo -d corp.local -u admin -p Pass --dc 10.0.0.1

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
- Tabs: Summary, Attack Paths, Graph, Kerberos, ACL, Delegation, GPO, Users, Groups, Computers
- D3.js force-directed граф для attack paths
- Summary: findings chart по severity + категорії

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
- Username enumeration через Kerberos AS-REQ — `adpath enum-users --wordlist users.txt`
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
- ✅ BloodHound JSON export — `--bloodhound` flag, сумісність з BH CE v5 (users/groups/computers/domains.json)
- ✅ Audit Policy / Blue Team — `internal/analysis/audit.go`: AD Recycle Bin status, legacy auditingPolicy attribute парсинг, ms-DS-MachineAccountQuota; `adpath audit` команда; HTML Audit tab; findings: High якщо audit не налаштовано, Medium якщо Recycle Bin відключений або MAQ > 0
- Username enumeration через Kerberos AS-REQ — `adpath enum-users --wordlist users.txt`
- ✅ LDAP signing + channel binding статус — `internal/analysis/ldap_security.go`: перевірка plain vs LDAPS, supportedCapabilities OID (1.2.840.113556.1.4.1791), SASL механізми; HTML tab "LDAP Security"; summary рядок в enum
- SMB signing статус — окрема задача (ADP-14), потребує SMB2 Negotiate парсинг
- ESC9, ESC10, ESC11, ESC13 — залишились не реалізовані
- ✅ Enrollment rights перевірка як qualifier для ESC1 — DACL парсинг enrollment GUID, ESC1 Critical тільки якщо low-priv може записатись; інакше Medium
- ✅ **SOCKS5 proxy** — `--proxy socks5://127.0.0.1:1080` на всіх командах; DNS резолвиться на proxy-стороні; замінено LDAP dialer через `golang.org/x/net/proxy`; `--proxy + --ccache` — заблоковано з помилкою (PTT не підтримується через proxy)
- **Stealth mode** — `--stealth` flag: мінімальна кількість LDAP запитів, без SMB enumeration, без forest-wide GC queries, без додаткових round-trips. Важливо для реальних engagements де є SIEM/detection. Пріоритет: тільки критичні знахідки, менше шуму в логах.
- ✅ **Shadow Credentials** — `internal/analysis/shadow_credentials.go`: DACL парсинг msDS-KeyCredentialLink (GUID 5b47d60f-...) на DA/EA/DC об'єктах; окрема команда `adpath shadow`; next steps з pywhisker/certipy; HTML tab Shadow Creds з таблицею findings
- ✅ **HTML report fixes (v0.9.0)** — Shadow Credentials tab в HTML звіті; EnrollableBy badge в ADCS tab для ESC1; виправлено severity badge (Medium більше не показує badge-critical)

### v0.9.1 TODO
- **MITRE ATT&CK mapping** — автоматичні теги до кожного finding: "T1558.003 — Kerberoasting", "T1484.001 — GPO modification" і т.д. CISO і compliance teams люблять цю мову. В HTML звіті — badge біля кожного finding з посиланням на attack.mitre.org. Подумати над посиланнями на mitigation.

### v0.9.2 ЗАВЕРШЕНО

- ✅ **--scope фільтрація** — `--scope "OU=Finance,DC=corp,DC=local"` підмінює base DN для всіх LDAP queries; доступно на всіх командах (enum, acl, kerberos, shadow, adcs, delegation, gpo, trust)

### v0.9.3 ЗАВЕРШЕНО

- ✅ **Anonymous LDAP check** — `ProbeAnonymousRead()` перевіряє чи anonymous bind може читати AD objects (не тільки RootDSE); `LDAPSecurityResult.AnonReadEnabled` + finding "Anonymous LDAP read enabled" (Medium); CLI при anonymous bind показує "RootDSE ✓ readable" + підказку для повного enumeration
- **Username enumeration via Kerberos AS-REQ** — `adpath enum-users --wordlist users.txt`: без пароля, тільки доступ до мережі. Помилка `PRINCIPAL_UNKNOWN` vs `PREAUTH_REQUIRED` — дозволяє підтвердити існування акаунта

### v1.0 ПУБЛІЧНИЙ РЕЛІЗ
- README з GIF демо
- Стаття, пости на r/netsec, UISGCON

---

## Як використовувати цей файл

На початку кожної нової сесії з Claude — скинь вміст цього файлу в чат.
Після кожної версії — оновлюй файл і пушь в репо.

*Останнє оновлення: v0.9.4 — Audit Policy / Blue Team (adpath audit, AD Recycle Bin, auditingPolicy parse, MAQ check, HTML Audit tab).*