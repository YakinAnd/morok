# adpath — Project Context

## Загальна інформація
- **Репо:** github.com/YakinAnd/adpath
- **Мова:** Go
- **Поточна версія:** v0.3.0
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

### v0.4 НАСТУПНИЙ
- NTLM / Kerberos auth (ccache підтримка)
- Lateral movement mapping

### v0.5 Report версія
- Покращений HTML звіт
- JSON export

### v1.0 ПУБЛІЧНИЙ РЕЛІЗ
- README з GIF демо
- Стаття, пости на r/netsec, UISGCON

---

## Як використовувати цей файл

На початку кожної нової сесії з Claude — скинь вміст цього файлу в чат.
Після кожної версії — оновлюй файл і пушь в репо.

*Останнє оновлення: v0.3.0*