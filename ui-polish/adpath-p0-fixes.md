# adpath HTML report — P0 critical fixes (pre-release blockers)

Ти працюєш над `internal/report/html.go` в проекті adpath. Зроби наступні фікси — це блокери перед публічним релізом v1.0. Файл генерує self-contained HTML звіт з вбудованим CSS і JS.

## Контекст
- Звіт — single HTML file, dark/light theme через CSS variables
- Шаблон в `internal/report/html.go`, темплейтні дані з `internal/graph` і `internal/analysis`
- Поточна версія: v0.9.8

## Завдання

### 1. Додати відсутні CSS variables `--badge-high-*` в dark theme

В блоці `html[data-theme="dark"] { ... }` після рядка `--badge-crit-bg: #742a2a;   --badge-crit-txt: #e53e3e;` додай:

```css
--badge-high-bg: #7b2d12;   --badge-high-txt: #fdba74;
```

Зараз `.badge-high` падає на inline fallback значення які не консистентні з рештою dark palette. Перевір що в light theme `--badge-high-bg` / `--badge-high-txt` вже визначені (мають бути).

### 2. Підняти контраст severity текстів (WCAG AA)

Знайди в CSS:
```css
.sev-critical { color: #e53e3e; font-weight: 700; }
.sev-high     { color: #f6ad55; font-weight: 600; }
.sev-medium   { color: var(--sev-medium); }
```

Заміни на theme-aware версію через CSS variables. Спочатку додай у `html[data-theme="dark"]`:
```css
--text-sev-critical: #fc8181;
--text-sev-high:     #fbbf24;
--text-sev-medium:   #fde68a;
```

У `html[data-theme="light"]`:
```css
--text-sev-critical: #c53030;
--text-sev-high:     #c2410c;
--text-sev-medium:   #92400e;
```

Потім заміни класи на:
```css
.sev-critical { color: var(--text-sev-critical); font-weight: 700; }
.sev-high     { color: var(--text-sev-high); font-weight: 600; }
.sev-medium   { color: var(--text-sev-medium); }
```

### 3. Виправити generic exploit text для не-DA шляхів

В `internal/graph/paths.go` (або де генерується `Exploit` поле для path findings) зараз для **всіх** privileged groups виводиться:
```
Account has transitive DA membership — existing credentials grant DA access (net use \\DC\IPC$ or WinRM)
```

Це невірно для:
- `Group Policy Creator Owners` — escalation через створення/модифікацію GPO
- `Account Operators` / `Backup Operators` / `Print Operators` / `Server Operators` — окремі техніки
- `Enterprise Admins` — це DA рівня, але формулювання "transitive DA" неточне (це EA)

Розгалуж exploit/fix text по target group. Створи map або switch-case:

```go
type PathExploitTemplate struct {
    Exploit string
    Fix     string
}

var pathExploitsByTarget = map[string]PathExploitTemplate{
    "Domain Admins": {
        Exploit: "Transitive DA membership — credentials grant full domain compromise via net use \\\\DC\\IPC$, WinRM, or DCSync",
        Fix:     "Enforce least-privilege; remove transitive paths; apply AD Tiered Administration. Audit: Get-ADGroupMember 'Domain Admins' -Recursive",
    },
    "Enterprise Admins": {
        Exploit: "Transitive EA membership — forest-wide compromise; can modify schema and enterprise-level objects",
        Fix:     "EA should be empty in steady-state; populate only for forest-level changes. Audit: Get-ADGroupMember 'Enterprise Admins' -Recursive",
    },
    "Group Policy Creator Owners": {
        Exploit: "Can create/modify GPOs linked to OUs/domain → SYSTEM on any joined machine via scheduled task or startup script in GPO",
        Fix:     "Remove non-admins from GPCO; restrict GPO creation; monitor SYSVOL for new GPOs. Audit: Get-GPOReport -All -ReportType XML",
    },
    "Account Operators": {
        Exploit: "Can create/modify/delete users and groups (except protected) → password reset on privileged accounts not in AdminSDHolder",
        Fix:     "Empty Account Operators in modern AD; use delegated OUs with specific permissions instead",
    },
    "Backup Operators": {
        Exploit: "SeBackupPrivilege/SeRestorePrivilege on DC → dump NTDS.dit via diskshadow + robocopy → DCSync offline",
        Fix:     "Backup Operators on DCs is equivalent to DA; restrict to dedicated backup tier (T0)",
    },
    "Server Operators": {
        Exploit: "Can manage services on DCs → install service running as SYSTEM → DA escalation",
        Fix:     "Empty Server Operators; use JEA (Just Enough Admin) for delegated server management",
    },
    "Print Operators": {
        Exploit: "SeLoadDriverPrivilege → load malicious kernel driver on DC → SYSTEM",
        Fix:     "Empty Print Operators; manage printers via dedicated service accounts with minimal rights",
    },
    "DnsAdmins": {
        Exploit: "DLL injection via dnscmd ServerLevelPluginDll → SYSTEM on DC",
        Fix:     "Restrict DnsAdmins; monitor changes to ServerLevelPluginDll registry value",
    },
}
```

Fallback (якщо target не в map) залишай поточний generic text.

### 4. Додати print stylesheet

Перед закриваючим `</style>` в HTML темплейті додай:

```css
@media print {
  /* Force light theme for printing */
  html { background: #fff !important; color: #000 !important; }
  html[data-theme="dark"] {
    --bg-page: #fff; --bg-card: #fff; --bg-hover: #f5f5f5;
    --bg-code: #f5f5f5; --bg-code-inner: #eee; --bg-grouped: #f9f9f9;
    --bg-input: #fff; --border: #ccc;
    --text-main: #000; --text-muted: #555; --text-secondary: #333; --text-subtle: #888;
    --accent: #1a56db; --accent-domain: #c05621; --color-ok: #166534;
  }
  /* Hide interactive elements */
  .nav, .global-search-wrap, #theme-toggle, .xp-btns, .filter-bar,
  .show-all-btn, #gs-clear, #graph-tooltip { display: none !important; }
  /* Expand all collapsible content */
  .tab-pane { display: block !important; page-break-before: always; }
  .tab-pane:first-of-type { page-break-before: auto; }
  .acc-body, .exp-body, .group-body { display: block !important; }
  /* Avoid breaking cards across pages */
  .path-card, .acl-card, .card, .exp-section { page-break-inside: avoid; }
  /* Remove shadows/animations */
  * { box-shadow: none !important; transition: none !important; }
  /* Section page breaks */
  h2.section-title { page-break-after: avoid; }
  /* Ensure URLs are visible */
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.7em; color: #666; }
}
```

### 5. Risk Summary в header

В header (поряд з theme toggle) додай агреговану панель Critical/High/Medium counts. У шаблоні:

```html
<div class="header-risk" style="margin-left:auto;margin-right:60px;display:flex;gap:8px;align-items:center">
  {{if gt .CriticalCount 0}}<span class="badge badge-critical" style="font-size:0.78rem">{{.CriticalCount}} Critical</span>{{end}}
  {{if gt .HighCount 0}}<span class="badge badge-high" style="font-size:0.78rem">{{.HighCount}} High</span>{{end}}
  {{if gt .MediumCount 0}}<span class="badge badge-medium" style="font-size:0.78rem">{{.MediumCount}} Medium</span>{{end}}
  {{if and (eq .CriticalCount 0) (eq .HighCount 0) (eq .MediumCount 0)}}<span class="badge badge-ok">Clean</span>{{end}}
</div>
```

В Go додай у report struct поля `CriticalCount`, `HighCount`, `MediumCount` і обчислюй їх агрегацією findings зі всіх модулів (paths + acl + kerberos + adcs + ldapsec + audit + policy).

## Перевірка

Після всіх змін:
1. `go build ./...` має пройти без помилок
2. Згенеруй тестовий звіт: `./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html`
3. Відкрий в браузері, перевір:
   - dark/light toggle працює (badges не мерехтять, severity тексти читабельні)
   - в header видно Critical/High counts
   - Path 5 (GPCO) має тепер релевантний exploit text про GPO, не про DA
   - Ctrl+P показує clean light-theme preview без navigation
4. Закомить з повідомленням: `feat(report): improve UI accessibility, contrast, and exploit accuracy (P0)`
