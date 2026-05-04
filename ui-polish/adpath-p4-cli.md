# adpath CLI output — P4 improvements

P3 готовий до застосування на HTML report. Тепер CLI output (`adpath enum`) — той самий scan, той самий backend, але окремий вивідний шар. При перегляді screenshot v0.9.9 знайдено баги і UX-можливості.

## Контекст
- Файл: `internal/cli/summary.go` (або де живе `printEnumSummary` / `renderCLI`)
- Конфіг кольорів: ймовірно `internal/cli/colors.go` чи аналогічно
- Lab: GOAD / sevenkingdoms.local
- `--json` flag вже існує — пропускаємо
- v0.9.9 вже надрукована в logo header, версію не чіпай

---

## 🔴 BLOCKER #1: Counts CLI vs HTML не сходяться

### Проблема

Той самий scan того ж домена — два різних висновки:

**CLI footer:**
```
RISK   CRITICAL    [!!] 42 critical    [!] 40 high    [-] 1 medium
```

**HTML header (раніше згенерований звіт):**
```
38 Critical · 40 High · 1 Medium
```

42 vs 38 critical — 4 finding'ів губляться десь по дорозі. Це **серйозний bug довіри** до тулзи: різні представлення одних і тих же даних дають різні цифри.

Можливі причини:
- CLI рахує findings до filtering by display threshold, HTML після
- HTML rolling-up duplicate ACL findings (3 rights × 1 user × 1 target = 1 finding замість 3), CLI рахує raw
- Один з виводів пропускає певну категорію (наприклад AdminSDHolder findings — в CLI 1, в HTML 0?)

### Фікс

#### Крок 1. Single source of truth

Створи (якщо немає) `internal/analysis/severity_counts.go`:

```go
package analysis

type SeverityCounts struct {
    Critical int
    High     int
    Medium   int
    Low      int
    Info     int
}

func (s SeverityCounts) Total() int {
    return s.Critical + s.High + s.Medium + s.Low + s.Info
}

func (s SeverityCounts) Add(other SeverityCounts) SeverityCounts {
    return SeverityCounts{
        Critical: s.Critical + other.Critical,
        High:     s.High + other.High,
        Medium:   s.Medium + other.Medium,
        Low:      s.Low + other.Low,
        Info:     s.Info + other.Info,
    }
}

// CountFindings counts findings by severity from a slice that has GetSeverity()
func CountFindings[T interface{ GetSeverity() string }](findings []T) SeverityCounts {
    var c SeverityCounts
    for _, f := range findings {
        switch f.GetSeverity() {
        case "Critical":
            c.Critical++
        case "High":
            c.High++
        case "Medium":
            c.Medium++
        case "Low":
            c.Low++
        case "Info":
            c.Info++
        }
    }
    return c
}
```

#### Крок 2. Один метод на Report struct

В `internal/report/report.go` (або де живе `Report`):

```go
func (r *Report) AggregateSeverity() analysis.SeverityCounts {
    var total analysis.SeverityCounts

    total = total.Add(analysis.CountFindings(r.Paths))
    total = total.Add(analysis.CountFindings(r.ACLFindings))
    total = total.Add(analysis.CountFindings(r.ADCSVulns))
    total = total.Add(analysis.CountFindings(r.ShadowCredFindings))
    total = total.Add(analysis.CountFindings(r.DelegationFindings))
    total = total.Add(analysis.CountFindings(r.LDAPSecFindings))
    total = total.Add(analysis.CountFindings(r.AuditFindings))
    total = total.Add(analysis.CountFindings(r.AdminSDHolderFindings))
    total = total.Add(analysis.CountFindings(r.PolicyFindings))
    total = total.Add(analysis.CountFindings(r.KerberosFindings))

    return total
}
```

Кожен finding type має реалізувати `GetSeverity() string`. Якщо вже є — добре, переважно вже є. Якщо немає — додай.

#### Крок 3. CLI footer і HTML header використовують **один і той же метод**

В `internal/cli/summary.go`:
```go
counts := report.AggregateSeverity()
fmt.Printf("RISK   %s    [!!] %d critical    [!] %d high    [-] %d medium\n",
    riskVerdict(counts), counts.Critical, counts.High, counts.Medium)
```

В `internal/report/html.go` template data:
```go
templateData := struct {
    // ...
    CriticalCount int
    HighCount     int
    MediumCount   int
}{
    CriticalCount: report.AggregateSeverity().Critical,
    HighCount:     report.AggregateSeverity().High,
    MediumCount:   report.AggregateSeverity().Medium,
}
```

Це гарантує що CLI footer і HTML header показують **ідентичні** числа.

### Перевірка

```bash
./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html 2>&1 | tail -3
grep -E "[0-9]+ Critical" /tmp/test.html | head -1
# Числа критікал в обох виводах мають збігатись
```

Додай unit тест в `internal/analysis/severity_counts_test.go`:

```go
func TestAggregateSeverity_MatchesCLI(t *testing.T) {
    r := &Report{
        Paths: []Path{
            {Severity: "Critical"},
            {Severity: "Critical"},
        },
        ACLFindings: []ACLFinding{
            {Severity: "Critical"},
            {Severity: "High"},
        },
    }
    counts := r.AggregateSeverity()
    assert.Equal(t, 3, counts.Critical)
    assert.Equal(t, 1, counts.High)
}
```

---

## 🔴 BLOCKER #2: ESC1 duplicate в ADCS section (той самий що P3 #3)

### Проблема

```
ADCS    1 critical · 0 high
[!!]   ESC1                 (ESC1)
```

Перший `ESC1` — це **ESC vulnerability class** (правильно), другий в дужках має бути **template name** (наприклад `User`, `WebServer`, `KerberosAuthentication`). Це той самий bug що в HTML — binding неправильного поля.

### Фікс

Виправлення в одному місці фіксить обидва вивідні шари. Дивись P3 BLOCKER #3 — там фікс через `internal/analysis/adcs.go` де треба переконатись що `Template.Name != Template.ESC`.

В CLI rendering знайди (десь в `internal/cli/sections/adcs.go` або аналогічно):

```go
// Було:
fmt.Fprintf(w, "[!!]   %s\t\t\t(%s)\n", t.ESC, t.ESC)

// Треба:
fmt.Fprintf(w, "[!!]   %s\t\t\t(%s)\n", t.ESC, t.Name)
```

Якщо в lab data `Template.Name` теж "ESC1" (бо template буквально так названий в GOAD) — це не баг шаблону, а збіг lab-даних. На реальному CA назви будуть `User`, `Machine`, `WebServer` — і duplicate зникне сам. Але переконайся через grep що binding правильний.

---

## ⚠️ Strongly recommended

### 3. Згрупувати ACL findings по principal

#### Проблема

Зараз 5 рядків про одну й ту саму людину:

```
ACL    33 critical · 39 high
[!!]  lord.varys     WriteDACL    → Administrators
[!!]  lord.varys     WriteOwner   → Administrators
[!!]  lord.varys     GenericAll   → Administrators
[!!]  lord.varys     WriteDACL    → Print Operators
[!!]  lord.varys     WriteOwner   → Print Operators
```

Це **ховає головний факт**: lord.varys = single point of compromise. Замість того щоб бути одним bullet з 5 expansions, виглядає як 5 окремих problem.

#### Фікс

В `internal/cli/sections/acl.go` (або де живе ACL CLI render):

```go
type aclGroupKey struct {
    Principal string
    Right     string
}

func renderACLSection(w io.Writer, findings []analysis.ACLFinding, limit int) {
    // Group by (principal, right) → list of targets
    grouped := make(map[aclGroupKey][]string)
    var keyOrder []aclGroupKey

    for _, f := range findings {
        key := aclGroupKey{Principal: f.Principal, Right: f.Right}
        if _, exists := grouped[key]; !exists {
            keyOrder = append(keyOrder, key)
        }
        grouped[key] = append(grouped[key], f.Target)
    }

    // Sort: critical principals first, then by principal name
    sort.SliceStable(keyOrder, func(i, j int) bool {
        if keyOrder[i].Principal != keyOrder[j].Principal {
            return keyOrder[i].Principal < keyOrder[j].Principal
        }
        return rightSeverity(keyOrder[i].Right) < rightSeverity(keyOrder[j].Right)
    })

    // Track principals we've seen to render them once
    seenPrincipal := make(map[string]bool)
    rendered := 0

    for _, key := range keyOrder {
        if rendered >= limit {
            break
        }
        targets := grouped[key]

        if !seenPrincipal[key.Principal] {
            fmt.Fprintf(w, "[!!]  %s\n", colorize(key.Principal, ColorCritical))
            seenPrincipal[key.Principal] = true
        }

        // Indented right + targets
        targetList := strings.Join(targets, ", ")
        if len(targetList) > 60 {
            targetList = targetList[:57] + "..."
        }
        fmt.Fprintf(w, "        %-12s → %s\n",
            colorize(key.Right, ColorCriticalDim),
            targetList)
        rendered++
    }

    remaining := len(findings) - countRendered(grouped, limit)
    if remaining > 0 {
        fmt.Fprintf(w, "      (+%d more — run: adpath acl -d %s ...)\n",
            remaining, domain)
    }
}
```

Результат:

```
ACL    33 critical · 39 high
[!!]  lord.varys
        WriteDACL    → Administrators, Print Operators, Backup Operators
        WriteOwner   → Administrators, Print Operators, Backup Operators
        GenericAll   → Administrators, Print Operators, Backup Operators
      (+24 more — run: adpath acl -d sevenkingdoms.local ...)
```

Це 4 рядки замість 9, і одразу читабельний message: **"один користувач має повний контроль над трьома Tier-0 групами"**.

#### Перевірка

Запусти на lab — має бути не більше 7-8 рядків в ACL section на summary screen, навіть при 72 findings.

### 4. Додати timing footer

#### Проблема

Після `report saved to: report.html` нічого. Користувач не знає чи це швидко (10s) чи довго (5min). Це впливає на perception "ця тулза швидка/повільна".

#### Фікс

В `internal/cli/main.go` або де `enumCmd.RunE`:

```go
import "time"

func runEnum(cmd *cobra.Command, args []string) error {
    startTime := time.Now()
    queryCounter := &analysis.QueryCounter{}  // pass into LDAP client

    report, err := enumerate(opts, queryCounter)
    if err != nil {
        return err
    }

    if err := saveReport(report, opts.Output); err != nil {
        return err
    }

    elapsed := time.Since(startTime)
    fmt.Printf("\nreport saved to: %s\n", opts.Output)
    fmt.Printf("enumeration completed in %s · %d LDAP queries\n",
        formatDuration(elapsed), queryCounter.Count())

    return nil
}

func formatDuration(d time.Duration) string {
    if d < time.Second {
        return fmt.Sprintf("%dms", d.Milliseconds())
    }
    if d < time.Minute {
        return fmt.Sprintf("%.1fs", d.Seconds())
    }
    return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}
```

`QueryCounter` — простий thread-safe counter:

```go
package analysis

import "sync/atomic"

type QueryCounter struct {
    n int64
}

func (q *QueryCounter) Inc() { atomic.AddInt64(&q.n, 1) }
func (q *QueryCounter) Count() int64 { return atomic.LoadInt64(&q.n) }
```

Інкрементуй у LDAP client wrapper:

```go
func (c *Client) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
    if c.counter != nil {
        c.counter.Inc()
    }
    return c.conn.Search(req)
}
```

Output:

```
report saved to: report.html
enumeration completed in 12.3s · 247 LDAP queries
```

### 5. Risk score в footer

#### Проблема

Зараз CLI footer:
```
RISK   CRITICAL    [!!] 42 critical    [!] 40 high    [-] 1 medium
```

Немає числа. Користувач після другого scan хоче побачити "було 83, стало 71" — без числа неможливо. Risk score у тебе вже обчислюється для HTML — треба тільки винести в CLI.

#### Фікс

В `internal/cli/summary.go` де рендериться footer:

```go
score := report.RiskScore  // вже обчислений для HTML

verdict := riskVerdict(score)  // CRITICAL / HIGH / MEDIUM / LOW
verdictColor := riskColor(score.Grade)

fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
fmt.Fprintf(w, "RISK   %s  (%s · %d/100)   [!!] %d critical   [!] %d high   [-] %d medium\n",
    colorize(verdict, verdictColor),
    score.Grade,
    score.Total,
    counts.Critical,
    counts.High,
    counts.Medium,
)
```

Output:

```
─────────────────────────────────────────────────────────────────
RISK   CRITICAL  (F · 83/100)    [!!] 42 critical    [!] 40 high    [-] 1 medium
```

`riskVerdict` маппить grade на verbal label:
```go
func riskVerdict(s RiskScore) string {
    switch s.Grade {
    case "F": return "CRITICAL"
    case "D": return "HIGH"
    case "C": return "MEDIUM"
    case "B": return "LOW"
    case "A": return "MINIMAL"
    }
    return "UNKNOWN"
}
```

### 6. One-line domain summary вгорі (перед TRUSTS)

#### Проблема

Зараз перші рядки після authenticated:
```
enumerating sevenkingdoms.local ...
querying north.sevenkingdoms.local via 192.168.56.11

TRUSTS
```

Йдуть одразу в trusts. Корисно мати **один summary рядок з найважливішими метриками** перед детальними секціями. Це той "tldr" який пентестер копіпастить в notes.

#### Фікс

Після `enumerating` додай блок:

```go
fmt.Fprintf(w, "\nDOMAIN SUMMARY\n")
fmt.Fprintf(w, "  %s · %d users · %d computers · %d groups · %d admins · %d trust(s)\n",
    report.Domain.Name,
    report.UserCount,
    report.ComputerCount,
    report.GroupCount,
    report.AdminCount,
    len(report.Trusts),
)
fmt.Fprintf(w, "  %d attack paths · %d ACL findings · %d ADCS · krbtgt: %dd\n",
    len(report.Paths),
    len(report.ACLFindings),
    len(report.ADCSVulns),
    report.KrbtgtAgeDays,
)
fmt.Fprintln(w)
```

Output:

```
DOMAIN SUMMARY
  sevenkingdoms.local · 16 users · 3 computers · 55 groups · 4 admins · 1 trust
  5 attack paths · 72 ACL findings · 1 ADCS · krbtgt: 51d

TRUSTS
domain trusts                 1
...
```

Це дає reader instant overview перед тим як занурюватись у деталі.

### 7. Color consistency — exposure metrics

#### Проблема

В EXPOSURE block кольори не консистентні:

```
krbtgt pwd age              51 days        ← білий (default)
stale users (90d+)          12             ← yellow (warning)
stale computers (45d+)       0             ← білий
objects with description    61             ← yellow
no LAPS                      3 / 3 computers ← yellow
```

`krbtgt 51 days` — білий бо < 180. Але `stale computers 0` теж білий — це ОК (без warning). А `stale users 12` жовтий — це warning. Логіка вірна але читач не одразу її бачить.

В PROTECTED USERS:
```
members                       1
privileged not in group       3 (NTLM/RC4 auth possible, delegation not blocked)
```

`members 1` — нейтральний. Але якщо є 4 admins і тільки 1 в Protected Users — це **warning** (3 з 4 admins незахищені). Зараз червоний тільки на `privileged not in group: 3`. Логічно: якщо `privileged not in group > 0`, то `members` теж warning-yellow.

#### Фікс

В `internal/cli/colors.go` створи helper:

```go
func ExposureColor(value int, thresholds ExposureThreshold) Color {
    switch {
    case value >= thresholds.Critical:
        return ColorCritical
    case value >= thresholds.Warning:
        return ColorWarning
    case value >= thresholds.Notice:
        return ColorNotice
    default:
        return ColorDefault
    }
}

type ExposureThreshold struct {
    Critical int  // red
    Warning  int  // yellow
    Notice   int  // dim cyan
}

var (
    StaleUsersThreshold     = ExposureThreshold{Critical: 50, Warning: 1, Notice: 0}
    StaleComputersThreshold = ExposureThreshold{Critical: 20, Warning: 1, Notice: 0}
    NoLAPSThreshold         = ExposureThreshold{Critical: 1, Warning: 0, Notice: 0}
    DescriptionsThreshold   = ExposureThreshold{Critical: 100, Warning: 10, Notice: 1}
    KrbtgtAgeThreshold      = ExposureThreshold{Critical: 365, Warning: 180, Notice: 90}
)
```

Застосуй в `renderExposureSection`:

```go
fmt.Fprintf(w, "stale users (90d+)        %s\n",
    colorize(fmt.Sprintf("%d", report.StaleUsers),
        ExposureColor(report.StaleUsers, StaleUsersThreshold)))
```

І в Protected Users — якщо `privilegedNotInGroup > 0`, рендер `members` теж жовтим:

```go
membersColor := ColorDefault
if privilegedNotInGroup > 0 {
    membersColor = ColorWarning  // partial coverage
}
fmt.Fprintf(w, "members                       %s\n",
    colorize(fmt.Sprintf("%d", members), membersColor))
```

### 8. Drill-down hint для Protected Users

#### Проблема

```
PROTECTED USERS
members                       1
privileged not in group       3 (NTLM/RC4 auth possible, delegation not blocked)
```

`3` — без імен. Симетрично з ACL section де є `(+67 more — run: adpath acl ...)`, додай drill-down:

#### Фікс

```go
fmt.Fprintf(w, "privileged not in group       %s %s\n",
    colorize(fmt.Sprintf("%d", count), ColorCritical),
    colorize("(NTLM/RC4 auth possible, delegation not blocked)", ColorMutedRed))

if count > 0 {
    fmt.Fprintf(w, "                              (run: adpath protected -d %s)\n",
        report.Domain.Name)
}
```

### 9. Shadow Creds drill-down hint

#### Проблема

```
SHADOW CREDS   3 finding(s)
[!!]  lord.varys   → Administrator
[!!]  lord.varys   → robert.baratheon
[!!]  lord.varys   → cersei.lannister
```

Чудово, але читач який не знає Shadow Credentials атаки не розуміє що з цим робити. Симетрично з ADCS exploit hints.

#### Фікс

```go
fmt.Fprintf(w, "SHADOW CREDS   %d finding(s) %s\n",
    len(findings),
    colorize("(detection only — exploit: pywhisker / certipy shadow)", ColorMuted))
```

Маленький напрям де шукати exploit tooling. Після цього можна групувати як ACL:

```
SHADOW CREDS   3 finding(s)  (detection only — exploit: pywhisker / certipy shadow)
[!!]  lord.varys
        → Administrator, robert.baratheon, cersei.lannister
```

3 рядки → 2 рядки, а message сильніший.

### 10. Stale window unification (footnote)

#### Проблема

```
stale users (90d+)        12
stale computers (45d+)     0
```

Два різних threshold. Це правильно (CIS standard) але користувач здивується. Не хочу примусово unify, краще додати context.

#### Фікс

Додай в `--help` або в EXPOSURE header tooltip:

```go
fmt.Fprintf(w, "EXPOSURE  %s\n",
    colorize("(thresholds: users 90d, computers 45d — per CIS Benchmarks)", ColorMuted))
```

Або винеси в окрему tooltip колонку в кінці рядка:

```
stale users (90d+)        12     (CIS: ≥90d inactive)
stale computers (45d+)     0     (CIS: ≥45d inactive)
```

Перший варіант компактніший.

---

## 💄 Polish

### 11. Quiet mode

```bash
adpath enum --quiet -d sevenkingdoms.local
```

Output: тільки `RISK CRITICAL (F · 83/100) — 42 critical, 40 high, 1 medium`

Для CI/automation:
```bash
if adpath enum --quiet | grep -q "CRITICAL\|HIGH"; then
    slack-notify "AD scan failed compliance"
fi
```

В `enumCmd.Flags()`:
```go
enumCmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "suppress detailed output, print only risk verdict")
```

В render:
```go
if opts.Quiet {
    fmt.Printf("RISK %s (%s · %d/100) — %d critical, %d high, %d medium\n",
        verdict, score.Grade, score.Total,
        counts.Critical, counts.High, counts.Medium)
    return
}
// ... full output
```

### 12. Verbose mode

```bash
adpath enum -v -d sevenkingdoms.local
```

Не обмежувати ACL/Description/etc до 5 рядків — показати все.

```go
enumCmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show all findings without truncation")

// In render:
limit := 5
if opts.Verbose {
    limit = 0  // no limit
}
```

---

## Перевірка після всіх фіксів

```bash
go build ./...
go test ./internal/analysis/...

# Generate, compare counts
./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html 2>&1 | tee /tmp/cli.txt
grep "Critical\|High\|Medium" /tmp/cli.txt | tail -3
grep -E "[0-9]+ Critical" /tmp/test.html | head -1
# Critical/High/Medium counts мають збігатись точно

# Visual checks:
# 1. ACL section: lord.varys appears once, with rights and grouped targets
# 2. ADCS: ESC1 (User) or ESC1 (WebServer), not ESC1 (ESC1)
# 3. Footer: includes "(F · 83/100)"
# 4. After report saved: "enumeration completed in Xs · Y LDAP queries"
# 5. EXPOSURE: krbtgt 51d white, stale users 12 yellow, no LAPS yellow

# Quiet mode test
./adpath enum --quiet -d sevenkingdoms.local -u user -p pass
# Single line: RISK CRITICAL (F · 83/100) — 42 critical, 40 high, 1 medium
```

## Commit

```
fix(cli): align severity counts with HTML, group ACL by principal, add timing

- Single source of truth (Report.AggregateSeverity) used by both CLI and HTML
- Group ACL findings by principal+right to surface concentrated risk
  (lord.varys appears once with all rights, not 9 separate lines)
- Fix duplicate ESC class in ADCS line (was binding ESC twice instead of Name)
- Add risk score (F · 83/100) to footer verdict line
- Add timing footer with elapsed time and LDAP query count
- Add domain summary one-liner before sections start
- Consistent exposure coloring with named thresholds
- Drill-down hints for Protected Users and Shadow Creds
- --quiet flag for CI integration, --verbose flag to disable truncation

P4 fixes from CLI output review.
```
