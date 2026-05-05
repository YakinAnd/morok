# adpath CLI — P6 micro fixes: quiet mode, truncation, empty targets

P4 застосовано здебільшого добре, але при тестуванні `--quiet` і `--verbose` проти GOAD lab знайдено 3 регресії/недоробки. Це короткий фокус-фікс, не великий refactor.

## Контекст
- Файл: `internal/cli/main.go` (entry point, runEnum)
- Файл: `internal/cli/summary.go` (рендер summary секцій)
- Файл: `internal/cli/sections/acl.go` (ACL grouping і truncation)
- Поточна версія: v0.9.9
- Lab: GOAD / sevenkingdoms.local

---

## 🔴 BUG #1: `--quiet` flag не виконує quiet rendering

### Проблема

Команда `adpath enum --quiet -d ... -u ... -p ...` зараз генерує **повний** scan output (TRUSTS, EXPOSURE, PROTECTED USERS, ACCOUNTS, ADMINSDHOLDER, DOMAIN, USERS, ACL і т.д.) — ідентично default mode. В кінці footer:

```
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium
```

`--quiet` за специфікацією P4 #11 мав виводити **тільки** один рядок — для CI/automation:

```
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium
```

Зараз флаг приймається парсером (немає помилки про unknown flag), але далі не використовується. Або немає `if opts.Quiet { quietRender(); return }` гілки в `runEnum`, або `Quiet` поле не пробрасується в `Options` struct.

### Фікс

#### Крок 1. Перевір що поле є в Options struct

В `internal/cli/options.go` (або де визначено `EnumOptions`):

```go
type EnumOptions struct {
    Domain   string
    User     string
    Password string
    DC       string
    Output   string
    Verbose  bool
    Quiet    bool   // <-- переконайся що поле існує
    // ...
}
```

#### Крок 2. Перевір binding в Cobra

В `internal/cli/main.go` (`enumCmd` definition):

```go
enumCmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "suppress detailed output, print only risk verdict (for CI)")
enumCmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show all findings without truncation")
```

Якщо обидва прапорці передані одночасно — `--quiet` повинен мати **пріоритет** (бо він строго singletwet).

#### Крок 3. Гілка в runEnum

В `internal/cli/main.go` функція `runEnum` (або `runEnumerate`, як там названа):

```go
func runEnum(cmd *cobra.Command, args []string) error {
    startTime := time.Now()

    // ... existing auth + enumerate logic ...

    report, err := enumerate(opts)
    if err != nil {
        return err
    }

    // QUIET MODE — single line for CI, then return
    if opts.Quiet {
        renderQuietFooter(os.Stdout, report)
        if opts.Output != "" {
            // still save report file silently if --output specified
            if err := saveReport(report, opts.Output); err != nil {
                return err
            }
        }
        return nil
    }

    // ... existing full rendering ...

    elapsed := time.Since(startTime)
    renderFullFooter(os.Stdout, report, elapsed)
    return nil
}
```

#### Крок 4. Quiet renderer

В `internal/cli/summary.go` додай:

```go
// renderQuietFooter prints a single-line risk verdict suitable for CI parsing.
// No colors, no Unicode separators, no extra whitespace.
func renderQuietFooter(w io.Writer, report *Report) {
    counts := report.AggregateSeverity()
    score := report.RiskScore

    // Plain ASCII, no color escapes — easier to grep/awk in CI.
    fmt.Fprintf(w, "RISK %s (%s %d/100) %d critical, %d high, %d medium\n",
        riskVerdict(score),
        score.Grade,
        score.Total,
        counts.Critical,
        counts.High,
        counts.Medium,
    )
}
```

Зверни увагу — **без ANSI color codes** в quiet mode. CI logs часто ловлять escape codes як garbage. Якщо у тебе є хелпер `colorize()` — він не повинен викликатись в quiet path.

Розглянь альтернативний `key=value` формат для max parseability:

```go
// Опція А (default): human-readable single line
fmt.Fprintf(w, "RISK %s (%s %d/100) %d critical, %d high, %d medium\n", ...)

// Опція B (за прапорцем --quiet=kv): machine-readable
fmt.Fprintf(w, "risk=%s grade=%s score=%d critical=%d high=%d medium=%d\n", ...)
```

Поки що вистачить опції А. Якщо community просить — пізніше додаси `--format=kv|json|text` як `nmap` зробив з `-oG/-oN/-oX`.

### Перевірка

```bash
./adpath enum --quiet -d sevenkingdoms.local -u administrator -p '...' --dc 192.168.56.10 2>&1 | wc -l
# Очікувано: 1

./adpath enum --quiet -d ... 2>&1
# Очікувано: рівно один рядок типу
# RISK CRITICAL (F 83/100) 38 critical, 40 high, 1 medium

# CI workflow test
if ./adpath enum --quiet -d ... -u ... -p ... | grep -q "CRITICAL\|HIGH"; then
  echo "AD compliance failed"
fi
```

---

## ⚠️ BUG #2: Truncation посеред слова (`Replic...`)

### Проблема

В ACL section verbose output:
```
[!!]  lord.varys
       WriteDACL    → Administrators, Print Operators, Backup Operators, Replic...
       WriteOwner   → Administrators, Print Operators, Backup Operators, Replic...
       GenericAll   → Administrators, Print Operators, Backup Operators, Replic...
```

`Replic...` — це truncated `Replicator` (built-in group). Поточна логіка ймовірно:

```go
if len(targetList) > 60 {
    targetList = targetList[:57] + "..."
}
```

Це режеться **посеред слова**, що:
1. Виглядає неохайно (`Replic...` ≠ професійно)
2. Не каже скільки ще targets є приховано
3. Втрачає інформацію — користувач не знає скільки `+N more`

### Фікс

Заміни в `internal/cli/sections/acl.go` логіку truncation на word-aware з `+N more` суфіксом:

```go
// truncateTargets joins targets up to maxLen, replacing the rest with "+N more".
// Always breaks on commas, never mid-word.
func truncateTargets(targets []string, maxLen int) string {
    if len(targets) == 0 {
        return ""
    }

    var included []string
    total := 0
    const sep = ", "

    for i, t := range targets {
        addLen := len(t)
        if i > 0 {
            addLen += len(sep)
        }

        // Reserve space for ", +N more" suffix if we'll need it
        remaining := len(targets) - i
        suffix := ""
        if remaining > 1 {
            suffix = fmt.Sprintf(", +%d more", remaining-1)
        }

        if total+addLen+len(suffix) > maxLen && len(included) > 0 {
            return strings.Join(included, sep) +
                fmt.Sprintf(", +%d more", len(targets)-len(included))
        }

        included = append(included, t)
        total += addLen
    }

    return strings.Join(included, sep)
}
```

Виклик:
```go
targetList := truncateTargets(targets, 70)  // ширина термінала ~80, лишаємо запас
fmt.Fprintf(w, "       %-12s → %s\n",
    colorize(right, ColorCriticalDim),
    targetList)
```

#### Verbose mode — без truncation взагалі

Якщо `--verbose`, показуй усі targets без обрізання:

```go
var targetList string
if opts.Verbose {
    targetList = strings.Join(targets, ", ")
} else {
    targetList = truncateTargets(targets, 70)
}
```

### Очікуваний output

Default mode:
```
[!!]  lord.varys
       WriteDACL    → Administrators, Print Operators, Backup Operators, +2 more
       WriteOwner   → Administrators, Print Operators, Backup Operators, +2 more
       GenericAll   → Administrators, Print Operators, Backup Operators, +2 more
```

Verbose mode (`-v`):
```
[!!]  lord.varys
       WriteDACL    → Administrators, Print Operators, Backup Operators, Replicator, Schema Admins
       WriteOwner   → Administrators, Print Operators, Backup Operators, Replicator, Schema Admins
       GenericAll   → Administrators, Print Operators, Backup Operators, Replicator, Schema Admins
```

Тепер користувач **знає** що є ще 2 targets, і у verbose бачить їх повністю.

### Перевірка

```bash
./adpath enum -d ... -u ... -p ... 2>&1 | grep -E "→.*\.\.\."
# Очікувано: 0 рядків з "..."  (більше немає mid-word truncation)

./adpath enum -d ... -u ... -p ... 2>&1 | grep -E "\+[0-9]+ more"
# Очікувано: ≥1 рядок (труcation тепер словесний з суфіксом)
```

---

## ⚠️ BUG #3: Empty target в ACL — `renly.baratheon WriteDACL → `

### Проблема

В verbose output ACL section:
```
[!]  KingsGuard
       WriteDACL    → stannis.baratheon
       WriteOwner   → stannis.baratheon
       GenericAll   → stannis.baratheon
[!]  renly.baratheon
       WriteDACL    →
```

Стрілка `→` є, target порожній. Це або:
- (A) ACL finding має `Target == ""` (data integrity bug в `internal/analysis/acl.go`)
- (B) Render код не filter'ує findings з порожнім target
- (C) Group має 0 targets після dedup, але не filter'ується

### Фікс

#### Захист на рівні аналізу (defense in depth)

В `internal/analysis/acl.go` — там де створюються findings:

```go
func (a *ACLAnalyzer) addFinding(principal, right, target string) {
    // Skip findings without a resolvable target
    if strings.TrimSpace(target) == "" {
        a.logger.Debugf("skipping ACL finding with empty target: principal=%s right=%s",
            principal, right)
        return
    }
    a.findings = append(a.findings, ACLFinding{
        Principal: principal,
        Right:     right,
        Target:    target,
    })
}
```

#### Захист на рівні рендеру (на випадок legacy data)

В `internal/cli/sections/acl.go` функція `renderACLSection` — після групування, перед output:

```go
// Filter out groups that ended up with no valid targets after dedup/truncation
filteredTargets := make([]string, 0, len(targets))
for _, t := range targets {
    if strings.TrimSpace(t) != "" {
        filteredTargets = append(filteredTargets, t)
    }
}
if len(filteredTargets) == 0 {
    continue  // skip this right entirely
}

targetList := truncateTargets(filteredTargets, 70)
fmt.Fprintf(w, "       %-12s → %s\n",
    colorize(right, ColorCriticalDim),
    targetList)
```

#### Якщо у principal **всі** rights мають empty targets — пропускати весь principal

```go
// Before printing principal header, check if it has any non-empty findings
hasValidFinding := false
for _, right := range rights {
    targets := grouped[aclGroupKey{Principal: principal, Right: right}]
    for _, t := range targets {
        if strings.TrimSpace(t) != "" {
            hasValidFinding = true
            break
        }
    }
    if hasValidFinding {
        break
    }
}
if !hasValidFinding {
    continue  // skip this principal entirely
}
```

### Корінь проблеми

`renly.baratheon WriteDACL → <empty>` — швидше за все хтось має ACE з SID який не зміг резолвитись через LDAP (видалений account, foreign domain, ophan SID). В цьому випадку краще або:

1. Показати raw SID: `→ <S-1-5-21-...-1234>` (інформативно для пентестера)
2. Показати плейсхолдер: `→ <unresolved SID>`
3. Скіпнути взагалі (як в фіксі вище)

Я рекомендую **варіант #1 + #3 fallback**: спочатку спробувати показати SID, якщо і його немає — скіп.

В `addFinding`:
```go
func (a *ACLAnalyzer) addFinding(principal, right, target, targetSID string) {
    target = strings.TrimSpace(target)
    if target == "" {
        if targetSID != "" {
            target = "<" + targetSID + ">"  // fallback to raw SID
        } else {
            return  // truly orphan, skip
        }
    }
    a.findings = append(a.findings, ACLFinding{
        Principal: principal,
        Right:     right,
        Target:    target,
    })
}
```

Output для unresolved SID:
```
[!]  renly.baratheon
       WriteDACL    → <S-1-5-21-3223259369-1214789570-540078023-2104>
```

Це **інформативніше** — пентестер бачить що ACL існує, target deleted, але SID можна шукати в backup/snapshot.

---

## ⚠️ BUG #4 (бонус, з минулого review): timing footer не зайшов

P4 #4 — мав додатися:
```
report saved to: report.html
enumeration completed in 12.3s · 247 LDAP queries
```

В обох виводах (verbose і default) timing рядок відсутній. Якщо вже фіксиш — додай разом, бо контекст той самий (`runEnum`).

### Швидкий фікс

В `runEnum` після `renderFullFooter`:

```go
elapsed := time.Since(startTime)
queryCount := report.QueryCounter.Count()  // якщо counter integrated

if opts.Output != "" {
    fmt.Fprintf(os.Stdout, "\nreport saved to: %s\n", opts.Output)
}
fmt.Fprintf(os.Stdout, "enumeration completed in %s · %d LDAP queries\n",
    formatDuration(elapsed), queryCount)
```

`formatDuration` як в P4 #4. Якщо `QueryCounter` ще не integrated — поки можна `... in 12.3s` без queries part. Або skip `· %d LDAP queries` через nil check:

```go
if queryCount > 0 {
    fmt.Fprintf(os.Stdout, "enumeration completed in %s · %d LDAP queries\n", ...)
} else {
    fmt.Fprintf(os.Stdout, "enumeration completed in %s\n",
        formatDuration(elapsed))
}
```

---

## Перевірка після всіх фіксів

```bash
go build ./...
go test ./internal/cli/... ./internal/analysis/...

# 1. Quiet mode — single line
./adpath enum --quiet -d sevenkingdoms.local -u admin -p '...' --dc ... 2>&1 | wc -l
# Очікується: 1

# 2. No mid-word truncation
./adpath enum -d ... -u ... -p ... 2>&1 | grep -cE "→.*[a-z]\.\.\."
# Очікується: 0

# 3. Truncation with "+N more"
./adpath enum -d ... -u ... -p ... 2>&1 | grep -cE "\+[0-9]+ more"
# Очікується: ≥1

# 4. Verbose shows all targets, no truncation
./adpath enum --verbose -d ... -u ... -p ... 2>&1 | grep -cE "\+[0-9]+ more"
# Очікується: 0 (verbose показує все)

# 5. No empty arrows
./adpath enum -d ... -u ... -p ... 2>&1 | grep -cE "→\s*$"
# Очікується: 0

# 6. Timing footer present
./adpath enum -d ... -u ... -p ... 2>&1 | grep -E "completed in"
# Очікується: ≥1 рядок
```

## Commit

```
fix(cli): quiet mode, word-aware ACL truncation, empty target handling

- Implement --quiet rendering (single-line, plain ASCII, for CI use)
- Replace mid-word "Replic..." truncation with word-aware "+N more" suffix
- Filter out ACL findings with empty/unresolvable targets;
  fall back to raw SID when LDAP resolution fails
- Add timing footer (elapsed time + LDAP query count) to default mode

Verified against GOAD/sevenkingdoms.local: --quiet emits 1 line,
ACL grouping shows "+2 more" instead of "Replic...",
no empty arrows in renly.baratheon entry.
```
