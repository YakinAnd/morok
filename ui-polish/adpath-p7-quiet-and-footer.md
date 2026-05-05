# adpath CLI — P7 fix: --quiet mode actually works, default output deduplicated

P6 застосовано переважно добре, але два issues залишились в CLI output. Це короткий фокус-фікс.

## Контекст
- Файл: `internal/cli/main.go` (entry point — `runEnum` function)
- Файл: `internal/cli/summary.go` (рендер footer)
- Поточна версія: v0.9.9
- Lab: GOAD / sevenkingdoms.local

## Перевірка перед роботою

Спочатку діагностуй стан коду. Виконай:

```bash
grep -rn "Quiet.*bool" internal/cli/                   # Поле Options.Quiet
grep -rn '"quiet"' internal/cli/main.go                # Cobra binding
grep -rn "opts\.Quiet\|opts\.quiet" internal/cli/      # Чи код перевіряє флаг
grep -rn "renderQuiet\|QuietRender\|quietRender" internal/  # Чи є quiet renderer
grep -rn "report saved to:" internal/                  # Місця де friendly print
```

Зрозумій що є на місці, і на основі цього виконай нижче. Не дублюй якщо вже зроблено — застосовуй тільки відсутнє.

---

## 🔴 BUG #1: `--quiet` приймається, але виконує повний рендер

### Симптом

```
$ ./adpath enum --quiet -d sevenkingdoms.local -u admin -p '...' --dc ... --report report.html

# Очікується (для CI/automation):
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium

# Фактично — повний default output:
TRUSTS
domain trusts                 1
trusted domain    direction   type   ...
[... 50+ рядків ...]
EXPOSURE
...
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium
report saved to: report.html
```

Прапорець існує, парсер не помиляється, але рендер не реагує.

### Корінь проблеми (одне з трьох)

1. **Поле відсутнє** в `Options` struct (`opts.Quiet` нікуди не пробрасується)
2. **Binding неправильний** — `BoolVar(&someOtherVar, ...)` замість `&opts.Quiet`
3. **Гілка відсутня** в `runEnum` — поле читається з прапорця, але `if opts.Quiet` не написано

Найімовірніше — варіант 3. Прапорець акуратно зареєстрований ("я пам'ятав додати"), а switch у `runEnum` забутий.

### Фікс

#### Крок 1. Переконайся що поле є

В `internal/cli/options.go` або де визначено `EnumOptions`:

```go
type EnumOptions struct {
    Domain   string
    User     string
    Password string
    DC       string
    Report   string
    Verbose  bool
    Quiet    bool   // <-- має існувати
    // ... решта
}
```

#### Крок 2. Cobra binding

В `internal/cli/main.go` (або де `enumCmd` визначено):

```go
enumCmd.Flags().BoolVar(&opts.Quiet, "quiet", false,
    "suppress detailed output, print only risk verdict (for CI integration)")
```

Перевір що binding до **&opts.Quiet** (тієї змінної що передається в runEnum), не до іншого scope.

#### Крок 3. Гілка в `runEnum` — головний фікс

Подивись на поточну `runEnum` функцію. Скоріш за все вона виглядає так:

```go
func runEnum(cmd *cobra.Command, args []string) error {
    // auth
    // enumerate
    report, err := enumerate(opts)
    if err != nil { return err }

    // ❌ Тут немає quiet branch — одразу йде повний рендер
    renderFullReport(os.Stdout, report, opts.Verbose)

    if opts.Report != "" {
        saveReport(report, opts.Report)
        fmt.Println("report saved to:", opts.Report)
    }

    return nil
}
```

Перетвори на:

```go
func runEnum(cmd *cobra.Command, args []string) error {
    startTime := time.Now()

    // auth
    // enumerate
    report, err := enumerate(opts)
    if err != nil { return err }

    // === QUIET BRANCH — виконується першим, повертає одразу ===
    if opts.Quiet {
        // 1. Зберегти HTML-звіт мовчки, без друку шляху
        if opts.Report != "" {
            if err := saveReport(report, opts.Report); err != nil {
                // помилку друкуємо в stderr щоб не порушити stdout формат
                fmt.Fprintf(os.Stderr, "error saving report: %v\n", err)
                return err
            }
        }
        // 2. Один рядок в stdout, без ANSI кольорів
        renderQuietFooter(os.Stdout, report)
        return nil
    }

    // === DEFAULT BRANCH — повний рендер ===
    renderFullReport(os.Stdout, report, opts.Verbose)

    // 3. Footer з timing і шляхом до звіту (але один раз!)
    elapsed := time.Since(startTime)
    renderDefaultFooter(os.Stdout, report, opts.Report, elapsed)

    return nil
}
```

Ключове — **`return nil` всередині quiet branch** обриває виконання. Без нього rendering продовжується.

#### Крок 4. Quiet renderer

В `internal/cli/summary.go`:

```go
// renderQuietFooter prints a single-line risk verdict for CI parsing.
// Plain ASCII, no color escapes, no extra info beyond the verdict.
func renderQuietFooter(w io.Writer, report *Report) {
    counts := report.AggregateSeverity()
    score := report.RiskScore

    fmt.Fprintf(w, "RISK %s (%s · %d/100) — %d critical, %d high, %d medium\n",
        riskVerdict(score),
        score.Grade,
        score.Total,
        counts.Critical,
        counts.High,
        counts.Medium,
    )
}
```

**ВАЖЛИВО**: жодних `colorize()` викликів в quiet path. ANSI escape codes (`\033[31m...`) ламають CI логи в Jenkins, GitHub Actions, тощо. Plain ASCII only.

Якщо `riskVerdict` зараз повертає colored string — створи окрему `riskVerdictPlain`:

```go
func riskVerdictPlain(s RiskScore) string {
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

І викликай `riskVerdictPlain` з `renderQuietFooter`.

### Перевірка

```bash
go build ./...

# Test 1: quiet emits exactly 1 line
./adpath enum --quiet -d sevenkingdoms.local -u admin -p '...' --dc 192.168.56.10 2>&1 | wc -l
# ✅ Очікується: 1

# Test 2: quiet line is parseable
./adpath enum --quiet -d ... 2>&1 | grep -E "^RISK (CRITICAL|HIGH|MEDIUM|LOW|MINIMAL) \(.* · [0-9]+/100\)"
# ✅ Очікується: 1 збіг

# Test 3: quiet + --report saves file silently
./adpath enum --quiet --report /tmp/q.html -d ... 2>&1 | wc -l
# ✅ Очікується: 1 (без "report saved to:" в stdout)
ls -la /tmp/q.html
# ✅ Очікується: файл існує

# Test 4: no ANSI escape codes in quiet output (no color leaking to CI logs)
./adpath enum --quiet -d ... 2>&1 | grep -P '\x1b\['
# ✅ Очікується: 0 збігів

# Test 5: default mode не зачеплено
./adpath enum -d ... 2>&1 | wc -l
# ✅ Очікується: ~80-150 рядків (повний output)
```

---

## ⚠️ BUG #2: Дублікація "report saved" footer в default mode

### Симптом

В кінці default output:

```
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium

report saved to: report.html

REPORT
saved to                report.html
enumeration completed in 5.2s
```

`report saved to: report.html` зʼявляється **двічі** — спочатку як inline message, потім як секція `REPORT`. Це візуальний noise.

Скоріш за все відбулось наступне: при додаванні timing footer (P6 #4) хтось створив нову секцію `REPORT` з `saved to` + `enumeration completed in`, але старий `fmt.Println("report saved to:", path)` залишився непоміченим.

### Фікс

#### Крок 1. Знайти і видалити старий print

```bash
grep -rn "report saved to:" internal/
```

Виведе можливо 2 місця. Залиш **тільки те що в новій секції** `REPORT` (або в `renderDefaultFooter`). Видали legacy `fmt.Println("report saved to:", ...)`.

#### Крок 2. Консолідуй footer в одну функцію

В `internal/cli/summary.go`:

```go
// renderDefaultFooter prints the closing block of the default (verbose) output:
// risk verdict, report path, and timing — all in one consistent block.
func renderDefaultFooter(w io.Writer, report *Report, reportPath string, elapsed time.Duration) {
    counts := report.AggregateSeverity()
    score := report.RiskScore

    // Separator
    fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))

    // Verdict line (with colors — this is human-facing)
    fmt.Fprintf(w, "RISK   %s   (%s · %d/100)    [!!] %s    [!] %s    [-] %s\n",
        colorize(riskVerdict(score), riskColor(score.Grade)),
        score.Grade,
        score.Total,
        colorize(fmt.Sprintf("%d critical", counts.Critical), ColorCritical),
        colorize(fmt.Sprintf("%d high", counts.High), ColorWarning),
        colorize(fmt.Sprintf("%d medium", counts.Medium), ColorNotice),
    )
    fmt.Fprintln(w)

    // Report file (only if --report was specified)
    if reportPath != "" {
        fmt.Fprintf(w, "report saved to: %s\n", reportPath)
    }

    // Timing
    queryCount := report.QueryCounter.Count()
    if queryCount > 0 {
        fmt.Fprintf(w, "enumeration completed in %s · %d LDAP queries\n",
            formatDuration(elapsed), queryCount)
    } else {
        fmt.Fprintf(w, "enumeration completed in %s\n", formatDuration(elapsed))
    }
}
```

Чи не використовуй стару `REPORT` секцію взагалі — заміни на компактний footer без header.

#### Крок 3. Видали будь-які залишки

Перевір ще раз:
```bash
grep -rn "REPORT\b" internal/cli/  # шукай "REPORT" як header без іншого контексту
grep -rn "saved to" internal/cli/
```

Якщо є дві функції що печатають "saved to" — залишити одну.

### Очікуваний default output (footer)

```
─────────────────────────────────────────────────────────────────────────────
RISK   CRITICAL   (F · 83/100)    [!!] 38 critical    [!] 40 high    [-] 1 medium

report saved to: report.html
enumeration completed in 5.2s
```

Один блок, чисто, без дублікацій.

### Перевірка

```bash
./adpath enum --report /tmp/test.html -d ... 2>&1 | grep -c "saved to"
# ✅ Очікується: 1 (не 2)

./adpath enum --report /tmp/test.html -d ... 2>&1 | grep -c "^REPORT$"
# ✅ Очікується: 0 (стара секція видалена)

./adpath enum --report /tmp/test.html -d ... 2>&1 | tail -10
# Має бути чистий блок: separator → RISK → blank → report saved → completed in
```

---

## Швидкий regression check

Переконайся що P6 фікси не зламались:

```bash
# Truncation з +N more (не "Replic...")
./adpath enum -d ... 2>&1 | grep -cE "\+[0-9]+ more"
# ✅ Очікується: ≥1

./adpath enum -d ... 2>&1 | grep -cE "→.*[a-z]\.\.\."
# ✅ Очікується: 0 (немає mid-word truncation)

# Empty arrows відсутні
./adpath enum -d ... 2>&1 | grep -cE "→\s*$"
# ✅ Очікується: 0

# Verbose показує все
./adpath enum -v -d ... 2>&1 | grep -cE "\+[0-9]+ more"
# ✅ Очікується: 0 (verbose без truncation)
```

## Commit

```
fix(cli): --quiet now emits single-line verdict; deduplicate default footer

BUG #1: --quiet flag was registered but ignored. Default output ran in full
  regardless. Now branches early in runEnum, calls renderQuietFooter() and
  returns. Plain ASCII, no ANSI codes — safe for CI log parsers.
  Saves --report file silently when both flags set.

BUG #2: "report saved to: <path>" was printed twice in default mode (once
  inline, once in a "REPORT" section block). Consolidated into a single
  renderDefaultFooter() call. Removed legacy print.

Verified: --quiet output is exactly 1 line, default footer is one clean block.
```
