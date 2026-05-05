# adpath — find and fix the broken --quiet flag

The `--quiet` flag was supposed to be fixed in commit `85f099c` but the commit only suppressed connection logs in `internal/ldap/client.go`. The full enumeration output (TRUSTS, EXPOSURE, ACCOUNT, ADMINSDHOLDER, USERS, ACL, etc.) is still being rendered in quiet mode, defeating the purpose of the flag.

Your job: find where the bug is and fix it. Don't ask me — diagnose and execute.

## Step 1 — Reproduce the bug

```bash
cd /path/to/adpath
go build ./...
./adpath enum --quiet -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10 | wc -l
```

If the result is **anything other than 1**, the bug is real and you must continue.

The expected output of `--quiet` is exactly one line:
```
RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium
```

## Step 2 — Find the architecture

The project structure may not match what you expect. Discover it:

```bash
# Where does the CLI live?
ls cmd/
ls internal/

# Where is quietMode currently used?
grep -rn "quietMode" cmd/ internal/

# Where is the enumCmd defined (Cobra command)?
grep -rn "enumCmd\|cobra.Command\|RunE\b" cmd/ internal/ | head -20

# Where are the section headers printed (TRUSTS, EXPOSURE, etc.)?
grep -rn '"TRUSTS"\|"EXPOSURE"\|"ADMINSDHOLDER"' cmd/ internal/ | head -10
```

These greps will tell you:
- Which file holds the `enum` subcommand entry point
- Which function orchestrates the full enumeration → rendering flow
- How `quietMode` is currently propagated (it's a package-level global, not a struct field — keep it that way for consistency)

## Step 3 — Identify the root cause

The fix in commit `85f099c` was incomplete because guards were added to **individual log statements** in the connection phase, not to the **section rendering phase**. Specifically, the entry function (likely `runEnum` or similar — find it in step 2) probably looks like this:

```go
func runEnum(...) error {
    client, err := connectAndBind()  // ← respects quietMode now
    if err != nil { return err }

    report, err := enumerate(client)
    if err != nil { return err }

    // ❌ EVERYTHING BELOW IS THE BUG — nothing here checks quietMode
    renderTrusts(report)
    renderExposure(report)
    renderAdminSDHolder(report)
    // ... many more renderXxx calls ...
    renderRiskFooter(report)

    if reportPath != "" {
        saveReport(report, reportPath)
    }
    return nil
}
```

The fix is to add an **early return** branch right after enumeration completes, before any section rendering happens.

## Step 4 — Apply the fix

In the entry function (whatever you found in step 2), insert this branch immediately after the `enumerate(...)` call returns successfully:

```go
// Quiet mode: skip detailed sections, emit single-line verdict only.
if quietMode {
    renderQuietFooter(os.Stdout, report)
    if reportPath != "" {
        // Still save HTML report if --report was specified, but silently.
        if err := saveReport(report, reportPath); err != nil {
            fmt.Fprintf(os.Stderr, "error saving report: %v\n", err)
            return err
        }
    }
    return nil
}
```

The variable names (`report`, `reportPath`, `saveReport`) might differ in your code — match what's already there. The structure is what matters: **branch → render single line → save report silently if needed → `return nil`**.

### If `renderQuietFooter` does not exist

Create it in the file that already holds the default footer rendering (search for where `RISK CRITICAL` is currently printed):

```go
// renderQuietFooter prints a single-line risk verdict for CI/automation use.
// Plain ASCII, no ANSI color codes — safe for log pipelines.
func renderQuietFooter(w io.Writer, report *Report) {
    counts := report.AggregateSeverity()
    score := report.RiskScore

    verdict := "MINIMAL"
    switch score.Grade {
    case "F":
        verdict = "CRITICAL"
    case "D":
        verdict = "HIGH"
    case "C":
        verdict = "MEDIUM"
    case "B":
        verdict = "LOW"
    }

    fmt.Fprintf(w, "RISK %s (%s · %d/100) — %d critical, %d high, %d medium\n",
        verdict,
        score.Grade,
        score.Total,
        counts.Critical,
        counts.High,
        counts.Medium,
    )
}
```

Adjust types (`*Report`, `AggregateSeverity()`, `RiskScore`) to match what already exists in the codebase. If method names differ (e.g. it's `report.SeverityCounts()` instead of `AggregateSeverity()`) — use the existing one. Don't create new aggregation logic; reuse what feeds the default footer.

**No `colorize()` calls in this function.** ANSI escapes break CI log parsers (Jenkins, GitHub Actions, GitLab CI). Plain `fmt.Fprintf` only.

## Step 5 — Verify (mandatory before commit)

Run all of these. Each must pass:

```bash
go build ./...
# Expected: clean build, no errors

./adpath enum --quiet -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10 | wc -l
# Expected: 1

./adpath enum --quiet -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10
# Expected: a single line like "RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium"

./adpath enum --quiet --report /tmp/q.html -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10 | wc -l
# Expected: 1 (still single line even when --report is set)
ls -la /tmp/q.html
# Expected: file exists, ~300KB

./adpath enum --quiet -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10 | grep -P '\x1b\[' | wc -l
# Expected: 0 (no ANSI escape codes in quiet output)

./adpath enum -d sevenkingdoms.local -u administrator -p '8dCT-DJjgScp' --dc 192.168.56.10 | wc -l
# Expected: ~80-150 (default mode unchanged, still full output)
```

**If any of these fails, the fix is not done.** Iterate until all pass. Common failure modes:

- `wc -l` returns 50+ → you forgot the `return nil` and execution falls through to default rendering. Add `return nil` immediately after the quiet branch.
- `wc -l` returns 2-3 → there's still a stray `fmt.Println` or `color.Cyan` somewhere being called before the quiet branch. Search for any remaining unguarded prints between auth and the quiet branch.
- Default mode broken → you accidentally moved code that shouldn't have been moved. Revert and re-apply the change as an additive insertion only.

## Step 6 — Commit

Only after all verification commands pass:

```bash
git add -u
git commit -m "fix(cli): --quiet now actually suppresses section rendering

Commit 85f099c silenced connection logs but section rendering (TRUSTS,
EXPOSURE, ACCOUNT, etc.) continued to print in quiet mode. Added an
early-return branch in the enum command entry function that calls
renderQuietFooter and exits before any section is rendered.

renderQuietFooter emits a single line of plain ASCII (no ANSI codes)
suitable for CI log parsing. --report still saves the HTML file
silently when both --quiet and --report are set.

Verified: ./adpath enum --quiet | wc -l now returns 1.
"
git push
```

## Boundaries

- **Don't refactor** the global `quietMode` into a struct field. Just use the existing variable.
- **Don't touch** the default rendering path. Only add the new quiet branch + helper function.
- **Don't change** function signatures of `enumerate`, `connectAndBind`, or any other existing functions. Additive change only.
- **Don't add** new flags or options. The `--quiet` flag already exists; just make it work.

The whole task should be a 15-30 line diff in 1-2 files. If your patch is bigger, you're doing too much.
