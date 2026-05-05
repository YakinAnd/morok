# Changelog

## [1.0.0] — 2026-05-05

### CLI (`enum` command)

- **`--quiet` mode** — single-line CI verdict, no ANSI codes, suppresses all section output. Safe for Jenkins, GitHub Actions, GitLab CI log parsers.
  ```
  RISK CRITICAL (F · 83/100) — 38 critical, 40 high, 1 medium
  ```
- **`--verbose` flag** — show all findings without per-section truncation (removed `-v` shorthand to avoid conflict with cobra's built-in version flag)
- **Risk score in footer** — grade + numeric score after every run: `RISK CRITICAL (F · 83/100)`
- **Timing footer** — `enumeration completed in 5.2s`
- **ACL grouping** — findings grouped by principal; targets show word-aware `+N more` instead of mid-word `Replic...` truncation
- **Empty ACL targets filtered** — unresolvable SIDs no longer produce blank `→` arrows
- **Shadow credentials** — grouped with exploit hint: `pywhisker / certipy shadow`
- **Severity counts** — CLI and HTML report now use the same source (`report.CountRiskTotals`) — no discrepancy
- **Removed** duplicate `version` entry from root help; removed `report saved to:` double-print in default mode

### HTML Report

- **Risk contribution bars** — proportional width (bar length = absolute points contributed), sorted by value, color = % of category cap
- **Light theme** — complete fix for hardcoded dark-theme colors:
  - Severity row borders, card values, badge backgrounds now use CSS variables
  - `--bar-sev-*` variables for vivid bar fills in both themes (red/orange/amber)
  - `--node-*` variables for D3 graph nodes, re-applied on theme switch
  - `--mark-*` variables for search highlight
  - Findings chart colors resolve dynamically — update on theme switch
  - Graph tooltip badges use `.badge-*` CSS classes
  - `.cvss-score` uses `--text-main` in light theme for WCAG AA contrast
- **Removed** dead `--sev-medium` CSS variable (replaced by `--text-sev-medium` long ago)
- **Removed** `color.Cyan("report saved to: ...")` print from `report.Generate()` — canonical print is in `runEnum`

### Fixes

- `--quiet` now truly suppresses all output: auth messages in `ldap/client.go`, enumeration progress in `ldap/enumerate.go`, and all section headers in `analysis/` (trusts, hygiene, protected users, AdminSDHolder) — previously only connection logs were suppressed
- Added `analysis.Quiet` package-level variable; `Quiet bool` field on `ldap.Client`

### Internal

- `internal/analysis/quiet.go` — package-level `Quiet bool` for suppressing section prints
- `internal/analysis/severity_counts.go` — shared `SeverityCounts` struct
- `internal/report/score.go` — `RiskScore`, `BreakdownEntry`, `SortedBreakdown()`
- `internal/report/executive.go` — executive summary helpers
- `report.CountRiskTotals()` exported (was unexported) — used by CLI and HTML generator

## [0.3.0] — earlier

- Initial public release with `enum`, `kerberos`, `acl` commands
- HTML report with D3.js attack path graph
- ADCS ESC1–ESC8 detection
- Delegation analysis
- Trust analysis
- Shadow credentials detection
- SYSVOL scan
- LAPS ACL analysis
