# Changelog

## [1.0.1] — 2026-05-09

### CLI

- **Per-domain output sections** — `══ domain.local ══` separator headers; each domain's findings in its own named block when trusts are followed
- **Severity prefixes** — `[+++]` critical (red bold), `[++]` high (red), `[+]` medium (yellow); removed `[-]` which looked like an absence of findings
- **Banner** — matches HTML report branding: `MOROK / SEE · THROUGH · THE · FOG / v1.0 · AD Attack Path Analysis`
- **Duplicate messages** — removed duplicate "querying domain" line on trust enumeration; unified to `enumerating <domain>...`

### HTML Report

- **SID-based computer deduplication** — GC forest query and trusted-domain enumeration no longer produce duplicate computer rows; deduplicated at merge by ObjectSID
- **Group filter — Domain Users** — Users tab filter now checks both `Member Of` and `Primary Group` columns; `Domain Users` and other primary-group-only members are found correctly
- **Group filter dropdown** — options deduplicated across all domains; no repeated group names
- **ADCS domain badge** — source domain shown as a styled badge (consistent with Attack Paths tab) instead of plain `/domain` text

### Analysis — fixes

- **INHERIT_ONLY_ACE** — ACEs with flag 0x08 now correctly skipped in DACL parsing; eliminates false-positive `WriteProperty(all)` findings on container-propagated ACEs that apply only to child objects
- **LDAP signing accuracy** — `SigningEnforced` is only set when tested over port 389; LDAPS connections no longer produce a false "enforced" result; added `SigningChecked bool` to `LDAPSecurityResult`
- **ESC2 RA-signature guard** — `msPKI-RA-Signature > 0` now correctly blocks ESC2 classification; RA countersign required means not directly exploitable
- **FSP transitive membership** — trust analysis walks group membership transitively via BFS (up to 200 nodes, cycle-safe) to detect Foreign Security Principals reaching privileged groups through nested groups
- **RBCD trustee resolution** — RBCD analysis now resolves trustee names from the security descriptor instead of using raw SIDs
- **DnsAdmins detection** — members of DnsAdmins are now detected and reported (ServerLevelPluginDll → DC SYSTEM path)
- **Shadow credentials** — now covers `adminCount=1` targets in addition to named DA/EA/DC objects; SMARTCARD_REQUIRED+adminCount detection added

### Analysis — new display fields

All 8 fields below were collected but never printed in prior releases:

- **OwnerFindings** — non-default owners on privileged AD objects (console + HTML ACL tab)
- **GMSAFindings** — principals that can read gMSA managed passwords (console + HTML LAPS tab)
- **LockoutDuration / MinPwdAge** — now shown in console GPO output and HTML Policy tab
- **PasswordNotRequired** — accounts with UAC PASSWD_NOTREQD (console + HTML Exposure tab)
- **SmartcardRequired+AdminCount** — privileged accounts where hash never rotates (console + HTML Exposure tab)
- **DnsAdmins members** — non-privileged members (console + HTML Exposure tab)
- **Pre-Windows 2000 Compatible Access** — when Everyone/Authenticated Users is a member (console + HTML Exposure tab)

### HTML Report

- **Non-Default Owners section** — ACL tab now shows OwnerFindings with CVSS scores and fix guidance
- **gMSA Password Readers section** — LAPS tab; principals that can retrieve managed passwords
- **Exposure tab** — 5 new sections: gMSA Readers, Passwd Not Required, Smartcard+AdminCount, DnsAdmins Members, Pre-Win2000 Access
- **Logo L3** — light theme inverts text colors only (`#1a1f2e` wordmark, `#8a6a3e` tagline); SVG uses bronze lines and cream rhombus on cream background; no plate, no gradient, no layout shift on theme toggle
- **Header layout fixes** — `#theme-toggle` is now a flex item (no longer `position:absolute`, no overlap with badges); `.meta` is `flex:0 0 auto`; `.findings-row` uses `margin-left:auto`; nav `::after` right buffer reduced 28px→8px
- **`lower` template function** — registered missing function that caused a parse error when reports included severity-class CSS class generation

---

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
