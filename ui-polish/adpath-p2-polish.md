# adpath HTML report — P2 polish & v1.0 features

P0 + P1 застосовані. Це фінальний polish + features які підсилюють Pro tier value.

## Завдання

### 1. Risk Score (PingCastle-style)

Додай агрегований "Risk Score" 0-100 на summary tab. Чим більше — тим гірше.

В Go (наприклад в `internal/report/score.go`):

```go
package report

type RiskScore struct {
    Total    int
    Grade    string  // A/B/C/D/F
    Breakdown map[string]int  // category → score contribution
}

// Scoring weights (tune based on real engagements)
const (
    WeightCriticalPath     = 15  // per path, max 30
    WeightDangerousACL     = 2   // per finding, max 20
    WeightKerberoastable   = 5   // per account, max 15
    WeightASREPRoastable   = 5   // per account, max 10
    WeightDelegation       = 8   // per finding, max 15
    WeightADCSVuln         = 10  // per template, max 20
    WeightWeakPolicy       = 5   // per critical policy issue, max 15
    WeightStaleAdmin       = 3   // per stale admin, max 10
    WeightNoLAPS           = 1   // per computer without LAPS, max 5
    WeightShadowCreds      = 3   // per finding, max 10
)

func CalculateRiskScore(r *Report) RiskScore {
    breakdown := map[string]int{}

    addCapped := func(key string, value, cap int) {
        if value > cap { value = cap }
        breakdown[key] = value
    }

    addCapped("Attack Paths",
        len(r.Paths) * WeightCriticalPath, 30)
    addCapped("Dangerous ACLs",
        len(r.ACLFindings) * WeightDangerousACL, 20)
    addCapped("Kerberoasting",
        len(r.Kerberoastable) * WeightKerberoastable, 15)
    addCapped("AS-REP Roasting",
        len(r.ASREPRoastable) * WeightASREPRoastable, 10)
    addCapped("Delegation",
        len(r.DelegationFindings) * WeightDelegation, 15)
    addCapped("ADCS",
        len(r.ADCSVulns) * WeightADCSVuln, 20)
    addCapped("Policy",
        countCriticalPolicies(r) * WeightWeakPolicy, 15)
    addCapped("Stale Admins",
        countStaleAdmins(r) * WeightStaleAdmin, 10)
    addCapped("No LAPS",
        len(r.NoLAPSComputers) * WeightNoLAPS, 5)
    addCapped("Shadow Creds",
        len(r.ShadowCredFindings) * WeightShadowCreds, 10)

    total := 0
    for _, v := range breakdown { total += v }
    if total > 100 { total = 100 }

    grade := "A"
    switch {
    case total >= 80: grade = "F"
    case total >= 60: grade = "D"
    case total >= 40: grade = "C"
    case total >= 20: grade = "B"
    }

    return RiskScore{Total: total, Grade: grade, Breakdown: breakdown}
}
```

В summary tab, перед "Findings Overview", додай:

```html
<div class="risk-score-card" style="display:grid;grid-template-columns:auto 1fr;gap:24px;
  padding:24px;background:var(--bg-card);border:1px solid var(--border);
  border-radius:8px;margin-bottom:24px;align-items:center">

  <div style="text-align:center;padding:0 24px;border-right:1px solid var(--border)">
    <div style="font-size:3.5rem;font-weight:800;line-height:1;color:{{.RiskScore.GradeColor}}">
      {{.RiskScore.Grade}}
    </div>
    <div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;
      letter-spacing:0.1em;margin-top:8px">
      Risk Grade
    </div>
    <div style="font-size:1.5rem;font-weight:700;color:var(--text-main);margin-top:12px">
      {{.RiskScore.Total}}<span style="font-size:0.9rem;color:var(--text-muted)">/100</span>
    </div>
  </div>

  <div>
    <div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:12px">
      Risk contribution by category
    </div>
    <div id="risk-breakdown" style="display:flex;flex-direction:column;gap:6px">
      {{range $cat, $score := .RiskScore.Breakdown}}
      {{if gt $score 0}}
      <div style="display:flex;align-items:center;gap:12px;font-size:0.82rem">
        <div style="width:140px;color:var(--text-secondary)">{{$cat}}</div>
        <div style="flex:1;background:var(--bg-hover);border-radius:3px;height:6px;overflow:hidden">
          <div style="width:{{$score}}%;height:100%;background:var(--text-sev-critical)"></div>
        </div>
        <div style="width:40px;text-align:right;color:var(--text-main);font-weight:600">{{$score}}</div>
      </div>
      {{end}}
      {{end}}
    </div>
  </div>
</div>
```

`GradeColor` додай як method:
```go
func (r RiskScore) GradeColor() string {
    switch r.Grade {
    case "A": return "var(--color-ok)"
    case "B": return "#84cc16"
    case "C": return "var(--text-sev-medium)"
    case "D": return "var(--text-sev-high)"
    case "F": return "var(--text-sev-critical)"
    }
    return "var(--text-main)"
}
```

### 2. Executive Summary tab (першою!)

Додай нову вкладку `executive` **першою** перед `summary`. Це 1-page view для CISO/менеджменту.

```html
<button class="active" role="tab" aria-selected="true" aria-controls="tab-executive"
  id="tab-btn-executive" onclick="showTab('executive')">Executive</button>
```

Контент:
```html
<div id="tab-executive" class="tab-pane active" role="tabpanel">

  <!-- Hero: domain + risk grade -->
  <div style="display:grid;grid-template-columns:1fr auto;gap:32px;padding:32px;
    background:var(--bg-card);border:1px solid var(--border);
    border-radius:12px;margin-bottom:24px">
    <div>
      <div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;
        letter-spacing:0.1em;margin-bottom:8px">Active Directory Security Assessment</div>
      <h1 style="font-size:2rem;color:var(--text-main);margin-bottom:8px">
        {{.Domain}}
      </h1>
      <div style="color:var(--text-secondary);font-size:0.9rem">
        Assessed {{.Timestamp}} · {{.UserCount}} users · {{.ComputerCount}} computers · {{.GroupCount}} groups
      </div>
    </div>
    <div style="text-align:center;padding:0 24px;border-left:1px solid var(--border)">
      <div style="font-size:5rem;font-weight:800;line-height:1;color:{{.RiskScore.GradeColor}}">
        {{.RiskScore.Grade}}
      </div>
      <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;
        letter-spacing:0.1em;margin-top:8px">{{.RiskScore.Total}}/100 Risk</div>
    </div>
  </div>

  <!-- Top 5 critical findings -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;
    letter-spacing:.06em;margin-bottom:8px">Top Issues Requiring Immediate Action</div>
  <div style="background:var(--bg-card);border:1px solid var(--border);
    border-radius:8px;margin-bottom:24px;overflow:hidden">
    {{range $i, $issue := .TopIssues}}
    <div style="display:grid;grid-template-columns:24px 1fr auto;gap:16px;
      padding:16px 20px;{{if not (eq $i (sub (len $.TopIssues) 1))}}border-bottom:1px solid var(--border);{{end}}
      align-items:center">
      <div style="font-size:1.2rem;font-weight:700;color:var(--text-sev-critical)">{{add $i 1}}</div>
      <div>
        <div style="font-size:0.95rem;color:var(--text-main);font-weight:600;margin-bottom:4px">
          {{$issue.Title}}
        </div>
        <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.5">
          {{$issue.Description}}
        </div>
      </div>
      <button onclick="showTab('{{$issue.Tab}}')"
        style="background:var(--bg-hover);border:1px solid var(--border);border-radius:6px;
        color:var(--accent);padding:6px 14px;font-size:0.8rem;cursor:pointer;white-space:nowrap">
        View →
      </button>
    </div>
    {{end}}
  </div>

  <!-- Quick stats -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
    gap:12px;margin-bottom:24px">
    <div class="card critical"><div class="value">{{.CriticalCount}}</div><div class="label">Critical Findings</div></div>
    <div class="card warning"><div class="value">{{.HighCount}}</div><div class="label">High Findings</div></div>
    <div class="card"><div class="value">{{len .Paths}}</div><div class="label">Attack Paths</div></div>
    <div class="card"><div class="value">{{len .ACLFindings}}</div><div class="label">Dangerous ACLs</div></div>
  </div>

  <!-- Methodology / scope -->
  <div style="padding:16px 20px;background:var(--bg-grouped);border:1px solid var(--border);
    border-radius:8px;font-size:0.82rem;color:var(--text-secondary);line-height:1.6">
    <strong style="color:var(--text-main)">Scope:</strong> This report enumerates Active Directory
    attack surface via authenticated LDAP queries. Findings include attack paths to privileged groups,
    dangerous ACL permissions, Kerberos delegation issues, and policy misconfigurations.
    Severity ratings follow industry-standard frameworks (MITRE ATT&CK, CIS).
  </div>
</div>
```

В Go додай метод `func (r *Report) TopIssues() []Issue` що повертає top 5 issues по severity:

```go
type Issue struct {
    Title       string
    Description string
    Tab         string  // tab to navigate to
    Severity    string
}

func (r *Report) BuildTopIssues() []Issue {
    var issues []Issue

    // Attack paths to DA/EA — always #1 if exist
    if daPaths := r.PathsToTarget("Domain Admins"); len(daPaths) > 0 {
        issues = append(issues, Issue{
            Title: fmt.Sprintf("%d attack path(s) to Domain Admins", len(daPaths)),
            Description: "Low-privilege accounts can escalate to full domain compromise. Eliminate transitive group memberships and ACL abuse vectors.",
            Tab: "paths", Severity: "Critical",
        })
    }

    // Critical ACL findings
    if criticalACLs := r.ACLBySeverity("Critical"); len(criticalACLs) > 0 {
        issues = append(issues, Issue{
            Title: fmt.Sprintf("%d critical ACL misconfigurations", len(criticalACLs)),
            Description: "Non-admin principals hold WriteDACL, WriteOwner, or GenericAll on privileged groups. These permit privilege escalation without exploiting any vulnerability.",
            Tab: "acl", Severity: "Critical",
        })
    }

    // Kerberoasting
    if len(r.Kerberoastable) > 0 {
        issues = append(issues, Issue{
            Title: fmt.Sprintf("%d Kerberoastable account(s)", len(r.Kerberoastable)),
            Description: "Service accounts with SPNs allow offline password cracking. Use managed service accounts (gMSA) or strong (25+ char) random passwords.",
            Tab: "kerberos", Severity: "High",
        })
    }

    // ADCS
    if len(r.ADCSVulns) > 0 {
        issues = append(issues, Issue{
            Title: fmt.Sprintf("%d vulnerable certificate template(s)", len(r.ADCSVulns)),
            Description: "ESC1-ESC11 misconfigurations enable persistent domain compromise via certificate-based authentication. Patch templates per Microsoft KB5014754.",
            Tab: "adcs", Severity: "Critical",
        })
    }

    // Weak password policy
    if r.HasWeakPasswordPolicy() {
        issues = append(issues, Issue{
            Title: "Weak domain password policy",
            Description: "Minimum length, complexity, or expiry policy fails CIS benchmarks. Update default domain policy to 14+ chars, complexity enabled, max age 365 days.",
            Tab: "summary", Severity: "Critical",
        })
    }

    if len(issues) > 5 { issues = issues[:5] }
    return issues
}
```

Для template helpers `add` і `sub`:
```go
funcMap := template.FuncMap{
    "add": func(a, b int) int { return a + b },
    "sub": func(a, b int) int { return a - b },
}
```

### 3. Diff mode hook (Pro tier)

Підготовка до Pro feature. У Free показуй заглушку, у Pro — реальний diff.

В CLI додай флаг:
```go
enumCmd.Flags().StringVar(&diffWith, "diff-with", "", "Compare with previous report JSON (Pro feature)")
```

Якщо `--diff-with` не вказаний — у summary tab додай блок:

```html
<div style="padding:16px 20px;background:var(--bg-grouped);border:1px dashed var(--border);
  border-radius:8px;margin-bottom:24px;display:flex;gap:16px;align-items:center">
  <div style="font-size:1.5rem">📊</div>
  <div style="flex:1">
    <div style="font-weight:600;color:var(--text-main);margin-bottom:4px">
      Diff Mode — Track Changes Over Time (Pro)
    </div>
    <div style="font-size:0.82rem;color:var(--text-secondary)">
      Compare this scan with previous reports to track new findings, fixed issues, and configuration drift.
    </div>
  </div>
  <a href="https://github.com/YakinAnd/adpath#pro" target="_blank"
    style="background:var(--brand-primary);color:#fff;padding:8px 16px;border-radius:6px;
    text-decoration:none;font-size:0.85rem;font-weight:600;white-space:nowrap">
    Learn more
  </a>
</div>
```

Це робить дві речі: (1) натякає на Pro tier value, (2) валідує feature interest через GitHub clicks.

### 4. Export to JSON button (для diff foundation)

Поряд з `Expand all` / `Collapse all` додай Export JSON:

```html
<button onclick="exportJSON()" title="Export report as JSON for diff/automation">
  Export JSON
</button>
```

В JS:
```javascript
function exportJSON() {
  // Report data is embedded as JSON in <script type="application/json" id="report-data">
  const dataEl = document.getElementById('report-data');
  if (!dataEl) { alert('Report data not available'); return; }
  const blob = new Blob([dataEl.textContent], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'adpath-{{.Domain}}-{{.TimestampISO}}.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
```

В HTML темплейті, перед `<script>` блоком JS, додай:
```html
<script type="application/json" id="report-data">
{{.JSONData}}
</script>
```

В Go:
```go
import "encoding/json"

// Before rendering template
jsonBytes, _ := json.MarshalIndent(report, "", "  ")
report.JSONData = template.JS(jsonBytes)  // template.JS to skip escaping
```

### 5. Print: cover page

Перший print page має бути cover (executive summary). Додай:

```css
@media print {
  .print-cover { display: block !important; page-break-after: always; }
  .print-cover-grade { font-size: 8rem; font-weight: 800; }
}
.print-cover { display: none; }
```

```html
<div class="print-cover" style="text-align:center;padding:80px 40px">
  <h1 style="font-size:2.5rem;margin-bottom:16px">Active Directory Security Assessment</h1>
  <div style="font-size:1.5rem;color:var(--text-secondary);margin-bottom:48px">{{.Domain}}</div>
  <div class="print-cover-grade" style="color:{{.RiskScore.GradeColor}}">{{.RiskScore.Grade}}</div>
  <div style="font-size:1.2rem;color:var(--text-muted);margin-top:16px">
    Risk Score: {{.RiskScore.Total}}/100
  </div>
  <div style="margin-top:80px;color:var(--text-muted)">
    Generated by adpath v{{.Version}} · {{.Timestamp}}
  </div>
</div>
```

## Перевірка

1. `go build ./...`
2. Risk score стабільний для одних і тих же даних (детермінований)
3. Executive tab — 1 екран висоти, без скролу на 1080p
4. Top 5 issues клікабельні, ведуть на правильну вкладку
5. JSON export відкривається `jq` без помилок: `jq . adpath-*.json`
6. Print preview: cover page → executive → решта секцій
7. Commit: `feat(report): risk score, executive summary, JSON export, Pro hook (P2)`

## Бонус — CHANGELOG

Перед фінальним релізом, оновити `CHANGELOG.md`:

```markdown
## [1.0.0] - 2026-04-XX

### Added
- Risk score (0-100) with letter grade (A-F) based on weighted findings
- Executive Summary tab with top 5 critical issues for management consumption
- Print stylesheet with cover page, page breaks, and print-friendly layout
- JSON export for automation and diff workflows
- Copy-to-clipboard buttons for all exploit commands
- ARIA roles and keyboard navigation across all interactive elements
- Footer with version and project link
- Diff mode hook (Pro tier preview)

### Changed
- Severity colors meet WCAG AA contrast on both light/dark themes
- Replaced emoji icons with inline SVG for cross-platform consistency
- ACL groups collapsed by default when >3 groups; per-group lazy render at 50 findings
- Path-specific exploit/fix templates for non-DA targets (GPCO, Operators, DnsAdmins, etc.)
- Unified brand purple palette across logo and accents

### Fixed
- Missing `--badge-high-*` CSS variables in dark theme
- `word-break: break-all` causing mid-word breaks in command blocks
- Generic "transitive DA" exploit text shown for all privileged groups
```
