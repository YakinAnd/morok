# morok MCP — Snapshot v2 + Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Version the embedded `morok-data` report snapshot from v1 to v2 with structured findings (severity/CVSS), add a `vulns` category so `--vuln-check` findings participate in History-tab diffing, add attack-path edges, and build a Go parser that reads a v2 snapshot back out of a generated `.html` report — the foundation the `morok mcp` server (later plan) will read from.

**Architecture:** `internal/report/snapshot.go` (new file) holds named, exported snapshot types and the rewritten `buildSnapshot` function (moved out of `html.go`, same package, same call site in `Generate()`). `internal/mcpserver/parser.go` (new package) extracts the embedded `<script id="morok-data">` block from an `.html` file and unmarshals it into `report.Snapshot`, rejecting anything below v2.

**Tech Stack:** Go 1.26, stdlib only (`encoding/json`, `regexp`, `os`) — no new external dependencies in this plan.

## Global Constraints

- Go version: 1.26 (per `go.mod`) — no new dependencies added in this plan.
- Never include "Claude" or "Anthropic" anywhere — code, comments, commit messages. No `Claude-Session:` trailer on commits.
- Never `git push` unless explicitly asked. Commit locally after each task.
- Table-driven tests matching the existing style in `internal/analysis/vulns_test.go` (`cases := []struct{...}{...}` + range loop with `t.Errorf`).
- This is purely additive to the JSON wire format: v1 snapshots must remain loadable by the existing History-tab JS exactly as today (verified: that JS only ever reads `.length` of `findings[category]` arrays — never inspects individual entries — so changing entries from strings to objects breaks nothing there).
- Run on branch `feat/c4-mcp-server` (already exists, holds the approved design spec at `docs/superpowers/specs/2026-07-26-morok-mcp-design.md`).

---

### Task 1: Snapshot v2 schema — named types + structured findings + attack-path edges

**Files:**
- Create: `internal/report/snapshot.go`
- Modify: `internal/report/html.go:606-...` (remove the old inline `buildSnapshot` — delete the whole function, its call site `data.SnapshotJSON = buildSnapshot(&data)` in `Generate()` stays unchanged since the function name and package are the same)
- Test: `internal/report/snapshot_test.go` (new file)

**Interfaces:**
- Produces: `report.Snapshot`, `report.SnapshotScore`, `report.SnapshotCounts`, `report.SnapshotFinding{Summary, Severity, CVSS, Detail, Remediation}`, `report.SnapshotAttackPath{Summary, TargetGroup, Depth, Edges}`, `report.SnapshotEdge{From, To, Type}` — all exported, consumed by Task 3 (parser) and by the later MCP-server plan.
- Consumes: existing `report.ReportData` fields (`KerberosResult`, `ACLResult`, `DelegationResult`, `AttackPaths`, `ADCSResult`, `ShadowCredentialsResult`, `GPOResult`, `RiskScore`, `TotalCritical/High/Medium`, `GeneratedAt`, `Domain`, `Version`) — unchanged, already defined in `html.go`.

- [ ] **Step 1: Find and read the current `buildSnapshot` to confirm exact field names before removing it**

Run: `grep -n "func buildSnapshot" -A 90 internal/report/html.go`

Confirm the function body matches what's described in this plan (field names `d.KerberosResult`, `d.ACLResult.Findings[].PrincipalName/.Right/.TargetName`, etc.) — if the source has drifted since this plan was written, adjust the code below to match the actual current field names before proceeding.

- [ ] **Step 2: Write the failing test**

Create `internal/report/snapshot_test.go`:

```go
package report

import (
	"encoding/json"
	"testing"

	"github.com/YakinAnd/morok/internal/analysis"
	"github.com/YakinAnd/morok/internal/graph"
)

func TestBuildSnapshot_V2Shape(t *testing.T) {
	d := &ReportData{
		GeneratedAt: "2026-07-26 10:00:00",
		Domain:      "test.local",
		Version:     "1.3.0",
		RiskScore:   RiskScore{Grade: "C", Total: 53},
		ACLResult: &analysis.ACLResult{
			Findings: []analysis.ACLFinding{
				{PrincipalName: "tyrion", Right: analysis.RightWriteDACL, TargetName: "Small Council", Severity: "Critical", CVSS: 9.1},
			},
		},
		AttackPaths: []graph.AttackPath{
			{
				Nodes:       []graph.Node{{SAMAccountName: "jsnow"}, {SAMAccountName: "Domain Admins"}},
				Edges:       []graph.Edge{{From: "CN=jsnow", To: "CN=Domain Admins", Type: graph.EdgeMemberOf}},
				Depth:       1,
				TargetGroup: "Domain Admins",
			},
		},
	}

	js := buildSnapshot(d)

	var snap Snapshot
	if err := json.Unmarshal([]byte(js), &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	if snap.V != 2 {
		t.Errorf("V = %d, want 2", snap.V)
	}

	acl := snap.Findings["acl"]
	if len(acl) != 1 {
		t.Fatalf("Findings[acl] len = %d, want 1", len(acl))
	}
	if acl[0].Severity != "Critical" || acl[0].CVSS != 9.1 {
		t.Errorf("acl[0] = %+v, want Severity=Critical CVSS=9.1", acl[0])
	}
	if acl[0].Summary != "tyrion|WriteDACL|Small Council" {
		t.Errorf("acl[0].Summary = %q, want %q", acl[0].Summary, "tyrion|WriteDACL|Small Council")
	}

	if len(snap.AttackPaths) != 1 {
		t.Fatalf("AttackPaths len = %d, want 1", len(snap.AttackPaths))
	}
	ap := snap.AttackPaths[0]
	if ap.TargetGroup != "Domain Admins" || ap.Depth != 1 {
		t.Errorf("AttackPaths[0] = %+v, want TargetGroup=Domain Admins Depth=1", ap)
	}
	if len(ap.Edges) != 1 || ap.Edges[0].From != "CN=jsnow" || ap.Edges[0].To != "CN=Domain Admins" || ap.Edges[0].Type != "MemberOf" {
		t.Errorf("AttackPaths[0].Edges = %+v, want one MemberOf edge CN=jsnow->CN=Domain Admins", ap.Edges)
	}
}

func TestBuildSnapshot_EmptyReportDataNoPanic(t *testing.T) {
	d := &ReportData{}
	js := buildSnapshot(d)
	var snap Snapshot
	if err := json.Unmarshal([]byte(js), &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap.V != 2 {
		t.Errorf("V = %d, want 2", snap.V)
	}
}
```

- [ ] **Step 2b: Run the test to verify it fails**

Run: `go test ./internal/report/... -run TestBuildSnapshot -v`
Expected: FAIL — `Snapshot`/`SnapshotFinding`/etc. are undefined (they don't exist until Step 3).

- [ ] **Step 3: Delete the old `buildSnapshot` from `html.go` and create `internal/report/snapshot.go`**

In `internal/report/html.go`, delete the entire existing `buildSnapshot` function (the one starting `func buildSnapshot(d *ReportData) template.JS {` and its local anonymous `snapshot`/`snapScore`/`snapCounts` types) — everything between the `// Snapshot builder` comment block and the function's closing `}`. Leave the call site in `Generate()` (`data.SnapshotJSON = buildSnapshot(&data)`) untouched.

Create `internal/report/snapshot.go`:

```go
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/YakinAnd/morok/internal/analysis"
)

// Snapshot is the schema for the embedded `morok-data` JSON block in every
// HTML report. It has two consumers: the History tab's JS-side diffing
// (interested only in per-category counts — see _HIST_CATEGORIES in
// html.go, which only ever calls .length on findings[category]) and the
// `morok mcp` reader (internal/mcpserver), interested in the full
// structured fields. Bumping V does not break old (v1) reports loaded as
// History-tab baselines — the JS loader never inspects individual entries.
type Snapshot struct {
	V           int                          `json:"v"`
	GeneratedAt string                       `json:"generated_at"`
	Domain      string                       `json:"domain"`
	Version     string                       `json:"version"`
	Score       SnapshotScore                `json:"score"`
	Counts      SnapshotCounts               `json:"counts"`
	Findings    map[string][]SnapshotFinding `json:"findings"`
	AttackPaths []SnapshotAttackPath         `json:"attack_paths,omitempty"`
}

type SnapshotScore struct {
	Grade string `json:"grade"`
	Value int    `json:"value"`
}

type SnapshotCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// SnapshotFinding is one structured finding entry. Severity/CVSS/Detail/
// Remediation are populated only where the source finding struct actually
// carries that data (see field comments below in buildSnapshot) — omitted
// rather than fabricated where it doesn't exist yet.
type SnapshotFinding struct {
	Summary     string  `json:"summary"`
	Severity    string  `json:"severity,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
}

type SnapshotAttackPath struct {
	Summary     string         `json:"summary"`
	TargetGroup string         `json:"target_group"`
	Depth       int            `json:"depth"`
	Edges       []SnapshotEdge `json:"edges"`
}

type SnapshotEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// buildSnapshot serializes a compact-but-structured fingerprint of all
// findings into JSON, embedded in the HTML report so that (a) other reports
// can load this file as a History-tab baseline, and (b) `morok mcp` can
// read a single report's findings without parsing HTML.
func buildSnapshot(d *ReportData) template.JS {
	snap := Snapshot{
		V:           2,
		GeneratedAt: d.GeneratedAt,
		Domain:      d.Domain,
		Version:     d.Version,
		Score:       SnapshotScore{Grade: d.RiskScore.Grade, Value: d.RiskScore.Total},
		Counts:      SnapshotCounts{Critical: d.TotalCritical, High: d.TotalHigh, Medium: d.TotalMedium},
		Findings:    make(map[string][]SnapshotFinding),
	}
	f := snap.Findings

	if d.KerberosResult != nil {
		for _, acc := range d.KerberosResult.KerberoastableAccounts {
			f["kerberoastable"] = append(f["kerberoastable"], SnapshotFinding{
				Summary: acc.SAMAccountName, Severity: acc.Severity, CVSS: acc.CVSS,
			})
		}
		for _, acc := range d.KerberosResult.ASREPAccounts {
			f["asrep"] = append(f["asrep"], SnapshotFinding{
				Summary: acc.SAMAccountName, Severity: acc.Severity, CVSS: acc.CVSS,
			})
		}
	}

	if d.ACLResult != nil {
		for _, af := range d.ACLResult.Findings {
			f["acl"] = append(f["acl"], SnapshotFinding{
				Summary:  af.PrincipalName + "|" + string(af.Right) + "|" + af.TargetName,
				Severity: af.Severity, CVSS: af.CVSS,
			})
		}
	}

	if d.DelegationResult != nil {
		for _, df := range d.DelegationResult.Findings {
			switch df.DelegationType {
			case analysis.DelegationUnconstrained:
				f["unconstrained_deleg"] = append(f["unconstrained_deleg"], SnapshotFinding{
					Summary: df.SAMAccountName, Severity: df.Severity, CVSS: df.CVSS,
				})
			case analysis.DelegationConstrained:
				f["constrained_deleg"] = append(f["constrained_deleg"], SnapshotFinding{
					Summary:  df.SAMAccountName + "|" + strings.Join(df.AllowedServices, ","),
					Severity: df.Severity, CVSS: df.CVSS,
				})
			case analysis.DelegationRBCD:
				f["rbcd"] = append(f["rbcd"], SnapshotFinding{
					Summary:  df.SAMAccountName + "|" + strings.Join(df.TrusteeNames, ","),
					Severity: df.Severity, CVSS: df.CVSS,
				})
			}
		}
	}

	for _, path := range d.AttackPaths {
		if len(path.Nodes) == 0 {
			continue
		}
		summary := fmt.Sprintf("%s→%s(%dhops)", path.Nodes[0].SAMAccountName, path.TargetGroup, path.Depth)
		edges := make([]SnapshotEdge, len(path.Edges))
		for i, e := range path.Edges {
			edges[i] = SnapshotEdge{From: e.From, To: e.To, Type: string(e.Type)}
		}
		snap.AttackPaths = append(snap.AttackPaths, SnapshotAttackPath{
			Summary: summary, TargetGroup: path.TargetGroup, Depth: path.Depth, Edges: edges,
		})
		f["attack_paths"] = append(f["attack_paths"], SnapshotFinding{Summary: summary})
	}

	if d.ADCSResult != nil {
		for _, tf := range d.ADCSResult.TemplateFindings {
			vulnTypes := make([]string, len(tf.VulnTypes))
			for i, v := range tf.VulnTypes {
				vulnTypes[i] = string(v)
			}
			f["adcs_templates"] = append(f["adcs_templates"], SnapshotFinding{
				Summary:  tf.TemplateName + "|" + strings.Join(vulnTypes, "/"),
				Severity: tf.Severity, CVSS: tf.CVSS,
			})
		}
	}

	if d.ShadowCredentialsResult != nil {
		for _, sf := range d.ShadowCredentialsResult.Findings {
			f["shadow_creds"] = append(f["shadow_creds"], SnapshotFinding{
				Summary:  sf.PrincipalName + "|" + sf.TargetName,
				Severity: sf.Severity, CVSS: sf.CVSS,
			})
		}
	}

	if d.GPOResult != nil {
		for _, af := range d.GPOResult.GPOACLFindings {
			f["gpo_write"] = append(f["gpo_write"], SnapshotFinding{
				Summary:  af.PrincipalName + "|" + af.GPOName,
				Severity: af.Severity, CVSS: af.CVSS,
			})
		}
		for _, gpo := range d.GPOResult.GPOFindings {
			if gpo.HasCPassword {
				f["gpp_passwords"] = append(f["gpp_passwords"], SnapshotFinding{Summary: gpo.Name})
			}
		}
	}

	b, _ := json.Marshal(snap)
	return template.JS(b)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/report/... -run TestBuildSnapshot -v`
Expected: PASS

- [ ] **Step 5: Run the full existing report test suite to confirm nothing else broke**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green, including the pre-existing `TestGenerateReport` in `internal/report/html_test.go` (it doesn't assert the raw JSON shape of `morok-data`, only HTML content markers, so it should be unaffected).

- [ ] **Step 6: Commit**

```bash
git add internal/report/snapshot.go internal/report/snapshot_test.go internal/report/html.go
git commit -m "$(cat <<'EOF'
feat: version report snapshot to v2 with structured findings + attack-path edges

Adds named exported types (Snapshot, SnapshotFinding, SnapshotAttackPath,
SnapshotEdge) so severity/CVSS and full path edges are available to
consumers beyond the History tab's count-only diffing, without breaking
v1 report compatibility.
EOF
)"
```

---

### Task 2: `vulns` category from `VulnResult` + History-tab category registration

**Files:**
- Modify: `internal/report/snapshot.go` (add `vulns` category to `buildSnapshot`)
- Modify: `internal/report/html.go` (one-line addition to the `_HIST_CATEGORIES` JS array)
- Test: `internal/report/snapshot_test.go` (add a case)

**Interfaces:**
- Consumes: `d.VulnResult *analysis.VulnResult` (already a field on `ReportData`, populated in `cmd/morok/main.go`), `analysis.VulnFinding{Host, FQDN, CVE, Name, Status, Detail, Remediation}`, `analysis.VulnStatus` constants (`VulnCandidate`, `VulnConfirmed`, `VulnUnreachable` — `VulnSafe` findings are never present in `VulnResult.Findings`, already filtered out by `RunVulnChecks`).
- Produces: `snap.Findings["vulns"]` populated — read by Task 3's parser tests and later by the MCP server's blueteam/redteam tools.

- [ ] **Step 1: Write the failing test**

Add to `internal/report/snapshot_test.go`:

```go
func TestBuildSnapshot_VulnsCategory(t *testing.T) {
	d := &ReportData{
		VulnResult: &analysis.VulnResult{
			Findings: []analysis.VulnFinding{
				{
					Host: "DC01$", FQDN: "dc01.corp.local", CVE: "CVE-2020-1472", Name: "Zerologon",
					Status: analysis.VulnCandidate, Detail: "DC running Windows Server 2016",
					Remediation: "Apply August 2020 CU.",
				},
				{
					Host: "WS-XP01$", FQDN: "ws-xp01.corp.local", CVE: "MS17-010", Name: "EternalBlue",
					Status: analysis.VulnConfirmed, Detail: "Trans2 probe confirmed",
					Remediation: "Apply KB4012212.",
				},
			},
		},
	}

	js := buildSnapshot(d)

	var snap Snapshot
	if err := json.Unmarshal([]byte(js), &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	vulns := snap.Findings["vulns"]
	if len(vulns) != 2 {
		t.Fatalf("Findings[vulns] len = %d, want 2", len(vulns))
	}
	if vulns[0].Summary != "CVE-2020-1472|Zerologon|candidate|DC01$" {
		t.Errorf("vulns[0].Summary = %q, want %q", vulns[0].Summary, "CVE-2020-1472|Zerologon|candidate|DC01$")
	}
	if vulns[0].Detail != "DC running Windows Server 2016" || vulns[0].Remediation != "Apply August 2020 CU." {
		t.Errorf("vulns[0] detail/remediation = %+v", vulns[0])
	}
	if vulns[1].Summary != "MS17-010|EternalBlue|confirmed|WS-XP01$" {
		t.Errorf("vulns[1].Summary = %q, want %q", vulns[1].Summary, "MS17-010|EternalBlue|confirmed|WS-XP01$")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/report/... -run TestBuildSnapshot_VulnsCategory -v`
Expected: FAIL — `Findings["vulns"]` is empty (len 0), because `buildSnapshot` doesn't handle `VulnResult` yet.

- [ ] **Step 3: Add the `vulns` category to `buildSnapshot`**

In `internal/report/snapshot.go`, inside `buildSnapshot`, after the `GPOResult` block and before `b, _ := json.Marshal(snap)`, add:

```go
	if d.VulnResult != nil {
		for _, vf := range d.VulnResult.Findings {
			status := "candidate"
			switch vf.Status {
			case analysis.VulnConfirmed:
				status = "confirmed"
			case analysis.VulnUnreachable:
				status = "unreachable"
			}
			f["vulns"] = append(f["vulns"], SnapshotFinding{
				Summary:     vf.CVE + "|" + vf.Name + "|" + status + "|" + vf.Host,
				Detail:      vf.Detail,
				Remediation: vf.Remediation,
			})
		}
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/report/... -run TestBuildSnapshot_VulnsCategory -v`
Expected: PASS

- [ ] **Step 5: Register `vulns` in the History tab's category list**

In `internal/report/html.go`, find the `_HIST_CATEGORIES` JS array (currently around line 4513):

```js
var _HIST_CATEGORIES = [
  { key: 'kerberoastable',    label: 'Kerberoastable',          tab: 'kerberos' },
  ...
  { key: 'gpp_passwords',     label: 'GPP Passwords',           tab: 'gpo' },
];
```

Add one entry before the closing `];`:

```js
  { key: 'vulns',             label: 'Vulnerability Checks',    tab: 'computers' },
```

- [ ] **Step 6: Run the full test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 7: Manual verification of the History-tab JS change**

Run: `go run ./cmd/gendemo2` (already produces `demo-before.html`/`demo-middle.html`/`demo-after.html` with vuln findings via `buildVulnResult()`), then open `demo-after.html` in a browser, go to the **History** tab, load `demo-before.html` as a baseline, and confirm "Vulnerability Checks" appears in the Regressions/Resolved/Outstanding breakdown (it will show under whichever bucket matches the vuln finding counts between the two demo scenarios — since `buildVulnResult()` is currently identical across all three demo scenarios, expect it to land in "Outstanding", not zero/missing).

- [ ] **Step 8: Commit**

```bash
git add internal/report/snapshot.go internal/report/snapshot_test.go internal/report/html.go
git commit -m "$(cat <<'EOF'
fix: include --vuln-check findings in report snapshot for History-tab diffing

buildSnapshot previously had no handling for analysis.VulnResult at all, so
EternalBlue/Zerologon/noPac/PetitPotam/PrintNightmare findings never showed
up as Regressions/Resolved/Outstanding on the History tab, unlike every
other finding category. Risk Score is unaffected — vuln findings still
don't contribute to the computed score, unchanged from the existing design.
EOF
)"
```

---

### Task 3: `internal/mcpserver` parser — extract + unmarshal + version gate

**Files:**
- Create: `internal/mcpserver/parser.go`
- Test: `internal/mcpserver/parser_test.go`

**Interfaces:**
- Consumes: `report.Snapshot` (from Task 1/2).
- Produces: `mcpserver.ParseReport(path string) (*report.Snapshot, error)` — the function the (later, separate plan) `morok mcp` CLI subcommand and MCP tool handlers will call to load report data.

- [ ] **Step 1: Create the package directory and write the failing tests**

Run: `mkdir -p internal/mcpserver`

Create `internal/mcpserver/parser_test.go`:

```go
package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestReport(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("writing test report: %v", err)
	}
	return path
}

const v2Body = `<html><body>
<script type="application/json" id="morok-data">{"v":2,"generated_at":"2026-07-26 10:00:00","domain":"corp.local","version":"1.3.0","score":{"grade":"C","value":53},"counts":{"critical":1,"high":2,"medium":3},"findings":{"acl":[{"summary":"tyrion|WriteDACL|Small Council","severity":"Critical","cvss":9.1}]}}</script>
</body></html>`

func TestParseReport_ValidV2(t *testing.T) {
	path := writeTestReport(t, v2Body)

	snap, err := ParseReport(path)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if snap.V != 2 {
		t.Errorf("V = %d, want 2", snap.V)
	}
	if snap.Domain != "corp.local" {
		t.Errorf("Domain = %q, want corp.local", snap.Domain)
	}
	acl := snap.Findings["acl"]
	if len(acl) != 1 || acl[0].Severity != "Critical" {
		t.Errorf("Findings[acl] = %+v", acl)
	}
}

func TestParseReport_RejectsV1(t *testing.T) {
	v1Body := `<html><body>
<script type="application/json" id="morok-data">{"v":1,"generated_at":"2026-06-01 10:00:00","domain":"corp.local","findings":{"acl":["tyrion|WriteDACL|Small Council"]}}</script>
</body></html>`
	path := writeTestReport(t, v1Body)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for v1 report, got nil")
	}
	if !strings.Contains(err.Error(), "older morok version") {
		t.Errorf("error = %q, want it to mention 'older morok version'", err.Error())
	}
}

func TestParseReport_MissingScriptBlock(t *testing.T) {
	path := writeTestReport(t, `<html><body><p>not a morok report</p></body></html>`)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for missing morok-data block, got nil")
	}
	if !strings.Contains(err.Error(), "no embedded morok-data") {
		t.Errorf("error = %q, want it to mention 'no embedded morok-data'", err.Error())
	}
}

func TestParseReport_MalformedJSON(t *testing.T) {
	path := writeTestReport(t, `<html><body>
<script type="application/json" id="morok-data">{not valid json</script>
</body></html>`)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParseReport_FileNotFound(t *testing.T) {
	_, err := ParseReport(filepath.Join(t.TempDir(), "does-not-exist.html"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/mcpserver/... -v`
Expected: FAIL to build — `ParseReport` is undefined (package doesn't exist yet beyond the test file).

- [ ] **Step 3: Write `internal/mcpserver/parser.go`**

```go
package mcpserver

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/YakinAnd/morok/internal/report"
)

var morokDataRe = regexp.MustCompile(`(?s)<script[^>]*id="morok-data"[^>]*>(.*?)</script>`)

// ParseReport reads a morok HTML report from path and returns its embedded
// snapshot. Returns an error if the file can't be read, the morok-data
// script block is missing or its JSON can't be parsed, or the report
// predates the v2 schema (v1 reports don't carry the structured
// severity/CVSS/remediation data the MCP tools need).
func ParseReport(path string) (*report.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading report %s: %w", path, err)
	}

	m := morokDataRe.FindSubmatch(data)
	if m == nil {
		return nil, fmt.Errorf("%s does not look like a morok report (no embedded morok-data block found)", path)
	}

	var snap report.Snapshot
	if err := json.Unmarshal(m[1], &snap); err != nil {
		return nil, fmt.Errorf("parsing morok-data in %s: %w", path, err)
	}

	if snap.V < 2 {
		return nil, fmt.Errorf("%s was generated by an older morok version (schema v%d) — regenerate the report with a version that supports vuln-check/MCP data", path, snap.V)
	}

	return &snap, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS for all 5 tests.

- [ ] **Step 5: Run the full project test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 6: Manual smoke test against a real generated report**

Run:
```bash
go run ./cmd/gendemo2
cat > /tmp/parse_smoke.go <<'EOF'
package main

import (
	"fmt"
	"github.com/YakinAnd/morok/internal/mcpserver"
)

func main() {
	snap, err := mcpserver.ParseReport("demo-after.html")
	if err != nil {
		panic(err)
	}
	fmt.Printf("domain=%s grade=%s vulns=%d\n", snap.Domain, snap.Score.Grade, len(snap.Findings["vulns"]))
}
EOF
go run /tmp/parse_smoke.go
rm /tmp/parse_smoke.go
```
Expected output: `domain=sevenkingdoms.local grade=<some letter> vulns=7` (7 matches the number of findings in `buildVulnResult()` in `cmd/gendemo2/main.go`).

- [ ] **Step 7: Commit**

```bash
git add internal/mcpserver/parser.go internal/mcpserver/parser_test.go
git commit -m "$(cat <<'EOF'
feat: add internal/mcpserver report parser

Extracts and unmarshals the embedded morok-data JSON snapshot from a
generated .html report, rejecting v1 (pre-vuln-check/MCP) reports with a
clear regenerate-the-report error. Foundation for the morok mcp server.
EOF
)"
```

---

## Self-Review Notes (already applied above)

- **Spec coverage:** Covers ADP-198 (schema v2 + named types), ADP-199 (vulns category + History registration), ADP-200 (attack path edges, folded into Task 1), ADP-201 (parser). Does **not** cover ADP-202–208 (MCP SDK wiring, tool implementations, CLI subcommand) or ADP-209 (exploit-command extraction) — those need their own plan(s), written after the Go MCP SDK choice is verified against its actual current API (not guessed), per the design spec's open questions.
- **Placeholder scan:** No TBD/TODO; every step has real, complete code.
- **Type consistency:** `SnapshotFinding`, `SnapshotAttackPath`, `SnapshotEdge` field names are identical across Task 1's definition, Task 2's addition, and Task 3's parser test fixtures (`summary`/`severity`/`cvss`/`detail`/`remediation` JSON tags match the Go struct tags exactly).
