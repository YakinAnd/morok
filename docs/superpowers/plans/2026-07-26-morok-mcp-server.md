# morok MCP — Server, Tools, CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the official Go MCP SDK (`github.com/modelcontextprotocol/go-sdk`) into a new `internal/mcpserver` server (building on the `ParseReport`/`report.Snapshot` foundation from the prior snapshot-v2 plan), register shared, blueteam, and redteam tool sets over a loaded report, and expose it via a new `morok mcp --report <file>` CLI subcommand.

**Architecture:** `internal/mcpserver/server.go` holds `Serve(ctx, path) error` — loads the report via the existing `ParseReport`, constructs an `*mcp.Server`, registers every tool set, and runs the stdio transport (blocks until the client disconnects). Each tool set lives in its own file (`tools_shared.go` created alongside `server.go` in Task 1, `tools_blueteam.go` in Task 2, `tools_redteam.go` in Task 3) as a `registerXTools(server, snap)` function. Every tool handler is a named function `xHandler(snap) func(ctx, req, in) (*mcp.CallToolResult, Out, error)` — this makes every handler directly callable and testable as a plain Go function, without needing to run the MCP server or understand its internal dispatch.

**Tech Stack:** Go 1.26, `github.com/modelcontextprotocol/go-sdk/mcp` (new dependency — official MCP SDK, requires Go 1.25+, no version conflict).

## Global Constraints

- Go version: 1.26 (per go.mod).
- New dependency this plan introduces: `github.com/modelcontextprotocol/go-sdk`. Add it by importing the package in code and running `go mod tidy` (requires network access) — do not hand-edit go.mod version numbers.
- Never include "Claude" or "Anthropic" anywhere — code, comments, commit messages. No `Claude-Session:` trailer on commits.
- Never `git push`.
- **`Serve()` blocks forever on stdio via `server.Run(ctx, &mcp.StdioTransport{})` once it reaches that call.** Never call `Serve()` with a *valid* report path inside a test — it will hang the test suite. Only exercise `Serve()`'s error path (missing/invalid report, which returns before reaching `server.Run`). Test every tool's actual logic by calling its handler function directly (e.g. `getReportSummaryHandler(snap)(context.Background(), nil, NoArgs{})`), never through a running server.
- `get_exploit_commands` is explicitly OUT OF SCOPE for this plan — it's blocked by a separate follow-up (extracting exploit-command builders out of `internal/report/html.go`'s template FuncMap closures into reusable functions). Do not attempt to implement it here.
- Multi-report sessions and live scanning through the MCP server are out of scope (per the design spec) — this plan only reads one already-generated report per process lifetime.
- This plan builds on `internal/mcpserver/parser.go` (`ParseReport`) and `internal/report/snapshot.go` (`Snapshot`, `SnapshotFinding`, `SnapshotAttackPath`, `SnapshotEdge`) from the prior plan — read those files before starting if their exact field names are unclear.

---

### Task 1: MCP SDK wiring + `morok mcp` CLI subcommand + shared tools

**Files:**
- Create: `internal/mcpserver/server.go`
- Create: `internal/mcpserver/tools_shared.go`
- Modify: `cmd/morok/main.go` (add `mcp` subcommand)
- Test: `internal/mcpserver/server_test.go`

**Interfaces:**
- Consumes: `mcpserver.ParseReport(path string) (*report.Snapshot, error)` (existing), `report.Snapshot{V, Domain, GeneratedAt, Version, Score{Grade,Value}, Counts{Critical,High,Medium}, Findings map[string][]SnapshotFinding, AttackPaths []SnapshotAttackPath}` (existing).
- Produces: `mcpserver.Serve(ctx context.Context, path string) error` — the function the CLI subcommand calls. `mcpserver.NoArgs` (empty struct, used by every zero-parameter tool in this and later tasks). `mcpserver.ReportSummary`, `mcpserver.CategoryList` (Out types for this task's two tools). `getReportSummaryHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, ReportSummary, error)` and `listCategoriesHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, CategoryList, error)` — later tasks follow this exact same "named function returning a closure" shape for every tool handler.

- [ ] **Step 1: Confirm current anchors in `cmd/morok/main.go` before editing**

Run: `grep -n "var versionCmd\|rootCmd.AddCommand(versionCmd)\|vulnCheck.*bool\|followTrusts.*bool" cmd/morok/main.go`

You'll use `versionCmd`'s definition as the pattern for the new `mcpCmd`, and its `rootCmd.AddCommand(versionCmd)` line as the anchor to add `rootCmd.AddCommand(mcpCmd)` next to. If these anchors have moved or been renamed since this plan was written, adapt the insertion points below accordingly — the pattern (a simple `cobra.Command` with `RunE`, registered in `init()`) is what matters, not exact line numbers.

- [ ] **Step 2: Write the failing tests**

Create `internal/mcpserver/server_test.go`:

```go
package mcpserver

import (
	"context"
	"testing"

	"github.com/YakinAnd/morok/internal/report"
)

func testSnapshot() *report.Snapshot {
	return &report.Snapshot{
		V: 2, Domain: "corp.local", GeneratedAt: "2026-07-26 10:00:00", Version: "1.2.2",
		Score:  report.SnapshotScore{Grade: "C", Value: 53},
		Counts: report.SnapshotCounts{Critical: 1, High: 2, Medium: 3},
		Findings: map[string][]report.SnapshotFinding{
			"acl": {
				{Summary: "tyrion|WriteDACL|Small Council", Severity: "Critical", CVSS: 9.1},
			},
			"vulns": {
				{Summary: "MS17-010|EternalBlue|confirmed|OLDMAESTER$", Detail: "Windows Server 2008 R2, build 7601", Remediation: "Apply KB4012212."},
				{Summary: "CVE-2021-36942|PetitPotam|candidate|KINGSLANDING$", Detail: "LDAP signing not enforced", Remediation: "Apply KB5005413."},
				{Summary: "MS17-010|EternalBlue|unreachable|ESSOS-DC$", Detail: "Windows Server 2008 R2, build 7601"},
			},
		},
		AttackPaths: []report.SnapshotAttackPath{
			{
				Summary: "jsnow→Domain Admins(2hops)", TargetGroup: "Domain Admins", Depth: 2,
				Edges: []report.SnapshotEdge{{From: "CN=jsnow", To: "CN=Night's Watch", Type: "MemberOf"}, {From: "CN=Night's Watch", To: "CN=Domain Admins", Type: "GenericAll"}},
			},
			{
				Summary: "svc_backup→Backup Operators(1hops)", TargetGroup: "Backup Operators", Depth: 1,
				Edges: []report.SnapshotEdge{{From: "CN=svc_backup", To: "CN=Backup Operators", Type: "MemberOf"}},
			},
		},
	}
}

func TestGetReportSummaryHandler(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getReportSummaryHandler(snap)(context.Background(), nil, NoArgs{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if out.Domain != "corp.local" || out.GeneratedAt != "2026-07-26 10:00:00" || out.Version != "1.2.2" {
		t.Errorf("out = %+v", out)
	}
	if out.Grade != "C" || out.Score != 53 {
		t.Errorf("out score fields = %+v", out)
	}
	if out.Critical != 1 || out.High != 2 || out.Medium != 3 {
		t.Errorf("out counts = %+v", out)
	}
}

func TestListCategoriesHandler(t *testing.T) {
	snap := testSnapshot()
	_, out, err := listCategoriesHandler(snap)(context.Background(), nil, NoArgs{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	want := []string{"acl", "vulns"}
	if len(out.Categories) != len(want) {
		t.Fatalf("Categories = %v, want %v", out.Categories, want)
	}
	for i := range want {
		if out.Categories[i] != want[i] {
			t.Errorf("Categories[%d] = %q, want %q (categories must be sorted)", i, out.Categories[i], want[i])
		}
	}
}

func TestServe_MissingReportReturnsError(t *testing.T) {
	// Safe to call Serve here: ParseReport fails on this path before Serve
	// ever reaches the blocking server.Run call. Never call Serve with a
	// valid report path in a test — see Global Constraints.
	err := Serve(context.Background(), "/nonexistent/report.html")
	if err == nil {
		t.Fatal("expected error for missing report, got nil")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run 'TestGetReportSummaryHandler|TestListCategoriesHandler|TestServe_MissingReportReturnsError' -v`
Expected: FAIL to build — `getReportSummaryHandler`, `listCategoriesHandler`, `NoArgs`, `Serve` are undefined.

- [ ] **Step 4: Write `internal/mcpserver/tools_shared.go`**

```go
package mcpserver

import (
	"context"
	"sort"

	"github.com/YakinAnd/morok/internal/report"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NoArgs is used for tools that take no input parameters.
type NoArgs struct{}

// ReportSummary is the Out type for get_report_summary.
type ReportSummary struct {
	Domain      string `json:"domain"`
	GeneratedAt string `json:"generated_at"`
	Version     string `json:"version"`
	Grade       string `json:"grade"`
	Score       int    `json:"score"`
	Critical    int    `json:"critical"`
	High        int    `json:"high"`
	Medium      int    `json:"medium"`
}

// CategoryList is the Out type for list_categories.
type CategoryList struct {
	Categories []string `json:"categories"`
}

func getReportSummaryHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, ReportSummary, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in NoArgs) (*mcp.CallToolResult, ReportSummary, error) {
		return nil, ReportSummary{
			Domain:      snap.Domain,
			GeneratedAt: snap.GeneratedAt,
			Version:     snap.Version,
			Grade:       snap.Score.Grade,
			Score:       snap.Score.Value,
			Critical:    snap.Counts.Critical,
			High:        snap.Counts.High,
			Medium:      snap.Counts.Medium,
		}, nil
	}
}

func listCategoriesHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, CategoryList, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in NoArgs) (*mcp.CallToolResult, CategoryList, error) {
		cats := make([]string, 0, len(snap.Findings))
		for k := range snap.Findings {
			cats = append(cats, k)
		}
		sort.Strings(cats)
		return nil, CategoryList{Categories: cats}, nil
	}
}

func registerSharedTools(server *mcp.Server, snap *report.Snapshot) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_report_summary",
		Description: "Domain, generated_at, version, grade, score, and critical/high/medium finding counts for the loaded report.",
	}, getReportSummaryHandler(snap))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_categories",
		Description: "Which finding categories have data in this report (e.g. acl, vulns, adcs_templates).",
	}, listCategoriesHandler(snap))
}
```

- [ ] **Step 5: Write `internal/mcpserver/server.go`**

```go
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Serve loads the report at path and runs an MCP server over stdio,
// exposing shared, blueteam, and redteam tools over its findings. Blocks
// until the transport closes (client disconnects) or ctx is done.
func Serve(ctx context.Context, path string) error {
	snap, err := ParseReport(path)
	if err != nil {
		return fmt.Errorf("loading report: %w", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "morok", Version: "1.2.2"}, nil)

	registerSharedTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
}
```

- [ ] **Step 6: Fetch the new dependency and run the tests**

Run: `go mod tidy` (requires network access — this fetches `github.com/modelcontextprotocol/go-sdk` and its transitive dependencies, updating `go.mod`/`go.sum`)

Then run: `go test ./internal/mcpserver/... -run 'TestGetReportSummaryHandler|TestListCategoriesHandler|TestServe_MissingReportReturnsError' -v`
Expected: PASS for all 3 tests.

- [ ] **Step 7: Add the `morok mcp` CLI subcommand**

In `cmd/morok/main.go`, add a new package-level variable next to the other flag variables (near `vulnCheck`, `followTrusts`):

```go
	mcpReportPath  string // --report for `morok mcp`: path to an already-generated report
```

Add a new command definition near `versionCmd`:

```go
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run an MCP server exposing a generated report's findings",
	Example: `  morok mcp --report /tmp/corp.html`,
	RunE: runMCP,
}

func runMCP(cmd *cobra.Command, args []string) error {
	return mcpserver.Serve(cmd.Context(), mcpReportPath)
}
```

Add the import for `mcpserver` alongside the existing `github.com/YakinAnd/morok/internal/...` imports at the top of the file:

```go
	"github.com/YakinAnd/morok/internal/mcpserver"
```

In `init()`, register the flag and the command (near where `versionCmd` is added and other flags are registered):

```go
	mcpCmd.Flags().StringVar(&mcpReportPath, "report", "", "Path to an already-generated morok HTML report (required)")
	mcpCmd.MarkFlagRequired("report")
	rootCmd.AddCommand(mcpCmd)
```

- [ ] **Step 8: Run the full build and test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green, including every pre-existing test in every package.

- [ ] **Step 9: Manual smoke test**

Run: `go build -o morok ./cmd/morok/ && ./morok mcp --report /nonexistent.html; echo "exit code: $?"`
Expected: prints an error mentioning "loading report" and exits non-zero (confirms the CLI subcommand wires through to `Serve` and its error path — do NOT run this with a valid report path, since it would block waiting on stdin; that's expected end-to-end behavior for a real MCP client, not something to verify manually here).

- [ ] **Step 10: Commit**

```bash
git add internal/mcpserver/server.go internal/mcpserver/tools_shared.go internal/mcpserver/server_test.go cmd/morok/main.go go.mod go.sum
git commit -m "$(cat <<'EOF'
feat: wire official Go MCP SDK, add `morok mcp` subcommand + shared tools

Adds github.com/modelcontextprotocol/go-sdk as a dependency, internal/mcpserver.Serve()
running a stdio MCP server over a loaded report, and get_report_summary/list_categories
as the first two tools. Every tool handler is a named function returning a closure so it
can be unit-tested directly without running the server.
EOF
)"
```

---

### Task 2: Vuln-summary parsing helper + blueteam tools

**Files:**
- Create: `internal/mcpserver/vulnsummary.go`
- Create: `internal/mcpserver/tools_blueteam.go`
- Modify: `internal/mcpserver/server.go` (register the new tool set)
- Test: `internal/mcpserver/vulnsummary_test.go`, `internal/mcpserver/tools_blueteam_test.go`

**Interfaces:**
- Consumes: `report.SnapshotFinding{Summary, Severity, CVSS, Detail, Remediation}` from `snap.Findings["vulns"]` — each entry's `Summary` is encoded by the prior plan as `"CVE|Name|status|Host"` (e.g. `"MS17-010|EternalBlue|confirmed|OLDMAESTER$"`).
- Produces: `parseVulnSummary(summary string) (parsedVuln, bool)` — used by this task's `get_vulnerability_summary` and by Task 3's `list_confirmed_vulnerabilities`. `mcpserver.FindingEntry`, `mcpserver.FindingList`, `mcpserver.RemediationItem`, `mcpserver.RemediationChecklist`, `mcpserver.VulnSummary` (Out types).

- [ ] **Step 1: Write the failing tests**

Create `internal/mcpserver/vulnsummary_test.go`:

```go
package mcpserver

import "testing"

func TestParseVulnSummary(t *testing.T) {
	cases := []struct {
		input string
		want  parsedVuln
		ok    bool
	}{
		{"MS17-010|EternalBlue|confirmed|OLDMAESTER$", parsedVuln{CVE: "MS17-010", Name: "EternalBlue", Status: "confirmed", Host: "OLDMAESTER$"}, true},
		{"CVE-2021-36942|PetitPotam|candidate|KINGSLANDING$", parsedVuln{CVE: "CVE-2021-36942", Name: "PetitPotam", Status: "candidate", Host: "KINGSLANDING$"}, true},
		{"not enough parts", parsedVuln{}, false},
		{"", parsedVuln{}, false},
		{"a|b|c|d|e", parsedVuln{}, false},
	}
	for _, c := range cases {
		got, ok := parseVulnSummary(c.input)
		if ok != c.ok {
			t.Errorf("parseVulnSummary(%q) ok = %v, want %v", c.input, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseVulnSummary(%q) = %+v, want %+v", c.input, got, c.want)
		}
	}
}
```

Create `internal/mcpserver/tools_blueteam_test.go`:

```go
package mcpserver

import (
	"context"
	"testing"
)

func TestListFindingsHandler_NoFilter(t *testing.T) {
	snap := testSnapshot()
	_, out, err := listFindingsHandler(snap)(context.Background(), nil, listFindingsIn{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	// testSnapshot has 1 acl finding + 3 vulns findings = 4 total
	if len(out.Findings) != 4 {
		t.Fatalf("Findings len = %d, want 4", len(out.Findings))
	}
}

func TestListFindingsHandler_FilterBySeverity(t *testing.T) {
	snap := testSnapshot()
	_, out, err := listFindingsHandler(snap)(context.Background(), nil, listFindingsIn{Severity: "critical"})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].Category != "acl" {
		t.Fatalf("Findings = %+v, want exactly the 1 acl finding (case-insensitive severity match)", out.Findings)
	}
}

func TestGetRemediationChecklistHandler_OnlyIncludesFindingsWithRemediation(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getRemediationChecklistHandler(snap)(context.Background(), nil, getRemediationChecklistIn{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	// The acl finding has no Remediation set in testSnapshot; all 3 vulns findings do
	// except the unreachable one has no Remediation set either (matches real buildSnapshot
	// behavior — ProbeError findings may lack Remediation).
	for _, item := range out.Items {
		if item.Category != "vulns" {
			t.Errorf("unexpected category %q in remediation checklist (acl has no Remediation in the fixture)", item.Category)
		}
	}
	if len(out.Items) == 0 {
		t.Fatal("expected at least the vulns findings with Remediation set")
	}
}

func TestGetRemediationChecklistHandler_FilteredByCategory(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getRemediationChecklistHandler(snap)(context.Background(), nil, getRemediationChecklistIn{Category: "acl"})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if len(out.Items) != 0 {
		t.Fatalf("Items = %+v, want empty (acl category has no Remediation-bearing findings in the fixture)", out.Items)
	}
}

func TestGetVulnerabilitySummaryHandler(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getVulnerabilitySummaryHandler(snap)(context.Background(), nil, NoArgs{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	// testSnapshot's vulns: 1 confirmed, 1 candidate, 1 unreachable
	if out.Confirmed != 1 || out.Candidate != 1 || out.Unreachable != 1 {
		t.Errorf("out = %+v, want Confirmed=1 Candidate=1 Unreachable=1", out)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run 'TestParseVulnSummary|TestListFindingsHandler|TestGetRemediationChecklistHandler|TestGetVulnerabilitySummaryHandler' -v`
Expected: FAIL to build — `parseVulnSummary`, `parsedVuln`, `listFindingsHandler`, `listFindingsIn`, `getRemediationChecklistHandler`, `getRemediationChecklistIn`, `getVulnerabilitySummaryHandler` are undefined.

- [ ] **Step 3: Write `internal/mcpserver/vulnsummary.go`**

```go
package mcpserver

import "strings"

// parsedVuln is the decoded form of a "vulns" category SnapshotFinding's
// Summary field, encoded by internal/report/snapshot.go's buildSnapshot as
// "CVE|Name|status|Host" (status is one of "candidate", "confirmed",
// "unreachable").
type parsedVuln struct {
	CVE    string
	Name   string
	Status string
	Host   string
}

// parseVulnSummary decodes a vulns-category Summary string. Returns
// ok=false if the string doesn't have exactly 4 pipe-separated parts.
func parseVulnSummary(summary string) (parsedVuln, bool) {
	parts := strings.Split(summary, "|")
	if len(parts) != 4 {
		return parsedVuln{}, false
	}
	return parsedVuln{CVE: parts[0], Name: parts[1], Status: parts[2], Host: parts[3]}, true
}
```

- [ ] **Step 4: Write `internal/mcpserver/tools_blueteam.go`**

```go
package mcpserver

import (
	"context"
	"strings"

	"github.com/YakinAnd/morok/internal/report"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listFindingsIn struct {
	Severity string `json:"severity,omitempty"`
}

// FindingEntry is one entry in the Out type for list_findings.
type FindingEntry struct {
	Category string  `json:"category"`
	Summary  string  `json:"summary"`
	Severity string  `json:"severity,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
}

// FindingList is the Out type for list_findings.
type FindingList struct {
	Findings []FindingEntry `json:"findings"`
}

func listFindingsHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, listFindingsIn) (*mcp.CallToolResult, FindingList, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in listFindingsIn) (*mcp.CallToolResult, FindingList, error) {
		var out FindingList
		for category, findings := range snap.Findings {
			for _, f := range findings {
				if in.Severity != "" && !strings.EqualFold(f.Severity, in.Severity) {
					continue
				}
				out.Findings = append(out.Findings, FindingEntry{
					Category: category, Summary: f.Summary, Severity: f.Severity, CVSS: f.CVSS,
				})
			}
		}
		return nil, out, nil
	}
}

type getRemediationChecklistIn struct {
	Category string `json:"category,omitempty"`
}

// RemediationItem is one entry in the Out type for get_remediation_checklist.
type RemediationItem struct {
	Category    string `json:"category"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation"`
}

// RemediationChecklist is the Out type for get_remediation_checklist.
type RemediationChecklist struct {
	Items []RemediationItem `json:"items"`
}

func getRemediationChecklistHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, getRemediationChecklistIn) (*mcp.CallToolResult, RemediationChecklist, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getRemediationChecklistIn) (*mcp.CallToolResult, RemediationChecklist, error) {
		var out RemediationChecklist
		for category, findings := range snap.Findings {
			if in.Category != "" && category != in.Category {
				continue
			}
			for _, f := range findings {
				if f.Remediation == "" {
					continue
				}
				out.Items = append(out.Items, RemediationItem{
					Category: category, Summary: f.Summary, Remediation: f.Remediation,
				})
			}
		}
		return nil, out, nil
	}
}

// VulnSummary is the Out type for get_vulnerability_summary.
type VulnSummary struct {
	Candidate   int `json:"candidate"`
	Confirmed   int `json:"confirmed"`
	Unreachable int `json:"unreachable"`
}

func getVulnerabilitySummaryHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, VulnSummary, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in NoArgs) (*mcp.CallToolResult, VulnSummary, error) {
		var out VulnSummary
		for _, f := range snap.Findings["vulns"] {
			pv, ok := parseVulnSummary(f.Summary)
			if !ok {
				continue
			}
			switch pv.Status {
			case "confirmed":
				out.Confirmed++
			case "unreachable":
				out.Unreachable++
			default:
				out.Candidate++
			}
		}
		return nil, out, nil
	}
}

func registerBlueteamTools(server *mcp.Server, snap *report.Snapshot) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_findings",
		Description: "All findings across every category, optionally filtered by severity (Critical/High/Medium — case-insensitive).",
	}, listFindingsHandler(snap))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_remediation_checklist",
		Description: "Remediation text grouped by category, optionally filtered to one category. Only findings with remediation guidance are included (currently: vulns).",
	}, getRemediationChecklistHandler(snap))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_vulnerability_summary",
		Description: "Counts of candidate/confirmed/unreachable vulnerability findings, mirroring the CLI's [VULNS] section.",
	}, getVulnerabilitySummaryHandler(snap))
}
```

- [ ] **Step 5: Register the new tool set in `server.go`**

In `internal/mcpserver/server.go`, change:

```go
	registerSharedTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
```

to:

```go
	registerSharedTools(server, snap)
	registerBlueteamTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS for all tests (Task 1's + this task's).

- [ ] **Step 7: Run the full build and test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add internal/mcpserver/vulnsummary.go internal/mcpserver/vulnsummary_test.go internal/mcpserver/tools_blueteam.go internal/mcpserver/tools_blueteam_test.go internal/mcpserver/server.go
git commit -m "$(cat <<'EOF'
feat: add blueteam MCP tools (list_findings, remediation checklist, vuln summary)

Adds a shared parseVulnSummary helper (decodes the "CVE|Name|status|Host"
Summary format the vulns category uses) plus list_findings, get_remediation_checklist,
and get_vulnerability_summary tools.
EOF
)"
```

---

### Task 3: Redteam tools (minus `get_exploit_commands`)

**Files:**
- Create: `internal/mcpserver/tools_redteam.go`
- Modify: `internal/mcpserver/server.go` (register the new tool set)
- Test: `internal/mcpserver/tools_redteam_test.go`

**Interfaces:**
- Consumes: `report.SnapshotAttackPath{Summary, TargetGroup, Depth, Edges}`, `report.SnapshotEdge{From, To, Type}` (existing), `parseVulnSummary` (from Task 2).
- Produces: `mcpserver.AttackPathSummary`, `mcpserver.AttackPathList`, `mcpserver.AttackPathDetail`, `mcpserver.VulnEntry`, `mcpserver.ConfirmedVulnList` (Out types). Three tools: `list_attack_paths`, `get_attack_path`, `list_confirmed_vulnerabilities`. Does **not** implement `get_exploit_commands` — that's blocked (see Global Constraints).

- [ ] **Step 1: Write the failing tests**

Create `internal/mcpserver/tools_redteam_test.go`:

```go
package mcpserver

import (
	"context"
	"testing"
)

func TestListAttackPathsHandler_SortedByDepth(t *testing.T) {
	snap := testSnapshot()
	_, out, err := listAttackPathsHandler(snap)(context.Background(), nil, NoArgs{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if len(out.Paths) != 2 {
		t.Fatalf("Paths len = %d, want 2", len(out.Paths))
	}
	// testSnapshot has Depth=2 (Domain Admins) and Depth=1 (Backup Operators);
	// sorted ascending, Backup Operators (depth 1) must come first.
	if out.Paths[0].Depth != 1 || out.Paths[0].TargetGroup != "Backup Operators" {
		t.Errorf("Paths[0] = %+v, want Depth=1 TargetGroup=Backup Operators", out.Paths[0])
	}
	if out.Paths[1].Depth != 2 || out.Paths[1].TargetGroup != "Domain Admins" {
		t.Errorf("Paths[1] = %+v, want Depth=2 TargetGroup=Domain Admins", out.Paths[1])
	}
}

func TestGetAttackPathHandler_FiltersByTargetGroup(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getAttackPathHandler(snap)(context.Background(), nil, getAttackPathIn{TargetGroup: "Domain Admins"})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if len(out.Paths) != 1 {
		t.Fatalf("Paths len = %d, want 1", len(out.Paths))
	}
	if len(out.Paths[0].Edges) != 2 {
		t.Fatalf("Paths[0].Edges len = %d, want 2 (full edge detail must be present)", len(out.Paths[0].Edges))
	}
}

func TestGetAttackPathHandler_NoMatchReturnsEmpty(t *testing.T) {
	snap := testSnapshot()
	_, out, err := getAttackPathHandler(snap)(context.Background(), nil, getAttackPathIn{TargetGroup: "Nonexistent Group"})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if len(out.Paths) != 0 {
		t.Errorf("Paths = %+v, want empty for a target group with no matches", out.Paths)
	}
}

func TestListConfirmedVulnerabilitiesHandler(t *testing.T) {
	snap := testSnapshot()
	_, out, err := listConfirmedVulnerabilitiesHandler(snap)(context.Background(), nil, NoArgs{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	// testSnapshot's vulns has exactly 1 confirmed finding (EternalBlue on OLDMAESTER$)
	if len(out.Vulns) != 1 {
		t.Fatalf("Vulns len = %d, want 1", len(out.Vulns))
	}
	if out.Vulns[0].CVE != "MS17-010" || out.Vulns[0].Host != "OLDMAESTER$" {
		t.Errorf("Vulns[0] = %+v, want CVE=MS17-010 Host=OLDMAESTER$", out.Vulns[0])
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run 'TestListAttackPathsHandler|TestGetAttackPathHandler|TestListConfirmedVulnerabilitiesHandler' -v`
Expected: FAIL to build — `listAttackPathsHandler`, `getAttackPathHandler`, `getAttackPathIn`, `listConfirmedVulnerabilitiesHandler` are undefined.

- [ ] **Step 3: Write `internal/mcpserver/tools_redteam.go`**

```go
package mcpserver

import (
	"context"
	"sort"

	"github.com/YakinAnd/morok/internal/report"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AttackPathSummary is one entry in the Out type for list_attack_paths.
type AttackPathSummary struct {
	Summary     string `json:"summary"`
	TargetGroup string `json:"target_group"`
	Depth       int    `json:"depth"`
}

// AttackPathList is the Out type for list_attack_paths.
type AttackPathList struct {
	Paths []AttackPathSummary `json:"paths"`
}

func listAttackPathsHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, AttackPathList, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in NoArgs) (*mcp.CallToolResult, AttackPathList, error) {
		out := AttackPathList{Paths: make([]AttackPathSummary, len(snap.AttackPaths))}
		for i, p := range snap.AttackPaths {
			out.Paths[i] = AttackPathSummary{Summary: p.Summary, TargetGroup: p.TargetGroup, Depth: p.Depth}
		}
		sort.Slice(out.Paths, func(i, j int) bool { return out.Paths[i].Depth < out.Paths[j].Depth })
		return nil, out, nil
	}
}

type getAttackPathIn struct {
	TargetGroup string `json:"target_group"`
}

// AttackPathDetail is the Out type for get_attack_path — full node/edge
// detail, not just the summary.
type AttackPathDetail struct {
	Paths []report.SnapshotAttackPath `json:"paths"`
}

func getAttackPathHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, getAttackPathIn) (*mcp.CallToolResult, AttackPathDetail, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getAttackPathIn) (*mcp.CallToolResult, AttackPathDetail, error) {
		var out AttackPathDetail
		for _, p := range snap.AttackPaths {
			if p.TargetGroup == in.TargetGroup {
				out.Paths = append(out.Paths, p)
			}
		}
		return nil, out, nil
	}
}

// VulnEntry is one entry in the Out type for list_confirmed_vulnerabilities.
type VulnEntry struct {
	CVE         string `json:"cve"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

// ConfirmedVulnList is the Out type for list_confirmed_vulnerabilities.
type ConfirmedVulnList struct {
	Vulns []VulnEntry `json:"vulns"`
}

func listConfirmedVulnerabilitiesHandler(snap *report.Snapshot) func(context.Context, *mcp.CallToolRequest, NoArgs) (*mcp.CallToolResult, ConfirmedVulnList, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, in NoArgs) (*mcp.CallToolResult, ConfirmedVulnList, error) {
		var out ConfirmedVulnList
		for _, f := range snap.Findings["vulns"] {
			pv, ok := parseVulnSummary(f.Summary)
			if !ok || pv.Status != "confirmed" {
				continue
			}
			out.Vulns = append(out.Vulns, VulnEntry{
				CVE: pv.CVE, Name: pv.Name, Host: pv.Host, Detail: f.Detail, Remediation: f.Remediation,
			})
		}
		return nil, out, nil
	}
}

func registerRedteamTools(server *mcp.Server, snap *report.Snapshot) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_attack_paths",
		Description: "All BFS attack paths, sorted by depth, with target group.",
	}, listAttackPathsHandler(snap))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_attack_path",
		Description: "Full node/edge detail for attack paths ending at a specific privileged group (e.g. \"Domain Admins\").",
	}, getAttackPathHandler(snap))

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_confirmed_vulnerabilities",
		Description: "Vulnerability findings with an active-probe-confirmed status (from --vuln-check).",
	}, listConfirmedVulnerabilitiesHandler(snap))
}
```

- [ ] **Step 4: Register the new tool set in `server.go`**

In `internal/mcpserver/server.go`, change:

```go
	registerSharedTools(server, snap)
	registerBlueteamTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
```

to:

```go
	registerSharedTools(server, snap)
	registerBlueteamTools(server, snap)
	registerRedteamTools(server, snap)

	return server.Run(ctx, &mcp.StdioTransport{})
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS for all tests (Tasks 1, 2, and this task's).

- [ ] **Step 6: Run the full build and test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add internal/mcpserver/tools_redteam.go internal/mcpserver/tools_redteam_test.go internal/mcpserver/server.go
git commit -m "$(cat <<'EOF'
feat: add redteam MCP tools (attack paths, confirmed vulnerabilities)

Adds list_attack_paths, get_attack_path, and list_confirmed_vulnerabilities.
get_exploit_commands is intentionally not implemented here — it's blocked
until exploit-command builders are extracted out of the HTML template's
FuncMap closures into reusable functions (separate follow-up).
EOF
)"
```

---

### Task 4: Docs for `morok mcp`

**Files:**
- Create: `docs/commands/mcp.md`
- Modify: `README.md` (Commands table)
- Modify: `docs/index.md` (Commands overview table)

**Interfaces:**
- Consumes: nothing — this is documentation only, describing the finished command from Tasks 1-3.

- [ ] **Step 1: Create `docs/commands/mcp.md`**

```markdown
# morok mcp

Run an MCP (Model Context Protocol) server exposing a single already-generated morok report's findings to an MCP-compatible client (Claude Code, Claude Desktop, or any other MCP client).

## Usage

```bash
morok mcp --report <path-to-report.html>
```

The report must have been generated by a morok version that supports the v2 report schema (anything from this release onward). Older (v1) reports are rejected with an error telling you to regenerate them.

`morok mcp` runs over stdio and blocks until the client disconnects — it's meant to be launched by an MCP client's own process management (e.g. as an entry in Claude Desktop's or Claude Code's MCP server config), not run interactively.

## Flags

| Flag | Description |
|------|-------------|
| `--report` | Path to an already-generated morok HTML report (required) |

## What it reads, and doesn't do

- Operates on exactly **one** report per process lifetime — there is no `load_report` tool to switch reports mid-session, and no support for comparing multiple reports (that's the HTML report's own History tab).
- Does **not** run `morok enum` itself — it only reads a report you already generated with `morok enum --report <file>` (optionally with `--vuln-check`).

## Tools

**Shared**

| Tool | Description |
|------|-------------|
| `get_report_summary` | Domain, generated_at, version, grade, score, and critical/high/medium counts |
| `list_categories` | Which finding categories have data in this report |

**Blueteam**

| Tool | Description |
|------|-------------|
| `list_findings` | All findings, optionally filtered by severity |
| `get_remediation_checklist` | Remediation text grouped by category, optionally filtered to one category (currently populated only for the `vulns` category — other categories don't yet carry structured remediation text) |
| `get_vulnerability_summary` | Counts of candidate/confirmed/unreachable vulnerability findings |

**Redteam**

| Tool | Description |
|------|-------------|
| `list_attack_paths` | All BFS attack paths, sorted by depth |
| `get_attack_path` | Full node/edge detail for paths ending at a specific privileged group |
| `list_confirmed_vulnerabilities` | Vulnerability findings confirmed via active `--vuln-check` probes |

`get_exploit_commands` is not yet implemented — exploit-command text currently only exists as rendered HTML in the report, not as structured data the MCP server can serve.

## Example (Claude Desktop / Claude Code MCP config)

```json
{
  "mcpServers": {
    "morok": {
      "command": "morok",
      "args": ["mcp", "--report", "/path/to/corp.local_report.html"]
    }
  }
}
```
```

- [ ] **Step 2: Add `morok mcp` to the Commands table in `README.md`**

Find the `## Commands` table (a `| Command | Description |` table) and add a row after `version`:

```
| `mcp` | Run an MCP server exposing a generated report's findings to MCP clients |
```

- [ ] **Step 3: Add `morok mcp` to the Commands overview table in `docs/index.md`**

Find the `## Commands overview` table and add the same row after `version`.

- [ ] **Step 4: Commit**

```bash
git add docs/commands/mcp.md README.md docs/index.md
git commit -m "docs: add morok mcp command reference"
```

## Self-Review Notes (already applied above)

- **Spec coverage:** Covers ADP-202 (SDK wiring), ADP-205 (shared tools), ADP-204 (blueteam tools), ADP-203 minus `get_exploit_commands` (redteam tools — that one tool is explicitly out of scope, blocked by the separate ADP-209 follow-up), ADP-206 (CLI subcommand), ADP-208 (docs). ADP-207 (tests for snapshot v2 + parser) was already fully covered by the prior plan's per-task TDD steps — no additional work needed here.
- **Placeholder scan:** No TBD/TODO; every step has complete, real code verified against the actual `github.com/modelcontextprotocol/go-sdk` API (NewServer/AddTool/Tool/CallToolRequest/StdioTransport/Run) rather than reconstructed from memory.
- **Type consistency:** `report.Snapshot`/`SnapshotFinding`/`SnapshotAttackPath`/`SnapshotEdge` field names match exactly what the prior plan produced. `NoArgs`, `parseVulnSummary`/`parsedVuln`, and every `Out` type are defined once (Task 1 or 2) and reused identically by later tasks with no renaming drift.
