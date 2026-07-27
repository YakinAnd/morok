package mcpserver

import (
	"context"
	"strings"

	"github.com/YakinAnd/morok/internal/report"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listFindingsIn struct {
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
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
			if in.Category != "" && !strings.EqualFold(category, in.Category) {
				continue
			}
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
			if in.Category != "" && !strings.EqualFold(category, in.Category) {
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
		Description: "All findings across every category, optionally filtered by severity (Critical/High/Medium — case-insensitive) and/or category (e.g. \"acl\", \"vulns\" — case-insensitive, exact match). Both filters apply together when supplied.",
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
