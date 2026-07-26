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
