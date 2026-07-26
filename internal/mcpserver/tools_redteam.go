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
