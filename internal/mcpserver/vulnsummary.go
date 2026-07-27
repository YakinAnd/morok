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
