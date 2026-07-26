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
