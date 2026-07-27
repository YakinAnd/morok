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
