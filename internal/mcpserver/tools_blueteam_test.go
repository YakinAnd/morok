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
