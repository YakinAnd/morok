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
