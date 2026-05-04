package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YakinAnd/adpath/internal/analysis"
	"github.com/YakinAnd/adpath/internal/graph"
	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// fakeResult builds a minimal EnumerationResult with representative data.
func fakeResult() *adldap.EnumerationResult {
	return &adldap.EnumerationResult{
		Domain:      "test.local",
		BaseDN:      "DC=test,DC=local",
		CollectedAt: time.Now(),
		Users: []adldap.LDAPUser{
			{
				DN: "CN=Alice,CN=Users,DC=test,DC=local",
				SAMAccountName: "alice",
				Enabled:        true,
				PasswordNeverExpires: true,
				AdminCount:     true,
			},
			{
				DN: "CN=krbtgt,CN=Users,DC=test,DC=local",
				SAMAccountName: "krbtgt",
				Enabled:        true,
			},
		},
		Groups: []adldap.LDAPGroup{
			{DN: "CN=Domain Admins,CN=Users,DC=test,DC=local", SAMAccountName: "Domain Admins"},
		},
		Computers: []adldap.LDAPComputer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=test,DC=local", SAMAccountName: "DC01$", Enabled: true},
		},
	}
}

func fakeAuditResult() *analysis.AuditResult {
	return &analysis.AuditResult{
		Domain:              "test.local",
		RecycleBinSupported: true,
		RecycleBinEnabled:   false,
		AuditingEnabled:     false,
		MachineAccountQuota: 10,
		AuditCategories: []analysis.AuditCategory{
			{Name: "Account Logon", Success: false, Failure: false},
			{Name: "Account Management", Success: true, Failure: false},
		},
		Findings: []analysis.AuditFinding{
			{Title: "Legacy audit policy not configured", Detail: "No auditing enabled.", Severity: "High"},
			{Title: "AD Recycle Bin disabled", Detail: "Enable it.", Severity: "Medium"},
			{Title: "Machine account quota = 10", Detail: "Set to 0.", Severity: "Medium"},
		},
	}
}

func fakeLDAPSecResult() *analysis.LDAPSecurityResult {
	return &analysis.LDAPSecurityResult{
		Domain:          "test.local",
		PlainLDAP:       true,
		SigningEnforced: false,
		Capabilities:   []string{"1.2.840.113556.1.4.800"},
		SASLMechanisms: []string{"GSSAPI", "GSS-SPNEGO"},
		Findings: []analysis.LDAPSecurityFinding{
			{Title: "LDAP signing not enforced", Detail: "Use LDAPS.", Severity: "Medium"},
		},
	}
}

// TestGenerateReport verifies the HTML report renders without error
// and contains key sections — no live LDAP connection needed.
func TestGenerateReport(t *testing.T) {
	outFile := t.TempDir() + "/test_report.html"

	result := fakeResult()
	g := graph.Build(result)
	paths := g.FindPathsToPrivilegedGroups(5)

	err := Generate(
		outFile,
		result,
		g,
		paths,
		nil, // KerberosResult
		nil, // ACLResult
		nil, // DelegationResult
		nil, // GPOResult
		nil, // HygieneResult
		nil, // PSOResult
		nil, // ADCSResult
		nil, // ProtectedUsersResult
		nil, // AdminSDHolderResult
		nil, // TrustResult
		nil, // ShadowCredentialsResult
		fakeLDAPSecResult(),
		fakeAuditResult(),
		nil, // SMBSigningResult
		nil, // SYSVOLResult
		nil, // LAPSACLResult
		"Password",
	)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	content, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read generated report: %v", err)
	}
	html := string(content)

	checks := []struct {
		label   string
		keyword string
	}{
		{"has DOCTYPE", "<!DOCTYPE html>"},
		{"has domain name", "test.local"},
		{"has Audit tab", "tab-audit"},
		{"has LDAP Security tab", "tab-ldapsec"},
		{"has Shadow Creds tab", "tab-shadow"},
		{"has Recycle Bin row", "AD Recycle Bin"},
		{"has MAQ finding", "Machine account quota"},
		{"has LDAP signing finding", "LDAP signing not enforced"},
		{"has audit finding High", "badge-high"},
		{"has summary section", "tab-summary"},
	}

	for _, c := range checks {
		if !strings.Contains(html, c.keyword) {
			t.Errorf("report missing %s (keyword: %q)", c.label, c.keyword)
		}
	}

	t.Logf("report generated: %d bytes, %d lines", len(html), strings.Count(html, "\n"))
}
