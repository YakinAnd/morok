package mcpserver

import (
	"testing"
	"time"

	"github.com/YakinAnd/morok/internal/graph"
	adldap "github.com/YakinAnd/morok/internal/ldap"
	"github.com/YakinAnd/morok/internal/report"
)

// fakeResult builds a minimal EnumerationResult for the round-trip test
// below. Mirrors internal/report/html_test.go's fakeResult() — kept as its
// own unexported copy here since that one isn't exported across packages.
func fakeResult() *adldap.EnumerationResult {
	return &adldap.EnumerationResult{
		Domain:      "integration.local",
		BaseDN:      "DC=integration,DC=local",
		CollectedAt: time.Now(),
		Users: []adldap.LDAPUser{
			{
				DN:             "CN=Alice,CN=Users,DC=integration,DC=local",
				SAMAccountName: "alice",
				Enabled:        true,
			},
		},
		Computers: []adldap.LDAPComputer{
			{DN: "CN=DC01,OU=Domain Controllers,DC=integration,DC=local", SAMAccountName: "DC01$", Enabled: true},
		},
	}
}

// TestParseReport_RoundTripsRealGeneratedReport binds the producer
// (report.Generate's embedded morok-data block) to the consumer
// (ParseReport's regex + JSON unmarshal) across the package seam. If the
// HTML template line that emits the <script id="morok-data"> block is ever
// reformatted in a way ParseReport's regex can't handle, this test fails —
// unlike the hand-written string fixtures elsewhere in both suites, which
// would keep passing regardless of what html.go actually emits.
func TestParseReport_RoundTripsRealGeneratedReport(t *testing.T) {
	outFile := t.TempDir() + "/report.html"

	result := fakeResult()
	g := graph.Build(result)
	paths := g.FindPathsToPrivilegedGroups(5)

	err := report.Generate(
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
		nil, // LDAPSecurityResult
		nil, // AuditResult
		nil, // SMBSigningResult
		nil, // SYSVOLResult
		nil, // LAPSACLResult
		nil, // TrustedDomains
		"Password",
		nil, // VulnResult
	)
	if err != nil {
		t.Fatalf("report.Generate: %v", err)
	}

	snap, err := ParseReport(outFile)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}

	if snap.V != 2 {
		t.Errorf("V = %d, want 2", snap.V)
	}
	if snap.Domain != "integration.local" {
		t.Errorf("Domain = %q, want %q", snap.Domain, "integration.local")
	}
	if snap.GeneratedAt == "" {
		t.Error("GeneratedAt is empty, want non-empty timestamp")
	}
}
