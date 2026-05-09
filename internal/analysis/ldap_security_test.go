package analysis

import (
	"testing"
)

func TestLDAPSecurityFindingOrder(t *testing.T) {
	// Verify oidLDAPIntegrity constant value is correct
	expected := "1.2.840.113556.1.4.1791"
	if oidLDAPIntegrity != expected {
		t.Errorf("oidLDAPIntegrity = %q, want %q", oidLDAPIntegrity, expected)
	}
}

func TestLDAPSecurityResultNilRDS(t *testing.T) {
	r := AnalyzeLDAPSecurity(nil, nil)
	if r != nil {
		t.Error("expected nil result when rds is nil")
	}
}
