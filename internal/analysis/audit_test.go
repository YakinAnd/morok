package analysis

import (
	"testing"
)

func TestIsRecycleBinSupported(t *testing.T) {
	tests := []struct {
		ffl  string
		want bool
	}{
		{"4", true},
		{"5", true},
		{"7", true},
		{"3", false},
		{"0", false},
		{"", false},
		{"bad", false},
	}
	for _, tt := range tests {
		got := isRecycleBinSupported(tt.ffl)
		if got != tt.want {
			t.Errorf("isRecycleBinSupported(%q) = %v, want %v", tt.ffl, got, tt.want)
		}
	}
}

func TestParseLegacyAuditPolicy_Empty(t *testing.T) {
	cats := parseLegacyAuditPolicy(nil)
	if len(cats) != len(auditCategoryNames) {
		t.Fatalf("expected %d categories, got %d", len(auditCategoryNames), len(cats))
	}
	for _, c := range cats {
		if c.Success || c.Failure {
			t.Errorf("category %q should be disabled in empty policy", c.Name)
		}
	}
}

func TestParseLegacyAuditPolicy_AllEnabled(t *testing.T) {
	// 10 bytes: AuditingMode=1, then each category byte = 0x03 (Success+Failure)
	raw := make([]byte, 10)
	raw[0] = 0x01
	for i := 1; i < 10; i++ {
		raw[i] = 0x03
	}
	cats := parseLegacyAuditPolicy(raw)
	for _, c := range cats {
		if !c.Success {
			t.Errorf("category %q: expected Success=true", c.Name)
		}
		if !c.Failure {
			t.Errorf("category %q: expected Failure=true", c.Name)
		}
	}
}

func TestParseLegacyAuditPolicy_SuccessOnly(t *testing.T) {
	// byte 0 = AuditingMode, byte 1 = 0x01 (System Events success only)
	raw := []byte{0x01, 0x01}
	cats := parseLegacyAuditPolicy(raw)
	if !cats[0].Success {
		t.Error("System Events should have Success=true")
	}
	if cats[0].Failure {
		t.Error("System Events should have Failure=false")
	}
	// remaining categories should be disabled
	for _, c := range cats[1:] {
		if c.Success || c.Failure {
			t.Errorf("category %q should be disabled", c.Name)
		}
	}
}

func TestAuditCategoryNames(t *testing.T) {
	expected := []string{
		"System Events",
		"Logon/Logoff",
		"Object Access",
		"Privilege Use",
		"Detailed Tracking",
		"Policy Change",
		"Account Management",
		"Directory Service Access",
		"Account Logon",
	}
	if len(auditCategoryNames) != len(expected) {
		t.Fatalf("expected %d category names, got %d", len(expected), len(auditCategoryNames))
	}
	for i, name := range expected {
		if auditCategoryNames[i] != name {
			t.Errorf("auditCategoryNames[%d] = %q, want %q", i, auditCategoryNames[i], name)
		}
	}
}
