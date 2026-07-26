package analysis

import (
	"testing"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

func TestParseBuild(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"10.0 (17763)", 17763},
		{"6.1 (7601)", 7601},
		{"6.3 (9600)", 9600},
		{"10.0 (14393)", 14393},
		{"", 0},
		{"Windows XP", 0},
		{"5.1 (2600)", 2600},
	}
	for _, c := range cases {
		got := parseBuild(c.input)
		if got != c.want {
			t.Errorf("parseBuild(%q) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestOsFamily(t *testing.T) {
	cases := []struct {
		os   string
		want string
	}{
		{"Windows XP Professional", "xp"},
		{"Windows Server 2003", "xp"},
		{"Windows Server 2008 R2 Standard", "2008r2"},
		{"Windows Server 2012 Standard", "2012"},
		{"Windows Server 2012 R2 Standard", "2012r2"},
		{"Windows Server 2016 Standard", "2016"},
		{"Windows Server 2019 Standard", "2019"},
		{"Windows Server 2022 Standard", "2022"},
		{"Windows 7 Professional", "2008r2"},
		{"Windows 10 Enterprise", "2016"},
		{"Windows 11 Pro", "2022"},
		{"", ""},
	}
	for _, c := range cases {
		got := osFamily(c.os)
		if got != c.want {
			t.Errorf("osFamily(%q) = %q, want %q", c.os, got, c.want)
		}
	}
}

func TestEternalBluePatched(t *testing.T) {
	cases := []struct {
		os      string
		build   int
		patched bool
	}{
		{"Windows XP Professional", 2600, false},
		{"Windows Server 2003", 3790, false},
		{"Windows Server 2008 R2 Standard", 7601, false},
		{"Windows Server 2012 Standard", 9200, false},
		{"Windows Server 2012 R2 Standard", 9600, false},
		{"Windows Server 2016 Standard", 14393, true},
		{"Windows Server 2019 Standard", 17763, true},
		{"Windows Server 2022 Standard", 20348, true},
	}
	for _, c := range cases {
		got := eternalBluePatched(c.os, c.build)
		if got != c.patched {
			t.Errorf("eternalBluePatched(%q, %d) = %v, want %v", c.os, c.build, got, c.patched)
		}
	}
}

func TestZerologonPatched(t *testing.T) {
	cases := []struct {
		os      string
		build   int
		patched bool
	}{
		{"Windows Server 2008 R2 Standard", 7601, false},
		{"Windows Server 2012 Standard", 9200, false},
		{"Windows Server 2012 R2 Standard", 9600, false},
		{"Windows Server 2016 Standard", 14393, true},
		{"Windows Server 2019 Standard", 17763, true},
		{"Windows Server 2022 Standard", 20348, true},
	}
	for _, c := range cases {
		got := zerologonPatched(c.os, c.build)
		if got != c.patched {
			t.Errorf("zerologonPatched(%q, %d) = %v, want %v", c.os, c.build, got, c.patched)
		}
	}
}

func TestRunVulnChecks_EmptyList(t *testing.T) {
	r := RunVulnChecks(nil, 10, nil, false)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
}

func TestRunVulnChecks_DisabledHostSkipped(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{SAMAccountName: "WS01$", OperatingSystem: "Windows XP Professional", Enabled: false},
	}
	r := RunVulnChecks(computers, 0, nil, false)
	if len(r.Findings) != 0 {
		t.Errorf("disabled host should be skipped, got %d findings", len(r.Findings))
	}
}

func TestRunVulnChecks_XPCandidateEternalBlue(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{
			SAMAccountName:         "WS-XP$",
			DNSHostName:            "ws-xp.corp.local",
			OperatingSystem:        "Windows XP Professional",
			OperatingSystemVersion: "5.1 (2600)",
			Enabled:                true,
			IsDC:                   false,
		},
	}
	r := RunVulnChecks(computers, 0, nil, false)
	found := false
	for _, f := range r.Findings {
		if f.CVE == "MS17-010" && f.Status == VulnCandidate {
			found = true
		}
	}
	if !found {
		t.Error("expected EternalBlue candidate for Windows XP")
	}
}

func TestRunVulnChecks_DCOnlyChecks(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{
			SAMAccountName:         "DC01$",
			DNSHostName:            "dc01.corp.local",
			OperatingSystem:        "Windows Server 2012 R2 Standard",
			OperatingSystemVersion: "6.3 (9600)",
			Enabled:                true,
			IsDC:                   true,
		},
	}
	r := RunVulnChecks(computers, 10, nil, false)

	cves := map[string]bool{}
	for _, f := range r.Findings {
		cves[f.CVE] = true
	}

	if !cves["CVE-2020-1472"] {
		t.Error("expected Zerologon for Server 2012 R2 DC")
	}
	if !cves["CVE-2021-42287"] {
		t.Error("expected noPac for DC with MAQ=10")
	}
}

func TestRunVulnChecks_NoPacRequiresMAQ(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{
			SAMAccountName:  "DC01$",
			OperatingSystem: "Windows Server 2016 Standard",
			Enabled:         true,
			IsDC:            true,
		},
	}
	// MAQ=0 → no noPac even on old OS
	r := RunVulnChecks(computers, 0, nil, false)
	for _, f := range r.Findings {
		if f.CVE == "CVE-2021-42287" {
			t.Error("noPac should not fire when MAQ=0")
		}
	}
}

func TestRunVulnChecks_DCOnlyCVEsNotOnWorkstation(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{
			SAMAccountName:  "WS01$",
			OperatingSystem: "Windows Server 2012 R2 Standard",
			Enabled:         true,
			IsDC:            false, // workstation, not DC
		},
	}
	r := RunVulnChecks(computers, 10, nil, false)
	for _, f := range r.Findings {
		switch f.CVE {
		case "CVE-2020-1472", "CVE-2021-42287", "CVE-2021-36942":
			t.Errorf("DC-only CVE %s should not fire on non-DC host", f.CVE)
		}
	}
}

func TestRunVulnChecks_Modern2022NoCandidates(t *testing.T) {
	computers := []adldap.LDAPComputer{
		{
			SAMAccountName:         "DC01$",
			DNSHostName:            "dc01.corp.local",
			OperatingSystem:        "Windows Server 2022 Standard",
			OperatingSystemVersion: "10.0 (20348)",
			Enabled:                true,
			IsDC:                   true,
		},
	}
	r := RunVulnChecks(computers, 10, nil, false)
	if len(r.Findings) != 0 {
		t.Errorf("Server 2022 DC should have 0 findings, got %d", len(r.Findings))
	}
}
