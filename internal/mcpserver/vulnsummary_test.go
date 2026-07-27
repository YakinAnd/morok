package mcpserver

import "testing"

func TestParseVulnSummary(t *testing.T) {
	cases := []struct {
		input string
		want  parsedVuln
		ok    bool
	}{
		{"MS17-010|EternalBlue|confirmed|OLDMAESTER$", parsedVuln{CVE: "MS17-010", Name: "EternalBlue", Status: "confirmed", Host: "OLDMAESTER$"}, true},
		{"CVE-2021-36942|PetitPotam|candidate|KINGSLANDING$", parsedVuln{CVE: "CVE-2021-36942", Name: "PetitPotam", Status: "candidate", Host: "KINGSLANDING$"}, true},
		{"not enough parts", parsedVuln{}, false},
		{"", parsedVuln{}, false},
		{"a|b|c|d|e", parsedVuln{}, false},
	}
	for _, c := range cases {
		got, ok := parseVulnSummary(c.input)
		if ok != c.ok {
			t.Errorf("parseVulnSummary(%q) ok = %v, want %v", c.input, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseVulnSummary(%q) = %+v, want %+v", c.input, got, c.want)
		}
	}
}
