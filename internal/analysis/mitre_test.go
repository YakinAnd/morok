package analysis

import (
	"strings"
	"testing"
)

func TestLookupTechniques_Kerberoasting(t *testing.T) {
	techs := LookupTechniques(MitreKerberoasting)
	if len(techs) == 0 {
		t.Fatal("expected at least one technique for kerberoasting")
	}
	if techs[0].ID != "T1558.003" {
		t.Errorf("expected T1558.003, got %s", techs[0].ID)
	}
}

func TestLookupTechniques_Unknown(t *testing.T) {
	techs := LookupTechniques("nonexistent")
	if techs != nil {
		t.Errorf("expected nil for unknown key, got %v", techs)
	}
}

func TestMitreTechniqueURL(t *testing.T) {
	tech := MitreTechnique{ID: "T1558.003", Name: "Kerberoasting"}
	url := tech.URL()
	if !strings.Contains(url, "T1558") {
		t.Errorf("URL should contain T1558, got %s", url)
	}
	if !strings.Contains(url, "attack.mitre.org") {
		t.Errorf("URL should contain attack.mitre.org, got %s", url)
	}
}

func TestAllMappingsHaveValidIDs(t *testing.T) {
	for key, techs := range mitreMappings {
		for _, tech := range techs {
			if len(tech.ID) < 5 {
				t.Errorf("key %s: technique ID %q too short", key, tech.ID)
			}
			if !strings.HasPrefix(tech.ID, "T") {
				t.Errorf("key %s: technique ID %q should start with T", key, tech.ID)
			}
			if tech.Name == "" {
				t.Errorf("key %s: technique %s has empty name", key, tech.ID)
			}
		}
	}
}
