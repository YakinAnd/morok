package report

import (
	"html/template"
	"sort"
)

// RiskScore holds the aggregated security risk assessment (0–100, A–F).
type RiskScore struct {
	Total     int
	Grade     string
	Breakdown map[string]int
}

// BreakdownEntry is one row in the sorted risk breakdown table.
type BreakdownEntry struct {
	Name  string
	Value int
}

// SortedBreakdown returns Breakdown as a slice sorted by value descending
// (largest contributor first). Stable tie-break by name. Guaranteed order
// between template renders — map iteration is non-deterministic.
func (r RiskScore) SortedBreakdown() []BreakdownEntry {
	entries := make([]BreakdownEntry, 0, len(r.Breakdown))
	for name, value := range r.Breakdown {
		entries = append(entries, BreakdownEntry{Name: name, Value: value})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Value != entries[j].Value {
			return entries[i].Value > entries[j].Value
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

// GradeColor returns a CSS color variable for the grade letter.
func (r RiskScore) GradeColor() template.CSS {
	switch r.Grade {
	case "A":
		return template.CSS("var(--color-ok)")
	case "B":
		return template.CSS("#84cc16")
	case "C":
		return template.CSS("var(--text-sev-medium)")
	case "D":
		return template.CSS("var(--text-sev-high)")
	case "F":
		return template.CSS("var(--text-sev-critical)")
	}
	return template.CSS("var(--text-main)")
}

const (
	weightCriticalPath   = 15
	capCriticalPath      = 30
	weightDangerousACL   = 2
	capDangerousACL      = 20
	weightKerberoastable = 5
	capKerberoastable    = 15
	weightASREP          = 5
	capASREP             = 10
	weightDelegation     = 8
	capDelegation        = 15
	weightADCS           = 10
	capADCS              = 20
	weightWeakPolicy     = 5
	capWeakPolicy        = 15
	weightStaleAdmin     = 3
	capStaleAdmin        = 10
	weightNoLAPS         = 1
	capNoLAPS            = 5
	weightShadowCreds    = 3
	capShadowCreds       = 10
)

func capped(value, cap int) int {
	if value > cap {
		return cap
	}
	return value
}

// CalculateRiskScore computes a weighted, capped 0–100 risk score from report data.
func CalculateRiskScore(d *ReportData) RiskScore {
	bd := map[string]int{}

	bd["Attack Paths"] = capped(len(d.AttackPaths)*weightCriticalPath, capCriticalPath)

	aclCount := 0
	if d.ACLResult != nil {
		aclCount = len(d.ACLResult.Findings)
	}
	bd["Dangerous ACLs"] = capped(aclCount*weightDangerousACL, capDangerousACL)

	kerb := 0
	asrep := 0
	if d.KerberosResult != nil {
		kerb = len(d.KerberosResult.KerberoastableAccounts)
		asrep = len(d.KerberosResult.ASREPAccounts)
	}
	bd["Kerberoasting"] = capped(kerb*weightKerberoastable, capKerberoastable)
	bd["AS-REP Roasting"] = capped(asrep*weightASREP, capASREP)

	delegCount := 0
	if d.DelegationResult != nil {
		delegCount = len(d.DelegationResult.Findings)
	}
	bd["Delegation"] = capped(delegCount*weightDelegation, capDelegation)

	adcsCount := 0
	if d.ADCSResult != nil {
		adcsCount = len(d.ADCSResult.TemplateFindings)
	}
	bd["ADCS"] = capped(adcsCount*weightADCS, capADCS)

	policyScore := 0
	if d.HygieneResult != nil {
		if d.Summary.WeakPasswordPolicy {
			policyScore += weightWeakPolicy
		}
		if d.HygieneResult.KrbtgtPwdAgeDays > 180 {
			policyScore += weightWeakPolicy
		}
	}
	bd["Policy"] = capped(policyScore, capWeakPolicy)

	staleAdmins := 0
	if d.HygieneResult != nil {
		for _, u := range d.HygieneResult.StaleUsers {
			if u.AdminCount {
				staleAdmins++
			}
		}
	}
	bd["Stale Admins"] = capped(staleAdmins*weightStaleAdmin, capStaleAdmin)

	bd["No LAPS"] = capped(d.Summary.NoLAPSCount*weightNoLAPS, capNoLAPS)

	shadowCount := 0
	if d.ShadowCredentialsResult != nil {
		shadowCount = len(d.ShadowCredentialsResult.Findings)
	}
	bd["Shadow Creds"] = capped(shadowCount*weightShadowCreds, capShadowCreds)

	total := 0
	for _, v := range bd {
		total += v
	}
	if total > 100 {
		total = 100
	}

	grade := "A"
	switch {
	case total >= 80:
		grade = "F"
	case total >= 60:
		grade = "D"
	case total >= 40:
		grade = "C"
	case total >= 20:
		grade = "B"
	}

	return RiskScore{Total: total, Grade: grade, Breakdown: bd}
}
