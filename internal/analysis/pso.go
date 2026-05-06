package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Models
// ============================================================

// PSO — Fine-Grained Password Settings Object
type PSO struct {
	Name             string
	Precedence       int
	MinLength        int
	Complexity       bool
	LockoutThreshold int
	MaxAgeDays       int   // 0 = never expires
	AppliesTo        []string // SAMAccountNames / group names
	IsWeak           bool
	WeakReasons      []string
}

// PSOResult — result of Fine-Grained Password Policy analysis
type PSOResult struct {
	PSOs []PSO
}

var psoAttributes = []string{
	"cn",
	"distinguishedName",
	"msDS-PasswordSettingsPrecedence",
	"msDS-MinimumPasswordLength",
	"msDS-PasswordComplexityEnabled",
	"msDS-LockoutThreshold",
	"msDS-MaximumPasswordAge",
	"msDS-PSOAppliesTo",
}

// ============================================================
// Analysis
// ============================================================

// AnalyzePSO enumerates Fine-Grained Password Policy objects
func AnalyzePSO(client *adldap.Client) (*PSOResult, error) {
	baseDN := "CN=Password Settings Container,CN=System," + client.GetBaseDN()
	entries, err := client.SearchBase(baseDN, "(objectClass=msDS-PasswordSettings)", psoAttributes)
	if err != nil {
		return &PSOResult{}, nil
	}

	result := &PSOResult{}

	for _, entry := range entries {
		pso := PSO{
			Name:             entry.GetAttributeValue("cn"),
			Precedence:       parseInt(entry.GetAttributeValue("msDS-PasswordSettingsPrecedence")),
			MinLength:        parseInt(entry.GetAttributeValue("msDS-MinimumPasswordLength")),
			Complexity:       parseBool(entry.GetAttributeValue("msDS-PasswordComplexityEnabled")),
			LockoutThreshold: parseInt(entry.GetAttributeValue("msDS-LockoutThreshold")),
			MaxAgeDays:       parseMaxAgeDays(entry.GetAttributeValue("msDS-MaximumPasswordAge")),
			AppliesTo:        resolveAppliesTo(entry.GetAttributeValues("msDS-PSOAppliesTo")),
		}

		// assess weakness
		if pso.MinLength < 8 {
			pso.IsWeak = true
			pso.WeakReasons = append(pso.WeakReasons, fmt.Sprintf("min length %d < 8", pso.MinLength))
		}
		if !pso.Complexity {
			pso.IsWeak = true
			pso.WeakReasons = append(pso.WeakReasons, "complexity disabled")
		}
		if pso.LockoutThreshold == 0 {
			pso.IsWeak = true
			pso.WeakReasons = append(pso.WeakReasons, "no lockout (brute force possible)")
		}
		if pso.MaxAgeDays == 0 {
			pso.IsWeak = true
			pso.WeakReasons = append(pso.WeakReasons, "passwords never expire")
		}

		result.PSOs = append(result.PSOs, pso)
	}

	if len(result.PSOs) > 0 {
		color.Cyan("\n  FINE-GRAINED PASSWORD POLICY  (%d)", len(result.PSOs))
		for _, p := range result.PSOs {
			if p.IsWeak {
				color.Yellow("  [WEAK] %-24s prec:%d  %s", p.Name, p.Precedence, strings.Join(p.WeakReasons, "; "))
			} else {
				color.White("  [OK]   %-24s prec:%d", p.Name, p.Precedence)
			}
		}
	}

	return result, nil
}

// ============================================================
// Helpers
// ============================================================

func parseInt(s string) int {
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

func parseBool(s string) bool {
	return strings.EqualFold(s, "true") || s == "1"
}

// parseMaxAgeDays converts msDS-MaximumPasswordAge (negative 100-ns intervals) to days.
// Value is stored as a negative large integer (same as maxPwdAge). 0 = never.
func parseMaxAgeDays(s string) int {
	if s == "" || s == "0" {
		return 0
	}
	// value is negative: e.g. -36288000000000 = 42 days
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return 0
	}
	if n < 0 {
		n = -n
	}
	days := int(n / (10000000 * 86400)) // 100-ns → seconds → days
	return days
}

// resolveAppliesTo extracts the CN from each DN for display
func resolveAppliesTo(dns []string) []string {
	var names []string
	for _, dn := range dns {
		parts := strings.Split(dn, ",")
		if len(parts) > 0 {
			cn := strings.TrimPrefix(parts[0], "CN=")
			names = append(names, cn)
		}
	}
	return names
}
