package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Моделі даних
// ============================================================

type DelegationType string

const (
	DelegationUnconstrained DelegationType = "Unconstrained"
	DelegationConstrained   DelegationType = "Constrained"
	DelegationRBCD          DelegationType = "Resource-Based Constrained"
)

type DelegationFinding struct {
	SAMAccountName  string
	DN              string
	ObjectType      string
	DelegationType  DelegationType
	AllowedServices []string
	AllowedTo       []string
	IsHighRisk      bool
	RiskReason      string
}

type DelegationResult struct {
	Domain   string
	Findings []DelegationFinding
}

// ============================================================
// LDAP фільтри
// ============================================================

const (
	FilterUnconstrainedUsers = "(&(objectClass=user)" +
		"(userAccountControl:1.2.840.113556.1.4.803:=524288)" +
		"(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"

	FilterUnconstrainedComputers = "(&(objectClass=computer)" +
		"(userAccountControl:1.2.840.113556.1.4.803:=524288)" +
		"(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"

	FilterConstrainedDelegation = "(&(|(objectClass=user)(objectClass=computer))" +
		"(msDS-AllowedToDelegateTo=*))"

	FilterRBCD = "(&(|(objectClass=user)(objectClass=computer))" +
		"(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
)

var delegationAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"objectClass",
	"userAccountControl",
	"msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
}

// ============================================================
// Основна функція
// ============================================================

func AnalyzeDelegation(client *adldap.Client) (*DelegationResult, error) {
	result := &DelegationResult{
		Domain: client.GetDomain(),
	}


	if err := findUnconstrainedUsers(client, result); err != nil {
		return nil, err
	}
	if err := findUnconstrainedComputers(client, result); err != nil {
		return nil, err
	}
	if err := findConstrainedDelegation(client, result); err != nil {
		return nil, err
	}
	if err := findRBCD(client, result); err != nil {
		return nil, err
	}

	return result, nil
}

// ============================================================
// Пошук Unconstrained
// ============================================================

func findUnconstrainedUsers(client *adldap.Client, result *DelegationResult) error {
	entries, err := client.Search(FilterUnconstrainedUsers, delegationAttributes)
	if err != nil {
		return fmt.Errorf("unconstrained user search failed: %w", err)
	}
	for _, entry := range entries {
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     "user",
			DelegationType: DelegationUnconstrained,
			IsHighRisk:     true,
			RiskReason:     "User account with unconstrained delegation — any connecting user's TGT is cached",
		})
	}
	return nil
}

func findUnconstrainedComputers(client *adldap.Client, result *DelegationResult) error {
	entries, err := client.Search(FilterUnconstrainedComputers, delegationAttributes)
	if err != nil {
		return fmt.Errorf("unconstrained computer search failed: %w", err)
	}
	for _, entry := range entries {
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     "computer",
			DelegationType: DelegationUnconstrained,
			IsHighRisk:     true,
			RiskReason:     "Computer with unconstrained delegation — compromise leads to TGT harvesting (PrinterBug, PetitPotam)",
		})
	}
	return nil
}

// ============================================================
// Пошук Constrained
// ============================================================

func findConstrainedDelegation(client *adldap.Client, result *DelegationResult) error {
	entries, err := client.Search(FilterConstrainedDelegation, delegationAttributes)
	if err != nil {
		return fmt.Errorf("constrained delegation search failed: %w", err)
	}
	for _, entry := range entries {
		allowedTo := entry.GetAttributeValues("msDS-AllowedToDelegateTo")
		objectType := getObjectTypeFromEntry(entry)
		isHighRisk, riskReason := assessConstrainedRisk(allowedTo)

		uac := delegParseUAC(entry.GetAttributeValue("userAccountControl"))
		if delegIsBitSet(uac, 0x1000000) {
			isHighRisk = true
			riskReason = "Protocol Transition enabled (S4U2Self) — can impersonate any user"
		}

		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName:  entry.GetAttributeValue("sAMAccountName"),
			DN:              entry.DN,
			ObjectType:      objectType,
			DelegationType:  DelegationConstrained,
			AllowedServices: allowedTo,
			IsHighRisk:      isHighRisk,
			RiskReason:      riskReason,
		})
	}
	return nil
}

func assessConstrainedRisk(allowedServices []string) (bool, string) {
	criticalServices := []string{"ldap/", "cifs/", "host/", "http/", "krbtgt", "dc", "domain controller"}
	for _, svc := range allowedServices {
		svcLower := strings.ToLower(svc)
		for _, critical := range criticalServices {
			if strings.Contains(svcLower, critical) {
				return true, fmt.Sprintf("Delegation allowed to critical service: %s", svc)
			}
		}
	}
	return false, ""
}

// ============================================================
// Пошук RBCD
// ============================================================

func findRBCD(client *adldap.Client, result *DelegationResult) error {
	entries, err := client.Search(FilterRBCD, delegationAttributes)
	if err != nil {
		return fmt.Errorf("RBCD search failed: %w", err)
	}
	for _, entry := range entries {
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     getObjectTypeFromEntry(entry),
			DelegationType: DelegationRBCD,
			IsHighRisk:     true,
			RiskReason:     "RBCD configured — check who can delegate to this object (potential privilege escalation)",
		})
	}
	return nil
}

// ============================================================
// Вивід
// ============================================================

func PrintDelegationResult(dr *DelegationResult) {
	color.Cyan("\n  DELEGATION")
	if len(dr.Findings) == 0 {
		color.White("  none found")
		return
	}

	unconstrained := filterByDelegationType(dr.Findings, DelegationUnconstrained)
	constrained := filterByDelegationType(dr.Findings, DelegationConstrained)
	rbcd := filterByDelegationType(dr.Findings, DelegationRBCD)

	if len(unconstrained) > 0 {
		color.Red("  UNCONSTRAINED (%d)", len(unconstrained))
		for _, f := range unconstrained {
			printDelegationFinding(f)
		}
		color.Cyan("\n  next steps (unconstrained):")
		color.White("    printerbug.py %s/<user>:<pass>@<DC> <vuln-host>  # trigger DC auth", dr.Domain)
		color.White("    rubeus.exe monitor /interval:1 /nowrap            # capture TGT")
	}
	if len(constrained) > 0 {
		color.Yellow("\n  CONSTRAINED (%d)", len(constrained))
		for _, f := range constrained {
			printDelegationFinding(f)
			for _, svc := range f.AllowedServices {
				color.White("    allowed: %s", svc)
			}
		}
		color.Cyan("\n  next steps (constrained):")
		color.White("    getST.py -spn <allowed-spn> -impersonate Administrator %s/<account>:<pass>", dr.Domain)
	}
	if len(rbcd) > 0 {
		color.Yellow("\n  RBCD (%d)", len(rbcd))
		for _, f := range rbcd {
			printDelegationFinding(f)
		}
		color.Cyan("\n  next steps (rbcd):")
		color.White("    rbcd.py -f <controlled> -t <target> -dc-ip <DC> %s/<user>:<pass>", dr.Domain)
	}
}

func printDelegationFinding(f DelegationFinding) {
	risk := ""
	if f.RiskReason != "" {
		risk = "  ! " + f.RiskReason
	}
	color.White("  %-20s  %-10s%s", f.SAMAccountName, f.ObjectType, risk)
}

// ============================================================
// Допоміжні функції
// ============================================================

func filterByDelegationType(findings []DelegationFinding, dt DelegationType) []DelegationFinding {
	var result []DelegationFinding
	for _, f := range findings {
		if f.DelegationType == dt {
			result = append(result, f)
		}
	}
	return result
}

func getObjectTypeFromEntry(entry interface{ GetAttributeValues(string) []string }) string {
	for _, c := range entry.GetAttributeValues("objectClass") {
		if strings.ToLower(c) == "computer" {
			return "computer"
		}
	}
	return "user"
}

func delegParseUAC(val string) uint64 {
	if val == "" {
		return 0
	}
	n, _ := strconv.ParseUint(val, 10, 64)
	return n
}

func delegIsBitSet(uac uint64, bit uint64) bool {
	return uac&bit != 0
}