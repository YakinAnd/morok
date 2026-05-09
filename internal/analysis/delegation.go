package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Data models
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
	TrusteeNames    []string // RBCD: principals that can act on behalf of this object
	IsHighRisk      bool
	RiskReason      string
	Severity        string
	CVSS            float64
	CVSSVector      string
}

type DelegationResult struct {
	Domain   string
	Findings []DelegationFinding
}

// ============================================================
// LDAP filters
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
// Core function
// ============================================================

// AnalyzeDelegation runs all delegation checks. Pass enumResult to resolve RBCD trustee names;
// pass nil when the enumeration result is not available (standalone delegation command).
func AnalyzeDelegation(client *adldap.Client, enumResult *adldap.EnumerationResult) (*DelegationResult, error) {
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
	if err := findRBCD(client, result, enumResult); err != nil {
		return nil, err
	}

	return result, nil
}

// ============================================================
// Search: Unconstrained
// ============================================================

func findUnconstrainedUsers(client *adldap.Client, result *DelegationResult) error {
	entries, err := client.Search(FilterUnconstrainedUsers, delegationAttributes)
	if err != nil {
		return fmt.Errorf("unconstrained user search failed: %w", err)
	}
	for _, entry := range entries {
		const unVec = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
		unScore := CVSSScore(unVec)
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     "user",
			DelegationType: DelegationUnconstrained,
			IsHighRisk:     true,
			RiskReason:     "User account with unconstrained delegation — any connecting user's TGT is cached",
			CVSS:           unScore,
			CVSSVector:     unVec,
			Severity:       CVSSSeverity(unScore),
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
		const unVec = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
		unScore := CVSSScore(unVec)
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     "computer",
			DelegationType: DelegationUnconstrained,
			IsHighRisk:     true,
			RiskReason:     "Computer with unconstrained delegation — compromise leads to TGT harvesting (PrinterBug, PetitPotam)",
			CVSS:           unScore,
			CVSSVector:     unVec,
			Severity:       CVSSSeverity(unScore),
		})
	}
	return nil
}

// ============================================================
// Search: Constrained
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

		// Constrained high-risk: AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N
		// Constrained low-risk: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N
		var conVector string
		if isHighRisk {
			conVector = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"
		} else {
			conVector = "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N"
		}
		conScore := CVSSScore(conVector)
		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName:  entry.GetAttributeValue("sAMAccountName"),
			DN:              entry.DN,
			ObjectType:      objectType,
			DelegationType:  DelegationConstrained,
			AllowedServices: allowedTo,
			IsHighRisk:      isHighRisk,
			RiskReason:      riskReason,
			CVSS:            conScore,
			CVSSVector:      conVector,
			Severity:        CVSSSeverity(conScore),
		})
	}
	return nil
}

func assessConstrainedRisk(allowedServices []string) (bool, string) {
	// Services where constrained delegation enables significant lateral movement or privilege escalation:
	// ldap/  → DCSync, LDAP writes (shadow creds, ACL changes)
	// cifs/  → file system access on target
	// host/  → includes many services (WMI, RPC, etc.) on target
	// http/  → web endpoints, Exchange EWS
	// krbtgt → Kerberos TGT service (full domain compromise)
	// rpcss/ → RPC endpoint mapper
	// wsman/ → WinRM / PowerShell remoting
	// gss-http → SPNEGO over HTTP
	// mssql/ → SQL Server impersonation
	// termsrv/ → RDP sessions
	// dns/   → DNS modification on DCs
	criticalServices := []string{
		"ldap/", "cifs/", "host/", "http/", "krbtgt",
		"rpcss/", "wsman/", "gss-http/", "mssql/", "termsrv/", "dns/",
		"dc", "domain controller",
	}
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
// Search: RBCD
// ============================================================

func findRBCD(client *adldap.Client, result *DelegationResult, enumResult *adldap.EnumerationResult) error {
	entries, err := client.Search(FilterRBCD, delegationAttributes)
	if err != nil {
		return fmt.Errorf("RBCD search failed: %w", err)
	}

	var nameMap map[string]nameInfo
	if enumResult != nil {
		nameMap = buildNameMap(enumResult)
	}

	for _, entry := range entries {
		const rbcdVec = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"
		rbcdScore := CVSSScore(rbcdVec)

		// Parse msDS-AllowedToActOnBehalfOfOtherIdentity to list who has RBCD rights.
		var trustees []string
		if nameMap != nil {
			sdBytes := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
			if len(sdBytes) > 0 {
				if aces, parseErr := parseSecurityDescriptor(sdBytes); parseErr == nil {
					seen := make(map[string]bool)
					for _, ace := range aces {
						if ace.ACEType == 0x01 || ace.ACEType == 0x06 {
							continue // skip deny ACEs
						}
						if seen[ace.SID] {
							continue
						}
						seen[ace.SID] = true
						if info, ok := nameMap[ace.SID]; ok {
							trustees = append(trustees, info.Name)
						} else {
							trustees = append(trustees, ace.SID)
						}
					}
				}
			}
		}

		riskReason := "RBCD configured"
		if len(trustees) > 0 {
			riskReason = "RBCD — principals that can act on behalf: " + strings.Join(trustees, ", ")
		} else {
			riskReason = "RBCD configured — run: Get-ADObject -Identity '<DN>' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity"
		}

		result.Findings = append(result.Findings, DelegationFinding{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			DN:             entry.DN,
			ObjectType:     getObjectTypeFromEntry(entry),
			DelegationType: DelegationRBCD,
			TrusteeNames:   trustees,
			IsHighRisk:     true,
			RiskReason:     riskReason,
			CVSS:           rbcdScore,
			CVSSVector:     rbcdVec,
			Severity:       CVSSSeverity(rbcdScore),
		})
	}
	return nil
}

// ============================================================
// Output
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
// Helper functions
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