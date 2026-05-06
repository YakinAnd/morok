package analysis

import (
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

const (
	// ADS_RIGHT_DS_READ_PROP — ReadProperty on a specific or all attributes
	ADS_RIGHT_DS_READ_PROP = 0x00000010
	// ADS_RIGHT_GENERIC_READ — Generic Read (implies ReadProperty on all)
	ADS_RIGHT_GENERIC_READ = 0x80000000
)

// LAPS attribute display names and their schemaIDGUID constants.
// Legacy LAPS GUID is fixed per MS schema extension; Windows LAPS uses a different one.
// We resolve the GUID dynamically from the schema; these are fallback well-known values.
const (
	// ms-Mcs-AdmPwd — legacy Microsoft LAPS password attribute
	guidLegacyLAPSPwd = "f0c8c3d5-3b6e-4f97-9b6d-0e8a4d8b4c2c"
	// ms-Mcs-AdmPwdExpirationTime — legacy LAPS expiration (used to detect LAPS presence)
	lapsExpirationAttr = "ms-Mcs-AdmPwdExpirationTime"
	// msLAPS-Password — Windows LAPS (Server 2022+) cleartext password
	guidWindowsLAPSPwd = "3e0abfd0-126a-4a33-a845-7a23a5c8e9d1"
)

// LAPSACLFinding — a principal that can read LAPS passwords on a computer.
type LAPSACLFinding struct {
	PrincipalName string
	PrincipalType string
	PrincipalDN   string
	ComputerName  string
	ComputerDN    string
	Right         string
	Severity      string
	CVSS          float64
	CVSSVector    string
}

// LAPSACLResult contains all findings for LAPS password read access.
type LAPSACLResult struct {
	Domain        string
	LAPSAttrGUID  string // resolved schemaIDGUID of ms-Mcs-AdmPwd (empty if schema not readable)
	LAPSFound     bool   // at least one computer has LAPS deployed
	Findings      []LAPSACLFinding
}

// AnalyzeLAPSACL checks which non-privileged principals have ReadProperty rights
// on ms-Mcs-AdmPwd (LAPS local admin password) on domain computer objects.
func AnalyzeLAPSACL(client *adldap.Client, result *adldap.EnumerationResult) (*LAPSACLResult, error) {
	r := &LAPSACLResult{Domain: result.Domain}
	nameMap := buildNameMap(result)

	// ── 1. Resolve ms-Mcs-AdmPwd schemaIDGUID from schema ────
	r.LAPSAttrGUID = resolveLAPSGUID(client)

	// ── 2. Collect LAPS-enabled computers ─────────────────────
	var lapsComputers []adldap.LDAPComputer
	for _, c := range result.Computers {
		if c.LAPSEnabled {
			lapsComputers = append(lapsComputers, c)
			r.LAPSFound = true
		}
	}
	if len(lapsComputers) == 0 {
		return r, nil
	}

	// ── 3. For each LAPS computer, parse ACL ──────────────────
	seenKey := make(map[string]bool) // deduplicate principal+computer pairs

	for _, comp := range lapsComputers {
		entries, err := client.SearchBase(comp.DN, "(objectClass=*)", sdOnlyAttrs)
		if err != nil || len(entries) == 0 {
			continue
		}
		sdBytes := entries[0].GetRawAttributeValue("nTSecurityDescriptor")
		if len(sdBytes) == 0 {
			continue
		}
		aces, err := parseSecurityDescriptor(sdBytes)
		if err != nil {
			continue
		}

		for _, ace := range aces {
			if ace.ACEType == 0x01 || ace.ACEType == 0x06 { // Deny
				continue
			}
			right := lapsReadRight(ace, r.LAPSAttrGUID)
			if right == "" {
				continue
			}

			// Skip the computer itself
			if strings.EqualFold(ace.SID, comp.ObjectSid) {
				continue
			}

			info, ok := nameMap[ace.SID]
			if !ok {
				continue
			}

			// Skip expected privileged principals
			if isPrivilegedPrincipal(info.Name) {
				continue
			}

			key := ace.SID + "|" + comp.DN
			if seenKey[key] {
				continue
			}
			seenKey[key] = true

			const lapsVec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
			lapsScore := CVSSScore(lapsVec)
			r.Findings = append(r.Findings, LAPSACLFinding{
				PrincipalName: info.Name,
				PrincipalType: info.Type,
				PrincipalDN:   info.DN,
				ComputerName:  comp.SAMAccountName,
				ComputerDN:    comp.DN,
				Right:         right,
				CVSS:          lapsScore,
				CVSSVector:    lapsVec,
				Severity:      CVSSSeverity(lapsScore),
			})
		}
	}

	return r, nil
}

// resolveLAPSGUID queries the AD schema for the schemaIDGUID of ms-Mcs-AdmPwd.
// Returns an empty string if LAPS is not installed or the schema is not readable.
func resolveLAPSGUID(client *adldap.Client) string {
	configDN, err := client.ConfigurationDN()
	if err != nil {
		return ""
	}
	schemaDN := "CN=Schema," + configDN

	entries, err := client.SearchBase(schemaDN, "(lDAPDisplayName=ms-Mcs-AdmPwd)", []string{"schemaIDGUID"})
	if err != nil || len(entries) == 0 {
		return ""
	}

	raw := entries[0].GetRawAttributeValue("schemaIDGUID")
	if len(raw) < 16 {
		return ""
	}
	return formatGUID(raw)
}

// lapsReadRight returns a description if the ACE grants read access to the LAPS password attribute.
func lapsReadRight(ace ACE, lapsGUID string) string {
	mask := ace.AccessMask

	// GenericAll → full control
	if mask&ADS_RIGHT_GENERIC_ALL != 0 {
		return "GenericAll"
	}

	// GenericRead → read all properties (includes LAPS)
	if mask&ADS_RIGHT_GENERIC_READ != 0 {
		return "GenericRead"
	}

	// WriteDACL / WriteOwner → can grant themselves read
	if mask&ADS_RIGHT_WRITE_DACL != 0 {
		return "WriteDACL"
	}
	if mask&ADS_RIGHT_WRITE_OWNER != 0 {
		return "WriteOwner"
	}

	// ReadProperty — needs ObjectType check
	if mask&ADS_RIGHT_DS_READ_PROP != 0 {
		// ACE type 0x05 (Object ACE): restricted to specific attribute
		if ace.ACEType == 0x05 {
			if lapsGUID != "" && strings.EqualFold(ace.ObjectType, lapsGUID) {
				return "ReadProperty(ms-Mcs-AdmPwd)"
			}
			// Also check the well-known fallback GUID
			if strings.EqualFold(ace.ObjectType, guidLegacyLAPSPwd) {
				return "ReadProperty(ms-Mcs-AdmPwd)"
			}
			return "" // restricted to a different attribute
		}
		// ACE type 0x00 (non-object): ReadProperty on ALL properties
		if ace.ACEType == 0x00 {
			return "ReadProperty(all)"
		}
	}

	return ""
}

// ============================================================
// Terminal output
// ============================================================

func PrintLAPSACLResult(r *LAPSACLResult) {
	if r == nil {
		return
	}

	color.Cyan("\n  LAPS ACL")

	if !r.LAPSFound {
		color.White("  %-28s no LAPS-enabled computers found", "status")
		return
	}

	if len(r.Findings) == 0 {
		color.White("  %-28s no unexpected read access detected", "laps read acl")
		return
	}

	color.Red("  %-28s %d — non-privileged principals can read local admin passwords", "laps read risks", len(r.Findings))
	color.White("  %-24s %-10s %-30s %s", "principal", "type", "computer", "right")
	color.White("  " + strings.Repeat("-", 78))

	for _, f := range r.Findings {
		line := "  " + padRight(f.PrincipalName, 24) + " " + padRight(f.PrincipalType, 10) + " " + padRight(f.ComputerName, 30) + " " + f.Right
		color.Red(line)
	}

	color.Cyan("\n  NEXT STEPS")
	color.White("  Use LAPS read access to retrieve local admin password:")
	color.White("    Get-AdmPwdPassword -ComputerName '<computer>'  # as the privileged principal")
	color.White("    crackmapexec smb <target> -u '<principal>' -p '<pass>' --laps")
	color.White("  Review ACL on computer object:")
	color.White("    Get-ACL 'AD:<computer DN>' | Select-Object -ExpandProperty Access")
}

// LAPSACLSummaryLine prints a one-liner for the enum summary.
func LAPSACLSummaryLine(r *LAPSACLResult) {
	if r == nil || len(r.Findings) == 0 {
		return
	}
	color.Red("  %-28s %d  (non-privileged principals can read LAPS passwords)", "laps read risks", len(r.Findings))
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}
