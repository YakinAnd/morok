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

const (
	// ms-Mcs-AdmPwdExpirationTime — used to detect legacy LAPS presence on computers
	lapsExpirationAttr = "ms-Mcs-AdmPwdExpirationTime"
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
	Domain          string
	LAPSAttrGUID    string // resolved schemaIDGUID of ms-Mcs-AdmPwd (legacy LAPS)
	WinLAPSGUID     string // resolved schemaIDGUID of msLAPS-Password (Windows LAPS cleartext)
	WinLAPSEncGUID  string // resolved schemaIDGUID of msLAPS-EncryptedPassword (Windows LAPS encrypted)
	LAPSFound       bool   // at least one computer has LAPS deployed
	Findings        []LAPSACLFinding
	GMSAFindings    []GMSAACLFinding // principals that can read gMSA passwords
}

// GMSAACLFinding — principal that can retrieve a gMSA managed password.
type GMSAACLFinding struct {
	GMSAName      string
	GMSADN        string
	PrincipalName string
	PrincipalType string
	Severity      string
	CVSS          float64
	CVSSVector    string
}

// AnalyzeLAPSACL checks which non-privileged principals have ReadProperty rights
// on ms-Mcs-AdmPwd (LAPS local admin password) on domain computer objects.
func AnalyzeLAPSACL(client *adldap.Client, result *adldap.EnumerationResult) (*LAPSACLResult, error) {
	r := &LAPSACLResult{Domain: result.Domain}
	nameMap := buildNameMap(result)

	// ── 1. Resolve LAPS attribute GUIDs from schema ──────────
	r.LAPSAttrGUID, r.WinLAPSGUID, r.WinLAPSEncGUID = resolveLAPSGUIDs(client)

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
			right := lapsReadRight(ace, r.LAPSAttrGUID, r.WinLAPSGUID, r.WinLAPSEncGUID)
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

	// ── 4. gMSA password readers ──────────────────────────────
	// msDS-GroupMSAMembership is a security descriptor that controls who can
	// retrieve the gMSA's managed password. Principals in the DACL can authenticate as the gMSA.
	gmsaEntries, err := client.Search(
		"(objectClass=msDS-GroupManagedServiceAccount)",
		[]string{"sAMAccountName", "distinguishedName", "msDS-GroupMSAMembership"},
	)
	if err == nil {
		const gmsaVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
		gmsaScore := CVSSScore(gmsaVec)
		for _, ge := range gmsaEntries {
			sdBytes := ge.GetRawAttributeValue("msDS-GroupMSAMembership")
			if len(sdBytes) == 0 {
				continue
			}
			aces, parseErr := parseSecurityDescriptor(sdBytes)
			if parseErr != nil {
				continue
			}
			gmsaName := ge.GetAttributeValue("sAMAccountName")
			for _, ace := range aces {
				if ace.ACEType == 0x01 || ace.ACEType == 0x06 {
					continue
				}
				info, ok := nameMap[ace.SID]
				if !ok {
					continue
				}
				if isPrivilegedPrincipal(info.Name) {
					continue
				}
				r.GMSAFindings = append(r.GMSAFindings, GMSAACLFinding{
					GMSAName:      gmsaName,
					GMSADN:        ge.DN,
					PrincipalName: info.Name,
					PrincipalType: info.Type,
					Severity:      CVSSSeverity(gmsaScore),
					CVSS:          gmsaScore,
					CVSSVector:    gmsaVec,
				})
			}
		}
	}

	return r, nil
}

// resolveLAPSGUIDs queries the AD schema for LAPS password attribute GUIDs.
// Returns (legacyGUID, winLAPSClearGUID, winLAPSEncGUID) — empty string if not installed.
func resolveLAPSGUIDs(client *adldap.Client) (string, string, string) {
	configDN, err := client.ConfigurationDN()
	if err != nil {
		return "", "", ""
	}
	schemaDN := "CN=Schema," + configDN

	resolve := func(attrName string) string {
		entries, err := client.SearchBase(schemaDN, "(lDAPDisplayName="+attrName+")", []string{"schemaIDGUID"})
		if err != nil || len(entries) == 0 {
			return ""
		}
		raw := entries[0].GetRawAttributeValue("schemaIDGUID")
		if len(raw) < 16 {
			return ""
		}
		return formatGUID(raw)
	}

	return resolve("ms-Mcs-AdmPwd"), resolve("msLAPS-Password"), resolve("msLAPS-EncryptedPassword")
}

// lapsReadRight returns a description if the ACE grants read access to a LAPS password attribute.
// legacyGUID = ms-Mcs-AdmPwd, winClearGUID = msLAPS-Password, winEncGUID = msLAPS-EncryptedPassword.
// All GUIDs are resolved at runtime from schema; empty string means that attribute is not installed.
func lapsReadRight(ace ACE, legacyGUID, winClearGUID, winEncGUID string) string {
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
			ot := ace.ObjectType
			if legacyGUID != "" && strings.EqualFold(ot, legacyGUID) {
				return "ReadProperty(ms-Mcs-AdmPwd)"
			}
			if winClearGUID != "" && strings.EqualFold(ot, winClearGUID) {
				return "ReadProperty(msLAPS-Password)"
			}
			if winEncGUID != "" && strings.EqualFold(ot, winEncGUID) {
				return "ReadProperty(msLAPS-EncryptedPassword)"
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

	if len(r.GMSAFindings) > 0 {
		color.Cyan("\n  GMSA PASSWORD READERS")
		color.Red("  %-28s %d — principals can retrieve gMSA managed password", "gmsa risks", len(r.GMSAFindings))
		color.White("  %-24s %-10s %s", "principal", "type", "gmsa account")
		color.White("  " + strings.Repeat("-", 60))
		for _, f := range r.GMSAFindings {
			line := "  " + padRight(f.PrincipalName, 24) + " " + padRight(f.PrincipalType, 10) + " " + f.GMSAName
			color.Red(line)
		}
		color.White("\n  Retrieve gMSA password hash:")
		color.White("    bloodyAD -u '<principal>' -p '<pass>' -d <domain> --host <DC> get object '<gMSA>' --attr msDS-ManagedPassword")
	}
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
