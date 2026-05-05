package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Models
// ============================================================

// AdminSDHolderResult contains AdminSDHolder and orphaned adminCount findings
type AdminSDHolderResult struct {
	// Accounts with adminCount=1 but not in any privileged group (orphaned)
	OrphanedAdminCount []OrphanedAdminCountFinding
	// Custom (non-default) ACEs on the AdminSDHolder template object
	CustomACEs []AdminSDHolderACEFinding
}

// OrphanedAdminCountFinding — enabled account with adminCount=1
// but no longer a member of any privileged group.
// SDProp no longer manages these, yet their security descriptor
// was hardened by AdminSDHolder — can create false sense of security
// or hide a backdoored account.
type OrphanedAdminCountFinding struct {
	SAMAccountName string
	DN             string
	Enabled        bool
}

// AdminSDHolderACEFinding — a non-default ACE on the AdminSDHolder object.
// Any ACE here is replicated to all protected objects by SDProp every 60 min.
// Attacker can persist access by adding ACE to AdminSDHolder.
type AdminSDHolderACEFinding struct {
	PrincipalSID  string
	PrincipalName string
	AccessMask    uint32
	Rights        []string
	Severity      string
	CVSS       float64
	CVSSVector string
}

// known privileged group SAMAccountNames (same list used for Protected Users check)
var sdprotectedGroups = map[string]bool{
	"Domain Admins":             true,
	"Enterprise Admins":         true,
	"Schema Admins":             true,
	"Administrators":            true,
	"Account Operators":         true,
	"Backup Operators":          true,
	"Print Operators":           true,
	"Server Operators":          true,
	"Group Policy Creator Owners": true,
	"Replicator":                true,
	"RAS and IAS Servers":       false, // not SDProp-managed, skip
	"Domain Controllers":        true,
	"Read-only Domain Controllers": true,
}

// ============================================================
// Analysis
// ============================================================

// AnalyzeAdminSDHolder checks for:
//  1. Orphaned adminCount=1 accounts (adminCount set but not in priv group)
//  2. Custom ACEs on the AdminSDHolder object in CN=System
func AnalyzeAdminSDHolder(client *adldap.Client, result *adldap.EnumerationResult) (*AdminSDHolderResult, error) {
	r := &AdminSDHolderResult{}

	// ── 1. Orphaned adminCount ────────────────────────────────
	// build set of DNs that are members of privileged groups
	privMemberDNs := make(map[string]bool)
	for _, g := range result.Groups {
		if !sdprotectedGroups[g.SAMAccountName] {
			continue
		}
		for _, m := range g.Members {
			privMemberDNs[strings.ToLower(m)] = true
		}
	}

	for _, u := range result.Users {
		if !u.AdminCount {
			continue
		}
		if strings.EqualFold(u.SAMAccountName, "krbtgt") ||
			strings.EqualFold(u.SAMAccountName, "Administrator") {
			continue
		}
		// adminCount=1 but not currently in any privileged group
		if !privMemberDNs[strings.ToLower(u.DN)] {
			r.OrphanedAdminCount = append(r.OrphanedAdminCount, OrphanedAdminCountFinding{
				SAMAccountName: u.SAMAccountName,
				DN:             u.DN,
				Enabled:        u.Enabled,
			})
		}
	}

	// ── 2. Custom ACEs on AdminSDHolder template ──────────────
	// AdminSDHolder lives at: CN=AdminSDHolder,CN=System,<BaseDN>
	adminSDHolderDN := "CN=AdminSDHolder,CN=System," + client.GetBaseDN()

	entries, err := client.SearchBase(
		adminSDHolderDN,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor", "distinguishedName"},
	)
	// Note: SearchBase doesn't pass SD control — use SearchACLBase instead
	if err != nil || len(entries) == 0 {
		// Try fetching with SD control via raw search
		entries, err = searchWithSDControl(client, adminSDHolderDN)
		if err != nil || len(entries) == 0 {
			// no access to AdminSDHolder — still return orphaned findings
			if !Quiet {
				printAdminSDHolderResult(r, false)
			}
			return r, nil
		}
	}

	sdBytes := entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) > 0 {
		aces, err := parseSecurityDescriptor(sdBytes)
		if err == nil {
			nameMap := buildNameMap(result)
			r.CustomACEs = findCustomAdminSDHolderACEs(aces, nameMap)
		}
	}

	if !Quiet {
		printAdminSDHolderResult(r, false)
	}
	return r, nil
}

// searchWithSDControl performs a base-object search with the SD control to read nTSecurityDescriptor.
func searchWithSDControl(client *adldap.Client, dn string) ([]*goldap.Entry, error) {
	conn := client.GetConn()
	if conn == nil {
		return nil, fmt.Errorf("no connection")
	}

	sdControl := goldap.NewControlString(
		"1.2.840.113556.1.4.801",
		true,
		string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
	)

	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor", "distinguishedName"},
		[]goldap.Control{sdControl},
	)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	return sr.Entries, nil
}

// findCustomAdminSDHolderACEs identifies non-default ACEs:
// any ACE where the principal is not a well-known built-in privileged SID.
func findCustomAdminSDHolderACEs(aces []ACE, nameMap map[string]nameInfo) []AdminSDHolderACEFinding {
	// built-in SIDs that legitimately appear in AdminSDHolder ACL
	builtinSIDs := map[string]bool{
		"S-1-5-18":   true, // SYSTEM
		"S-1-5-32-544": true, // Administrators (local)
	}
	// well-known RID suffixes that are expected
	builtinRIDSuffixes := []string{
		"-512", // Domain Admins
		"-519", // Enterprise Admins
		"-520", // Group Policy Creator Owners
		"-516", // Domain Controllers
		"-521", // Read-only Domain Controllers
	}

	var findings []AdminSDHolderACEFinding
	for _, ace := range aces {
		if ace.ACEType == 0x01 || ace.ACEType == 0x06 {
			continue // Deny ACE — not a backdoor
		}
		sid := ace.SID
		if builtinSIDs[sid] {
			continue
		}
		isBuiltinRID := false
		for _, suffix := range builtinRIDSuffixes {
			if strings.HasSuffix(sid, suffix) {
				isBuiltinRID = true
				break
			}
		}
		if isBuiltinRID {
			continue
		}

		// check if dangerous rights
		mask := ace.AccessMask
		dangerous := mask&ADS_RIGHT_GENERIC_ALL != 0 ||
			mask&ADS_RIGHT_WRITE_DACL != 0 ||
			mask&ADS_RIGHT_WRITE_OWNER != 0 ||
			mask&ADS_RIGHT_GENERIC_WRITE != 0

		if !dangerous {
			continue
		}

		name := sid
		if info, ok := nameMap[sid]; ok {
			name = info.Name
		}

		var rights []string
		if mask&ADS_RIGHT_GENERIC_ALL != 0 {
			rights = append(rights, "GenericAll")
		}
		if mask&ADS_RIGHT_WRITE_DACL != 0 {
			rights = append(rights, "WriteDACL")
		}
		if mask&ADS_RIGHT_WRITE_OWNER != 0 {
			rights = append(rights, "WriteOwner")
		}
		if mask&ADS_RIGHT_GENERIC_WRITE != 0 {
			rights = append(rights, "GenericWrite")
		}

		// ACE on AdminSDHolder propagates to ALL admin accounts: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
		const sdVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
		sdScore := CVSSScore(sdVec)
		findings = append(findings, AdminSDHolderACEFinding{
			PrincipalSID:  sid,
			PrincipalName: name,
			AccessMask:    mask,
			Rights:        rights,
			CVSS:          sdScore,
			CVSSVector:    sdVec,
			Severity:      CVSSSeverity(sdScore),
		})
	}
	return findings
}

// ============================================================
// Output
// ============================================================

func printAdminSDHolderResult(r *AdminSDHolderResult, showNextSteps bool) {
	color.Cyan("\n  ADMINSDHOLDER")

	if len(r.OrphanedAdminCount) == 0 && len(r.CustomACEs) == 0 {
		color.White("  %-32s no issues found", "status")
		return
	}

	if len(r.OrphanedAdminCount) > 0 {
		color.Yellow("  %-32s %d  (adminCount=1 but not in privileged group)",
			"orphaned adminCount", len(r.OrphanedAdminCount))
		for _, f := range r.OrphanedAdminCount {
			status := "disabled"
			if f.Enabled {
				status = "enabled"
			}
			color.Yellow("    %-24s %s", f.SAMAccountName, status)
		}
		color.White("  tip: clear adminCount with: Set-ADUser %s -Clear adminCount", "<samAccountName>")
	}

	if len(r.CustomACEs) > 0 {
		color.Red("\n  %-32s %d  (PERSISTENCE — ACE replicated to ALL protected objects every 60min)",
			"custom ACEs on AdminSDHolder", len(r.CustomACEs))
		for _, f := range r.CustomACEs {
			color.Red("    %-24s %s  [%s]", f.PrincipalName, f.PrincipalSID, strings.Join(f.Rights, ", "))
		}
		if showNextSteps {
			color.Cyan("\n  NEXT STEPS")
			color.White("  Remove backdoor ACE from AdminSDHolder:")
			color.White("  $acl = Get-Acl 'AD:CN=AdminSDHolder,CN=System,<BaseDN>'")
			color.White("  $acl.RemoveAccessRule(<rule>)")
			color.White("  Set-Acl 'AD:CN=AdminSDHolder,CN=System,<BaseDN>' $acl")
		}
	}
}

// PrintAdminSDHolderResult — public wrapper for standalone use (shows next steps)
func PrintAdminSDHolderResult(r *AdminSDHolderResult) {
	printAdminSDHolderResult(r, true)
}
