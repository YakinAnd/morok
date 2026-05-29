package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Data models
// ============================================================

// GPOFinding — a discovered GPO with its security findings
type GPOFinding struct {
	Name            string
	DN              string
	GUID            string
	LinkedTo        []string // OUs/Domain this GPO is linked to
	EditableBy      []string // principals that can edit this GPO (excluding admins)
	HasCPassword    bool     // GPO uses Preferences CSE that may contain cpassword
	IsHighRisk      bool
	RiskReasons     []string
	ACLFindings     []GPOACLFinding // dangerous write ACEs on this GPO object
}

// GPOACLFinding — low-priv principal with write access to a GPO object.
// WriteDACL/GenericAll on a GPO → can add scripts, logon tasks, etc.
type GPOACLFinding struct {
	GPOName       string
	GPOLinkedTo   []string // OUs/Domain this GPO is linked to (scope of impact)
	PrincipalName string
	PrincipalSID  string
	Rights        []string
	Severity      string
	CVSS       float64
	CVSSVector string
}

// PasswordPolicy — domain password policy settings
type PasswordPolicy struct {
	MinLength            int
	MaxAge               int  // days
	MinAge               int  // days
	Complexity           bool
	LockoutThreshold     int
	LockoutDuration      int  // minutes (0 = requires admin unlock)
	ReversibleEncryption bool
}

// GPOResult — GPO analysis result
type GPOResult struct {
	Domain          string
	GPOFindings     []GPOFinding
	GPOACLFindings  []GPOACLFinding // all dangerous GPO ACL findings (flattened)
	PasswordPolicy  *PasswordPolicy
	DefaultPolicy   *PasswordPolicy
}

// ============================================================
// LDAP filters
// ============================================================

const (
	FilterAllGPO       = "(objectClass=groupPolicyContainer)"
	FilterOUWithGPO    = "(&(objectClass=organizationalUnit)(gPLink=*))"
	FilterDomainObject = "(objectClass=domain)"
)

var gpoAttributes = []string{
	"distinguishedName",
	"displayName",
	"name",
	"gPCFileSysPath",
	"gPCMachineExtensionNames",
	"gPCUserExtensionNames",
	"nTSecurityDescriptor",
	"objectClass",
}

// gppCSEGuids — CSE GUIDs whose Preferences XML may contain cpassword
// (Groups, Drives, Printers, ScheduledTasks, Services, DataSources)
var gppCSEGuids = []string{
	"AADCED64-746C-4633-A97C-D61349046527", // Groups (machine)
	"91FBB303-0CD5-4055-BF42-E512A681B325", // Groups (user)
	"5794DAFD-BE60-433f-88A2-1A31939AC01F", // Drives
	"BC75B1ED-5833-4858-9BB8-CBF0B166DF9D", // Printers
	"BDDBE5E0-4B0B-4261-9ED1-26E7DAB4B6CF", // ScheduledTasks
	"A3F3E39B-5D83-4940-B954-28315B82F0A8", // ScheduledTasks (user)
	"BA649533-96CF-4F53-B4FA-F69ADE6B6F39", // DataSources
}

var ouAttributes = []string{
	"distinguishedName",
	"gPLink",
	"name",
}

var domainAttributes = []string{
	"distinguishedName",
	"gPLink",
	"minPwdLength",
	"maxPwdAge",
	"minPwdAge",
	"pwdProperties",
	"lockoutThreshold",
	"lockoutDuration",
	"lockoutObservationWindow",
}

// ============================================================
// Core analysis function
// ============================================================

// AnalyzeGPO finds dangerous GPO configurations. Pass an EnumerationResult to
// enable SID→name resolution for non-builtin principals in GPO ACLs.
func AnalyzeGPO(client *adldap.Client, optResult ...*adldap.EnumerationResult) (*GPOResult, error) {
	result := &GPOResult{
		Domain: client.GetDomain(),
	}

	gpos, err := collectGPOs(client)
	if err != nil {
		return nil, err
	}

	links, err := collectGPOLinks(client)
	if err != nil {
		return nil, err
	}

	for i := range gpos {
		guid := extractGUID(gpos[i].GUID)
		for ou, ouLinks := range links {
			for _, link := range ouLinks {
				if strings.EqualFold(extractGUID(link), guid) {
					gpos[i].LinkedTo = append(gpos[i].LinkedTo, ou)
				}
			}
		}
	}

	nameMap := make(map[string]nameInfo)
	if len(optResult) > 0 && optResult[0] != nil {
		nameMap = buildNameMap(optResult[0])
	}
	for i := range gpos {
		analyzeGPOPermissions(client, &gpos[i], nameMap)
	}

	for _, gpo := range gpos {
		if gpo.IsHighRisk || len(gpo.EditableBy) > 0 {
			result.GPOFindings = append(result.GPOFindings, gpo)
			result.GPOACLFindings = append(result.GPOACLFindings, gpo.ACLFindings...)
		}
	}

	pp, err := collectPasswordPolicy(client)
	if err != nil {
		color.Yellow("[!] Could not collect password policy: %v", err)
	} else {
		result.DefaultPolicy = pp
		assessPasswordPolicy(pp, result)
	}

	return result, nil
}

// ============================================================
// GPO object collection
// ============================================================

func collectGPOs(client *adldap.Client) ([]GPOFinding, error) {
	entries, err := client.Search(FilterAllGPO, gpoAttributes)
	if err != nil {
		return nil, fmt.Errorf("GPO search failed: %w", err)
	}

	var gpos []GPOFinding
	for _, entry := range entries {
		gpo := GPOFinding{
			Name: entry.GetAttributeValue("displayName"),
			DN:   entry.DN,
			GUID: entry.GetAttributeValue("name"),
		}

		// check CSE GUIDs for GPP Preferences
		machineCSE := entry.GetAttributeValue("gPCMachineExtensionNames")
		userCSE    := entry.GetAttributeValue("gPCUserExtensionNames")
		gpo.HasCPassword = checkForCPassword(machineCSE + userCSE)

		if gpo.HasCPassword {
			// CSE GUID presence only means the GPO uses Preferences — not that any
			// XML actually contains a cpassword. Flag as unverified; the SYSVOL scan
			// performs the definitive file-level check.
			gpo.RiskReasons = append(gpo.RiskReasons,
				"[Unverified] GPO uses Preferences CSE — check SYSVOL for cpassword: findstr /S /I cpassword \\\\<DC>\\SYSVOL\\*.xml")
		}

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

// ============================================================
// GPO link collection
// ============================================================

func collectGPOLinks(client *adldap.Client) (map[string][]string, error) {
	links := make(map[string][]string)

	ouEntries, err := client.Search(FilterOUWithGPO, ouAttributes)
	if err != nil {
		return nil, fmt.Errorf("OU GPO link search failed: %w", err)
	}

	for _, entry := range ouEntries {
		gPLink := entry.GetAttributeValue("gPLink")
		if gPLink == "" {
			continue
		}
		parsedLinks := parseGPLink(gPLink)
		if len(parsedLinks) > 0 {
			ouName := entry.GetAttributeValue("name")
			if ouName == "" {
				ouName = entry.DN
			}
			links[ouName] = parsedLinks
		}
	}

	domainEntries, err := client.Search(FilterDomainObject, domainAttributes)
	if err == nil {
		for _, entry := range domainEntries {
			gPLink := entry.GetAttributeValue("gPLink")
			if gPLink != "" {
				parsedLinks := parseGPLink(gPLink)
				if len(parsedLinks) > 0 {
					links["Domain"] = parsedLinks
				}
			}
		}
	}

	return links, nil
}

// parseGPLink parses a gPLink attribute value in the format:
// [LDAP://cn={GUID},cn=policies,...;0][LDAP://cn={GUID},...;2]
func parseGPLink(gPLink string) []string {
	var guids []string
	parts := strings.Split(gPLink, "[")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// extract GUID in {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} format
		start := strings.Index(part, "{")
		end := strings.Index(part, "}")
		if start != -1 && end != -1 && end > start {
			guid := part[start : end+1]
			guids = append(guids, guid)
		}
	}
	return guids
}

// extractGUID normalizes a GUID to {GUID} format
func extractGUID(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		s = "{" + s
	}
	if !strings.HasSuffix(s, "}") {
		s = s + "}"
	}
	return strings.ToLower(s)
}

// ============================================================
// GPO permission analysis
// ============================================================

// analyzeGPOPermissions checks who has dangerous write permissions on a GPO object.
// Uses the SD control to fetch nTSecurityDescriptor, then parses for low-priv write ACEs.
func analyzeGPOPermissions(client *adldap.Client, gpo *GPOFinding, nameMap map[string]nameInfo) {
	conn := client.GetConn()
	if conn == nil {
		return
	}

	sdControl := goldap.NewControlString(
		"1.2.840.113556.1.4.801",
		true,
		string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
	)

	req := goldap.NewSearchRequest(
		gpo.DN,
		goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=*)",
		[]string{"nTSecurityDescriptor"},
		[]goldap.Control{sdControl},
	)
	sr, err := conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return
	}

	sdBytes := sr.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return
	}

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return
	}

	for _, ace := range aces {
		if ace.ACEType == 0x01 || ace.ACEType == 0x06 {
			continue
		}
		principalName, lowPriv := isLowPrivSID(ace.SID)
		if !lowPriv {
			// also check nameMap for non-builtin principals
			if info, ok := nameMap[ace.SID]; ok {
				// skip known admin groups
				if isAdminGroup(info.Name) {
					continue
				}
				principalName = info.Name
				lowPriv = true
			}
		}
		if !lowPriv {
			continue
		}

		mask := ace.AccessMask
		dangerous := mask&ADS_RIGHT_GENERIC_ALL != 0 ||
			mask&ADS_RIGHT_WRITE_DACL != 0 ||
			mask&ADS_RIGHT_WRITE_OWNER != 0 ||
			mask&ADS_RIGHT_GENERIC_WRITE != 0

		if !dangerous {
			continue
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

		f := GPOACLFinding{
			GPOName:       gpo.Name,
			GPOLinkedTo:   gpo.LinkedTo,
			PrincipalName: principalName,
			PrincipalSID:  ace.SID,
			Rights:        rights,
		}
		// GPO linked to Domain or DC OU → Critical (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
		// Otherwise High (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)
		gpoVector := "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
		for _, link := range gpo.LinkedTo {
			if strings.EqualFold(link, "Domain") ||
				strings.Contains(strings.ToLower(link), "domain controller") {
				gpoVector = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
				break
			}
		}
		gpoScore := CVSSScore(gpoVector)
		f.CVSS = gpoScore
		f.CVSSVector = gpoVector
		f.Severity = CVSSSeverity(gpoScore)

		gpo.ACLFindings = append(gpo.ACLFindings, f)
		if len(gpo.ACLFindings) == 1 {
			gpo.IsHighRisk = true
			gpo.EditableBy = append(gpo.EditableBy, principalName)
		}
	}
}

// isAdminGroup returns true for well-known built-in admin group names
func isAdminGroup(name string) bool {
	switch name {
	case "Domain Admins", "Enterprise Admins", "Administrators",
		"SYSTEM", "Group Policy Creator Owners", "Schema Admins":
		return true
	}
	return false
}

// ============================================================
// Password Policy
// ============================================================

func collectPasswordPolicy(client *adldap.Client) (*PasswordPolicy, error) {
	entries, err := client.Search(FilterDomainObject, domainAttributes)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("domain object not found")
	}

	entry := entries[0]
	pp := &PasswordPolicy{}

	// minPwdLength
	if v := entry.GetAttributeValue("minPwdLength"); v != "" {
		fmt.Sscanf(v, "%d", &pp.MinLength)
	}

	// pwdProperties bit 0x1 = DOMAIN_PASSWORD_COMPLEX
	if v := entry.GetAttributeValue("pwdProperties"); v != "" {
		var props int
		fmt.Sscanf(v, "%d", &props)
		pp.Complexity = (props & 0x1) != 0
		pp.ReversibleEncryption = (props & 0x10) != 0
	}

	// lockoutThreshold
	if v := entry.GetAttributeValue("lockoutThreshold"); v != "" {
		fmt.Sscanf(v, "%d", &pp.LockoutThreshold)
	}

	// maxPwdAge — Windows stores as negative 100-nanosecond intervals
	if v := entry.GetAttributeValue("maxPwdAge"); v != "" {
		age, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			if age < 0 {
				age = -age
			}
			pp.MaxAge = int(age / 864000000000)
		}
	}

	// minPwdAge — same encoding; 0 = no minimum age
	if v := entry.GetAttributeValue("minPwdAge"); v != "" {
		age, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			if age < 0 {
				age = -age
			}
			pp.MinAge = int(age / 864000000000)
		}
	}

	// lockoutDuration — negative 100-ns intervals; 0xFFFFFFFFFFFFFFFF = indefinite (admin unlock)
	if v := entry.GetAttributeValue("lockoutDuration"); v != "" {
		dur, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			if dur < 0 {
				dur = -dur
			}
			if dur == 0 {
				pp.LockoutDuration = 0 // requires admin unlock
			} else {
				pp.LockoutDuration = int(dur / 600000000) // convert to minutes
			}
		}
	}

	return pp, nil
}

func assessPasswordPolicy(pp *PasswordPolicy, result *GPOResult) {
	// check for weak settings
	_ = pp
	_ = result
}

// ============================================================
// cpassword detection
// ============================================================

// checkForCPassword reports whether any of the GPO's CSE GUIDs are known to
// produce Preferences XML that may contain cpassword (MS14-025 / GPP password exposure).
// Detection is LDAP-only via gPCMachineExtensionNames / gPCUserExtensionNames —
// SYSVOL access is required for definitive confirmation.
func checkForCPassword(cseNames string) bool {
	if cseNames == "" {
		return false
	}
	upper := strings.ToUpper(cseNames)
	for _, guid := range gppCSEGuids {
		if strings.Contains(upper, strings.ToUpper(guid)) {
			return true
		}
	}
	return false
}

// ============================================================
// Output functions
// ============================================================

// PrintGPOResult prints GPO analysis results
func PrintGPOResult(gr *GPOResult) {
	printPasswordPolicyResult(gr)
	printGPOFindings(gr)
	printGPOACLFindings(gr)
}

func printPasswordPolicyResult(gr *GPOResult) {
	color.Cyan("\n  PASSWORD POLICY")
	if gr.DefaultPolicy == nil {
		color.White("  could not retrieve")
		return
	}
	pp := gr.DefaultPolicy

	printPolicyLine("min length", func() { color.White("  %-24s %d", "min length", pp.MinLength) },
		pp.MinLength < 8, pp.MinLength < 12,
		fmt.Sprintf("%d  (rec: 12+)", pp.MinLength))

	if !pp.Complexity {
		color.Red("  %-24s DISABLED", "complexity")
	} else {
		color.White("  %-24s enabled", "complexity")
	}
	if pp.ReversibleEncryption {
		color.Red("  %-24s ENABLED  (plaintext-equivalent)", "reversible enc")
	} else {
		color.White("  %-24s disabled", "reversible enc")
	}
	if pp.LockoutThreshold == 0 {
		color.Red("  %-24s DISABLED  (brute force possible)", "lockout threshold")
	} else if pp.LockoutThreshold > 10 {
		color.Yellow("  %-24s %d  (rec: ≤5)", "lockout threshold", pp.LockoutThreshold)
	} else {
		color.White("  %-24s %d", "lockout threshold", pp.LockoutThreshold)
	}
	if pp.LockoutDuration == 0 {
		color.White("  %-24s until admin unlock", "lockout duration")
	} else if pp.LockoutDuration < 15 {
		color.Yellow("  %-24s %d min  (rec: ≥15)", "lockout duration", pp.LockoutDuration)
	} else {
		color.White("  %-24s %d min", "lockout duration", pp.LockoutDuration)
	}
	if pp.MinAge == 0 {
		color.Yellow("  %-24s 0 days  (passwords can be changed immediately)", "min pwd age")
	} else {
		color.White("  %-24s %d days", "min pwd age", pp.MinAge)
	}
	if pp.MaxAge == 0 || pp.MaxAge > 3650 {
		color.Red("  %-24s never expires", "max pwd age")
	} else if pp.MaxAge > 90 {
		color.Yellow("  %-24s %d days  (rec: ≤90)", "max pwd age", pp.MaxAge)
	} else {
		color.White("  %-24s %d days", "max pwd age", pp.MaxAge)
	}
}

func printPolicyLine(label string, _ func(), bad bool, warn bool, val string) {
	if bad {
		color.Red("  %-24s %s", label, val)
	} else if warn {
		color.Yellow("  %-24s %s", label, val)
	} else {
		color.White("  %-24s %s", label, val)
	}
}

func printGPOFindings(gr *GPOResult) {
	color.Cyan("\n  GPO FINDINGS")
	if len(gr.GPOFindings) == 0 {
		color.White("  none found")
		return
	}

	for _, gpo := range gr.GPOFindings {
		sev := "WARN"
		if gpo.IsHighRisk {
			sev = "CRIT"
		}
		color.Yellow("  [%s] %s", sev, gpo.Name)
		for _, editor := range gpo.EditableBy {
			color.Red("       editable by: %s", editor)
		}
		for _, reason := range gpo.RiskReasons {
			color.Red("       risk: %s", reason)
		}
	}

	color.Cyan("\n  next steps (gpo abuse):")
	color.White("    pyGPOAbuse.py -f AddLocalAdmin -u <user> -p <pass> -d %s --dc-ip <DC>", gr.Domain)
	color.White("    findstr /S /I cpassword \\\\%s\\SYSVOL\\%s\\Policies\\*.xml", gr.Domain, gr.Domain)
}

func printGPOACLFindings(gr *GPOResult) {
	if len(gr.GPOACLFindings) == 0 {
		return
	}
	color.Cyan("\n  GPO ACL FINDINGS")
	color.White("  %-28s %-12s %-20s %s", "GPO", "severity", "principal", "rights")
	color.White("  " + strings.Repeat("-", 72))
	for _, f := range gr.GPOACLFindings {
		linked := ""
		if len(f.GPOLinkedTo) > 0 {
			linked = "  [linked: " + strings.Join(f.GPOLinkedTo, ", ") + "]"
		}
		line := fmt.Sprintf("  %-28s %-12s %-20s %s%s",
			f.GPOName, f.Severity, f.PrincipalName,
			strings.Join(f.Rights, ", "), linked)
		if f.Severity == "Critical" {
			color.Red(line)
		} else {
			color.Yellow(line)
		}
	}
	color.Cyan("\n  NEXT STEPS (GPO ACL)")
	color.White("  # Modify GPO to add local admin:")
	color.White("  pyGPOAbuse.py -f AddLocalAdmin -u '<principal>' -p '<pass>' -d %s --dc-ip <DC> --gpo-id '<GUID>'", gr.Domain)
	color.White("  # Or add computer startup script:")
	color.White("  pyGPOAbuse.py -f ComputerTask -u '<principal>' -p '<pass>' -d %s --dc-ip <DC> --task-name exec --command cmd.exe", gr.Domain)
}