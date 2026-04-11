package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Models
// ============================================================

type ADCSVulnType string

const (
	ESC1 ADCSVulnType = "ESC1" // Enrollee supplies subject (SAN injection)
	ESC2 ADCSVulnType = "ESC2" // Any Purpose / no EKU
	ESC3 ADCSVulnType = "ESC3" // Certificate Request Agent EKU
	ESC4 ADCSVulnType = "ESC4" // Low-priv principal has write permissions on template object
	ESC6 ADCSVulnType = "ESC6" // CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
	ESC7 ADCSVulnType = "ESC7" // Low-priv principal has ManageCA / ManageCertificates on CA
	ESC8 ADCSVulnType = "ESC8" // Web Enrollment endpoint active (NTLM relay possible)
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
	TemplateName    string
	TemplateOID     string
	CAName          string
	VulnTypes       []ADCSVulnType
	EnrollableBy    []string
	AllowsSANInject bool
	EKUs            []string
	AuthEnabled     bool // has Client Auth / Smart Card Logon EKU
	Severity        string
}

type CAFinding struct {
	CAName    string
	CADN      string
	VulnTypes []ADCSVulnType
	WebEnroll bool
	Details   string
	Severity  string
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
			result.CAFindings = append(result.CAFindings, CAFinding{
				CAName:    ca.Name,
				CADN:      ca.DN,
				VulnTypes: []ADCSVulnType{ESC6},
				Details:   "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set — any template issued by this CA allows SAN injection regardless of template settings. Equivalent to ESC1 for all templates.",
				Severity:  "Critical",
			})
		}

		// ESC8: flag Web Enrollment as potential (requires HTTP probe to confirm)
		result.CAFindings = append(result.CAFindings, CAFinding{
			CAName:    ca.Name,
			CADN:      ca.DN,
			VulnTypes: []ADCSVulnType{ESC8},
			WebEnroll: true,
			Details:   "Verify if Web Enrollment is active: http://" + ca.Server + "/certsrv/ — if accessible and NTLM auth is allowed, PetitPotam/Coercer → certipy relay attack is possible.",
			Severity:  "High",
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

	printADCSResult(result, false)
	return result, nil
}

// ============================================================
// Template analysis
// ============================================================

type ldapEntry interface {
	GetAttributeValue(string) string
	GetAttributeValues(string) []string
}

func analyzeTemplate(e ldapEntry) *CertTemplateFinding {
	name := e.GetAttributeValue("cn")
	if name == "" {
		name = e.GetAttributeValue("displayName")
	}

	// Parse msPKI-Certificate-Name-Flag as int32 (can be negative — signed)
	nameFlagStr := e.GetAttributeValue("msPKI-Certificate-Name-Flag")
	nameFlag, _ := strconv.ParseInt(nameFlagStr, 10, 64)

	ekus  := e.GetAttributeValues("pKIExtendedKeyUsage")
	raSig := e.GetAttributeValue("msPKI-RA-Signature")

	var vulns []ADCSVulnType
	allowsSAN  := false
	authEnabled := false

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

	// Only flag templates that enable authentication — others are low risk
	if !authEnabled && !allowsSAN {
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

	// Severity: Critical if ESC1 + auth EKU, else High
	sev := "High"
	if containsVuln(vulns, ESC1) && authEnabled {
		sev = "Critical"
	}

	return &CertTemplateFinding{
		TemplateName:    name,
		TemplateOID:     e.GetAttributeValue("msPKI-Cert-Template-OID"),
		VulnTypes:       vulns,
		AllowsSANInject: allowsSAN,
		AuthEnabled:     authEnabled,
		EKUs:            ekuDisplay,
		Severity:        sev,
	}
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
		color.White("  %-24s %-10s %-16s %s", "template", "severity", "vulns", "auth EKU")
		color.White("  " + strings.Repeat("-", 64))
		for _, f := range r.TemplateFindings {
			authStr := ""
			if f.AuthEnabled {
				authStr = strings.Join(f.EKUs, ", ")
			}
			line := fmt.Sprintf("  %-24s %-10s %-16s %s", f.TemplateName, f.Severity, formatVulns(f.VulnTypes), authStr)
			if f.Severity == "Critical" {
				color.Red(line)
			} else {
				color.Yellow(line)
			}
		}
	}

	// CA-level findings (ESC6)
	for _, cf := range r.CAFindings {
		if containsVuln(cf.VulnTypes, ESC6) {
			color.Red("\n  [ESC6] %s — %s", cf.CAName, cf.Details)
		}
	}

	// Next steps
	hasCritical := critCount > 0 || func() bool {
		for _, cf := range r.CAFindings {
			if containsVuln(cf.VulnTypes, ESC6) {
				return true
			}
		}
		return false
	}()

	if showNextSteps && (hasCritical || len(r.TemplateFindings) > 0) {
		color.Cyan("\n  NEXT STEPS")
		if critCount > 0 {
			color.White("  ESC1  certipy req -u user@%s -p pass -ca <CA> -template <tmpl> -upn admin@%s", r.Domain, r.Domain)
			color.White("        certipy auth -pfx admin.pfx -domain %s -dc-ip <DC>", r.Domain)
		}
		for _, cf := range r.CAFindings {
			if containsVuln(cf.VulnTypes, ESC8) {
				color.White("  ESC8  certipy relay -target http://%s/certsrv/certfnsh.asp -template Machine", cf.CAName)
				break
			}
		}
	}
}

// PrintADCSResult — public wrapper for standalone adcs command (shows next steps)
func PrintADCSResult(r *ADCSResult) {
	printADCSResult(r, true)
}
