package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Models
// ============================================================

// ADCSVulnType — ESC type identifier
type ADCSVulnType string

const (
	ESC1 ADCSVulnType = "ESC1" // Enrollee supplies subject (SAN) + any user can enroll
	ESC2 ADCSVulnType = "ESC2" // Any Purpose EKU or no EKU
	ESC3 ADCSVulnType = "ESC3" // Certificate Request Agent EKU
	ESC4 ADCSVulnType = "ESC4" // Template has dangerous write permissions
	ESC7 ADCSVulnType = "ESC7" // CA has ManageCA or ManageCertificates rights for low-priv principal
	ESC8 ADCSVulnType = "ESC8" // NTLM relay to HTTP enrollment endpoint (Web Enrollment enabled)
)

// CertTemplateFinding — one vulnerable certificate template
type CertTemplateFinding struct {
	TemplateName    string
	TemplateOID     string // pKIExpirationPeriod / msPKI-Cert-Template-OID
	CAName          string
	VulnTypes       []ADCSVulnType
	EnrollableBy    []string // principals that can enroll
	AllowsSANInject bool     // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	EKUs            []string
	Severity        string // Critical / High / Medium
}

// CAFinding — CA-level misconfiguration
type CAFinding struct {
	CAName      string
	CADN        string
	VulnTypes   []ADCSVulnType
	WebEnroll   bool   // HTTP enrollment endpoint active
	Details     string
	Severity    string
}

// ADCSResult — full ADCS analysis result
type ADCSResult struct {
	Domain            string
	CAs               []CAInfo
	TemplateFindings  []CertTemplateFinding
	CAFindings        []CAFinding
}

// CAInfo — basic CA info
type CAInfo struct {
	Name   string
	DN     string
	Server string // dNSHostName
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
	"msPKI-Certificate-Name-Flag",  // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
	"msPKI-Enrollment-Flag",        // CT_FLAG_PEND_ALL_REQUESTS etc.
	"pKIExtendedKeyUsage",          // EKU OIDs
	"nTSecurityDescriptor",         // ACL — who can enroll
	"msPKI-RA-Signature",           // num of authorized signatures required
	"msPKI-Cert-Template-OID",
}

var caAttributes = []string{
	"cn",
	"displayName",
	"distinguishedName",
	"dNSHostName",
	"certificateTemplates",
	"nTSecurityDescriptor",
}

// EKU OIDs that make a template dangerous (ESC2)
var dangerousEKUs = map[string]bool{
	"2.5.29.37.0":           true, // Any Purpose
	"1.3.6.1.5.5.7.3.2":    true, // Client Authentication
	"1.3.6.1.4.1.311.20.2.1": true, // Certificate Request Agent (ESC3)
}

// EKU OID → human name
var ekuNames = map[string]string{
	"1.3.6.1.5.5.7.3.1":      "Server Authentication",
	"1.3.6.1.5.5.7.3.2":      "Client Authentication",
	"1.3.6.1.5.5.7.3.4":      "Email",
	"2.5.29.37.0":             "Any Purpose",
	"1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
	"1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
}

// ============================================================
// Main analysis function
// ============================================================

// AnalyzeADCS discovers ADCS misconfigurations via LDAP.
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
		result.CAs = append(result.CAs, CAInfo{
			Name:   e.GetAttributeValue("cn"),
			DN:     e.DN,
			Server: e.GetAttributeValue("dNSHostName"),
		})
		// ESC8: if CA has web enrollment (HTTP) — flag it
		// We detect by checking if dNSHostName is set (CA is reachable)
		// Real detection requires HTTP probe — we flag as potential
		caF := CAFinding{
			CAName:    e.GetAttributeValue("cn"),
			CADN:      e.DN,
			VulnTypes: []ADCSVulnType{ESC8},
			WebEnroll: true,
			Details:   "Web Enrollment may be enabled — check http://" + e.GetAttributeValue("dNSHostName") + "/certsrv/. If accessible, NTLM relay attacks (PetitPotam → ESC8) are possible.",
			Severity:  "High",
		}
		result.CAFindings = append(result.CAFindings, caF)
	}

	// ── 2. Enumerate certificate templates ───────────────────
	templatesBase := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + configDN
	tmplEntries, err := client.SearchBase(templatesBase, filterCertTemplates, certTemplateAttributes)
	if err != nil {
		return nil, fmt.Errorf("template enumeration failed: %w", err)
	}

	for _, e := range tmplEntries {
		finding := analyzeTemplate(e)
		if finding != nil {
			result.TemplateFindings = append(result.TemplateFindings, *finding)
		}
	}

	printADCSResult(result)
	return result, nil
}

// analyzeTemplate checks a single template for ESC1/ESC2/ESC3
func analyzeTemplate(e interface{ GetAttributeValue(string) string; GetAttributeValues(string) []string }) *CertTemplateFinding {
	name := e.GetAttributeValue("cn")
	if name == "" {
		name = e.GetAttributeValue("displayName")
	}

	nameFlag := e.GetAttributeValue("msPKI-Certificate-Name-Flag")
	ekus     := e.GetAttributeValues("pKIExtendedKeyUsage")
	raSig    := e.GetAttributeValue("msPKI-RA-Signature")

	var vulns []ADCSVulnType
	allowsSAN := false

	// ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (bit 1 = 0x00000001)
	// msPKI-Certificate-Name-Flag is a signed int32
	if nameFlag == "1" || strings.HasPrefix(nameFlag, "-") {
		// flag has ENROLLEE_SUPPLIES_SUBJECT bit
		allowsSAN = true
		vulns = append(vulns, ESC1)
	}

	// ESC2/ESC3: check EKUs
	for _, eku := range ekus {
		if eku == "2.5.29.37.0" {
			vulns = appendUniq(vulns, ESC2)
		}
		if eku == "1.3.6.1.4.1.311.20.2.1" {
			vulns = appendUniq(vulns, ESC3)
		}
	}

	// ESC3 also: no authorized signatures required + CRA EKU
	if raSig == "0" || raSig == "" {
		for _, eku := range ekus {
			if eku == "1.3.6.1.4.1.311.20.2.1" {
				vulns = appendUniq(vulns, ESC3)
			}
		}
	}

	if len(vulns) == 0 {
		return nil
	}

	// Map EKU OIDs to names
	var ekuNames2 []string
	for _, oid := range ekus {
		if n, ok := ekuNames[oid]; ok {
			ekuNames2 = append(ekuNames2, n)
		} else {
			ekuNames2 = append(ekuNames2, oid)
		}
	}

	sev := "High"
	if containsVuln(vulns, ESC1) {
		sev = "Critical"
	}

	return &CertTemplateFinding{
		TemplateName:    name,
		TemplateOID:     e.GetAttributeValue("msPKI-Cert-Template-OID"),
		VulnTypes:       vulns,
		AllowsSANInject: allowsSAN,
		EKUs:            ekuNames2,
		Severity:        sev,
	}
}

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

// ============================================================
// Terminal output
// ============================================================

func printADCSResult(r *ADCSResult) {
	color.Cyan("\n  ADCS")
	color.White("  %-28s %d", "certificate authorities", len(r.CAs))
	for _, ca := range r.CAs {
		color.White("    %-26s %s", ca.Name, ca.Server)
	}

	color.White("  %-28s %d", "vulnerable templates", len(r.TemplateFindings))
	if len(r.TemplateFindings) > 0 {
		color.White("  %-20s %-10s %s", "template", "severity", "vulns")
		color.White("  " + strings.Repeat("-", 54))
		for _, f := range r.TemplateFindings {
			vulnStr := formatVulns(f.VulnTypes)
			if f.Severity == "Critical" {
				color.Red("  %-20s %-10s %s", f.TemplateName, f.Severity, vulnStr)
			} else {
				color.Yellow("  %-20s %-10s %s", f.TemplateName, f.Severity, vulnStr)
			}
		}
	}

	if len(r.CAFindings) > 0 {
		color.Cyan("\n  NEXT STEPS")
		color.White("  ESC1  certipy req -u user@domain -p pass -ca <CA> -template <tmpl> -upn admin@domain")
		color.White("        certipy auth -pfx admin.pfx -domain domain")
		color.White("  ESC8  certipy relay -target http://<CA>/certsrv/certfnsh.asp -template Machine")
	}
}

func formatVulns(vulns []ADCSVulnType) string {
	s := make([]string, len(vulns))
	for i, v := range vulns {
		s[i] = string(v)
	}
	return strings.Join(s, ", ")
}

// PrintADCSResult — public wrapper for standalone adcs command
func PrintADCSResult(r *ADCSResult) {
	printADCSResult(r)
}
