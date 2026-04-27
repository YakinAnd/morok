package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// Known supportedCapabilities OIDs
const (
	// LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID — DC supports LDAP signing/sealing
	oidLDAPIntegrity = "1.2.840.113556.1.4.1791"
)

type LDAPSecurityFinding struct {
	Title    string
	Detail   string
	Severity string
	CVSS     float64
}

type LDAPSecurityResult struct {
	Domain           string
	PlainLDAP        bool   // connection was on port 389
	SigningEnforced   bool   // false = signing not required = finding
	AnonReadEnabled  bool   // anonymous session can read AD objects
	Capabilities     []string
	SASLMechanisms   []string
	Findings         []LDAPSecurityFinding
}

// AnalyzeLDAPSecurity checks LDAP signing and channel binding status.
// It uses the already-established connection info + RootDSE capabilities.
func AnalyzeLDAPSecurity(client *adldap.Client, rds *adldap.RootDSEInfo) *LDAPSecurityResult {
	if rds == nil {
		return nil
	}

	r := &LDAPSecurityResult{
		Domain:         client.GetDomain(),
		PlainLDAP:      rds.PlainLDAP,
		Capabilities:   rds.SupportedCapabilities,
		SASLMechanisms: rds.SupportedSASLMechanisms,
	}

	// LDAP signing check:
	// If the authenticated session succeeded over plain port 389 (not LDAPS),
	// the DC does not require LDAP signing — traffic can be intercepted / replayed.
	if rds.PlainLDAP {
		r.SigningEnforced = false
		// LDAP MITM → credential capture/relay: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N
		ldapSignScore := CVSSScore("AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N")
		r.Findings = append(r.Findings, LDAPSecurityFinding{
			Title:    "LDAP signing not enforced",
			Detail:   "Authenticated bind succeeded over plain LDAP (port 389) without signing. An attacker performing LDAP MITM can read or modify in-flight LDAP traffic. Enforce via GPO: Network security: LDAP client signing requirements = Require signing; Domain controller: LDAP server signing requirements = Require signing.",
			CVSS:     ldapSignScore,
			Severity: CVSSSeverity(ldapSignScore),
		})
	} else {
		r.SigningEnforced = true
	}

	// Channel binding check via supportedCapabilities:
	// OID 1.2.840.113556.1.4.1791 indicates the DC *supports* signing/sealing.
	// Its absence on a non-LDAPS connection indicates an older or misconfigured DC.
	hasIntegrity := false
	for _, cap := range rds.SupportedCapabilities {
		if cap == oidLDAPIntegrity {
			hasIntegrity = true
			break
		}
	}

	if !hasIntegrity && rds.PlainLDAP {
		// Channel binding bypass → NTLM relay to LDAP: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N
		cbScore := CVSSScore("AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N")
		r.Findings = append(r.Findings, LDAPSecurityFinding{
			Title:    "LDAP channel binding not advertised",
			Detail:   fmt.Sprintf("DC does not advertise LDAP integrity OID (%s) in supportedCapabilities. Channel binding may not be enforced, increasing exposure to NTLM relay attacks against LDAP. Check KB4520412/MS Advisory ADV190023.", oidLDAPIntegrity),
			CVSS:     cbScore,
			Severity: CVSSSeverity(cbScore),
		})
	}

	// Anonymous read check
	if client.IsAnon {
		canRead := client.ProbeAnonymousRead()
		r.AnonReadEnabled = canRead
		if canRead {
			// Unauthenticated AD reconnaissance: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
			anonScore := CVSSScore("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
			r.Findings = append(r.Findings, LDAPSecurityFinding{
				Title:    "Anonymous LDAP read enabled",
				Detail:   "Unauthenticated (null session) bind can enumerate AD objects (users, groups). An attacker without credentials can perform reconnaissance. Disable anonymous LDAP access via: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters → DSHeuristics (set bit 7 to 0) and restrict null session permissions.",
				CVSS:     anonScore,
				Severity: CVSSSeverity(anonScore),
			})
		}
	}

	// Informational: flag if GSS-SPNEGO (NTLM/Kerberos) is available over plain LDAP
	// This is normal but relevant context for relay attack surface.
	if rds.PlainLDAP {
		for _, mech := range rds.SupportedSASLMechanisms {
			if strings.EqualFold(mech, "GSS-SPNEGO") || strings.EqualFold(mech, "GSSAPI") {
				// Context for relay surface — Low informational: AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
				saslScore := CVSSScore("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")
				r.Findings = append(r.Findings, LDAPSecurityFinding{
					Title:    "NTLM/Kerberos SASL available over plain LDAP",
					Detail:   fmt.Sprintf("SASL mechanism %s is available over port 389. Combined with unsigned LDAP, this enables NTLM relay to LDAP (e.g. via PetitPotam → ldap_shell / rbcd). Mitigate by enforcing LDAP signing and channel binding.", mech),
					CVSS:     saslScore,
					Severity: CVSSSeverity(saslScore),
				})
				break
			}
		}
	}

	return r
}

// PrintLDAPSecurityResult prints LDAP security findings to the terminal.
func PrintLDAPSecurityResult(r *LDAPSecurityResult) {
	if r == nil {
		return
	}

	color.Cyan("\n  LDAP SECURITY")

	transport := "LDAPS (port 636)"
	if r.PlainLDAP {
		transport = "plain LDAP (port 389)"
	}
	color.White("  %-28s %s", "transport", transport)

	signingStr := "enforced (LDAPS)"
	if !r.SigningEnforced {
		signingStr = "NOT enforced ⚠"
	}
	color.White("  %-28s %s", "signing", signingStr)

	if len(r.Findings) == 0 {
		color.White("  %-28s %s", "ldap security", "no issues found")
		return
	}

	for _, f := range r.Findings {
		line := fmt.Sprintf("  [%s] %s", f.Severity, f.Title)
		switch f.Severity {
		case "Medium":
			color.Yellow(line)
		default:
			color.White(line)
		}
	}
}

// LDAPSecuritySummaryLine prints a single summary line for the enum command output.
func LDAPSecuritySummaryLine(r *LDAPSecurityResult) {
	if r == nil || r.SigningEnforced {
		return
	}
	color.Yellow("  %-28s %s", "ldap signing", "NOT enforced — MITM possible (port 389)")
}
