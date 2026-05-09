package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
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
	CVSS       float64
	CVSSVector string
}

type LDAPSecurityResult struct {
	Domain           string
	PlainLDAP        bool   // connection was on port 389
	SigningEnforced  bool   // true only when verified that signing is required
	SigningChecked   bool   // true only when connected via port 389 (can determine signing policy)
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
	// When connected via LDAPS (636) we cannot determine the signing policy for port 389:
	// a DC can simultaneously accept unsigned LDAP on 389 and TLS on 636.
	if rds.PlainLDAP {
		r.SigningChecked = true
		r.SigningEnforced = false
		// LDAP MITM → credential capture/relay: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N
		const ldapSignVec = "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"
		ldapSignScore := CVSSScore(ldapSignVec)
		r.Findings = append(r.Findings, LDAPSecurityFinding{
			Title:      "LDAP signing not enforced",
			Detail:     "Authenticated bind succeeded over plain LDAP (port 389) without signing. An attacker performing LDAP MITM can read or modify in-flight LDAP traffic. Enforce via GPO: Network security: LDAP client signing requirements = Require signing; Domain controller: LDAP server signing requirements = Require signing.",
			CVSS:       ldapSignScore,
			CVSSVector: ldapSignVec,
			Severity:   CVSSSeverity(ldapSignScore),
		})
	}
	// else: LDAPS — signing policy on port 389 is unknown; SigningChecked stays false

	// LDAP integrity capability check (OID 1.2.840.113556.1.4.1791):
	// This OID indicates the DC *supports* LDAP signing/sealing (integrity protection),
	// NOT channel binding. Channel binding (EPA) is a server-side registry setting
	// (LdapEnforceChannelBinding) and cannot be detected via RootDSE alone.
	// Absence of this OID over plain LDAP indicates an older or misconfigured DC.
	hasIntegrity := false
	for _, cap := range rds.SupportedCapabilities {
		if cap == oidLDAPIntegrity {
			hasIntegrity = true
			break
		}
	}

	if !hasIntegrity && rds.PlainLDAP {
		const cbVec = "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"
		cbScore := CVSSScore(cbVec)
		r.Findings = append(r.Findings, LDAPSecurityFinding{
			Title:      "LDAP integrity (signing) not advertised",
			Detail:     fmt.Sprintf("DC does not advertise LDAP integrity OID (%s) in supportedCapabilities — signing/sealing may not be enforced. Note: channel binding (EPA) is a separate setting not detectable via LDAP; verify LdapEnforceChannelBinding registry value manually. Check KB4520412 / MS Advisory ADV190023.", oidLDAPIntegrity),
			CVSS:       cbScore,
			CVSSVector: cbVec,
			Severity:   CVSSSeverity(cbScore),
		})
	}

	// Anonymous read check
	if client.IsAnon {
		canRead := client.ProbeAnonymousRead()
		r.AnonReadEnabled = canRead
		if canRead {
			// Unauthenticated AD reconnaissance: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
			const anonVec = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
			anonScore := CVSSScore(anonVec)
			r.Findings = append(r.Findings, LDAPSecurityFinding{
				Title:      "Anonymous LDAP read enabled",
				Detail:     "Unauthenticated (null session) bind can enumerate AD objects (users, groups). An attacker without credentials can perform reconnaissance. Disable anonymous LDAP access via: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters → DSHeuristics (set bit 7 to 0) and restrict null session permissions.",
				CVSS:       anonScore,
				CVSSVector: anonVec,
				Severity:   CVSSSeverity(anonScore),
			})
		}
	}

	// Informational: flag if GSS-SPNEGO (NTLM/Kerberos) is available over plain LDAP
	// This is normal but relevant context for relay attack surface.
	if rds.PlainLDAP {
		for _, mech := range rds.SupportedSASLMechanisms {
			if strings.EqualFold(mech, "GSS-SPNEGO") || strings.EqualFold(mech, "GSSAPI") {
				// Context for relay surface — Low informational: AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
				const saslVec = "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
				saslScore := CVSSScore(saslVec)
				r.Findings = append(r.Findings, LDAPSecurityFinding{
					Title:      "NTLM/Kerberos SASL available over plain LDAP",
					Detail:     fmt.Sprintf("SASL mechanism %s is available over port 389. Combined with unsigned LDAP, this enables NTLM relay to LDAP (e.g. via PetitPotam → ldap_shell / rbcd). Mitigate by enforcing LDAP signing and channel binding.", mech),
					CVSS:       saslScore,
					CVSSVector: saslVec,
					Severity:   CVSSSeverity(saslScore),
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

	var signingStr string
	switch {
	case !r.SigningChecked:
		signingStr = "unknown (LDAPS — port 389 not tested)"
	case r.SigningEnforced:
		signingStr = "enforced"
	default:
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
	if r == nil || !r.SigningChecked || r.SigningEnforced {
		return
	}
	color.Yellow("  %-28s %s", "ldap signing", "NOT enforced — MITM possible (port 389)")
}
