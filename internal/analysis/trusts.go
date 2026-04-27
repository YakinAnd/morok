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

// TrustDirection maps trustDirection attribute values
type TrustDirection int

const (
	TrustDirectionDisabled     TrustDirection = 0
	TrustDirectionInbound      TrustDirection = 1 // we trust them
	TrustDirectionOutbound     TrustDirection = 2 // they trust us
	TrustDirectionBidirectional TrustDirection = 3
)

func (d TrustDirection) String() string {
	switch d {
	case TrustDirectionInbound:
		return "Inbound"
	case TrustDirectionOutbound:
		return "Outbound"
	case TrustDirectionBidirectional:
		return "Bidirectional"
	default:
		return "Disabled"
	}
}

// TrustType maps trustType attribute values
type TrustType int

const (
	TrustTypeDownlevel  TrustType = 1 // Windows NT 4.0
	TrustTypeUplevel    TrustType = 2 // Active Directory (same forest or cross-forest)
	TrustTypeKerberos   TrustType = 3 // MIT Kerberos realm
	TrustTypeDCE        TrustType = 4 // DCE
)

func (t TrustType) String() string {
	switch t {
	case TrustTypeDownlevel:
		return "Downlevel (NT4)"
	case TrustTypeUplevel:
		return "AD (Uplevel)"
	case TrustTypeKerberos:
		return "MIT Kerberos"
	case TrustTypeDCE:
		return "DCE"
	default:
		return fmt.Sprintf("Unknown(%d)", int(t))
	}
}

// trustAttributes bitmask constants
const (
	// TRUST_ATTRIBUTE_NON_TRANSITIVE — trust is non-transitive
	trustAttrNonTransitive = 0x00000001
	// TRUST_ATTRIBUTE_UPLEVEL_ONLY — only uplevel clients
	trustAttrUplevelOnly = 0x00000002
	// TRUST_ATTRIBUTE_QUARANTINED_DOMAIN — SID filtering enabled (safe)
	trustAttrSIDFilteringEnabled = 0x00000004
	// TRUST_ATTRIBUTE_FOREST_TRANSITIVE — forest-wide trust
	trustAttrForestTransitive = 0x00000008
	// TRUST_ATTRIBUTE_CROSS_ORGANIZATION — cross-org (selective auth)
	trustAttrCrossOrganization = 0x00000010
	// TRUST_ATTRIBUTE_WITHIN_FOREST — internal to forest (parent-child or tree-root)
	trustAttrWithinForest = 0x00000020
	// TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL — treat forest trust as external
	trustAttrTreatAsExternal = 0x00000040
	// TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION — uses RC4 (weaker)
	trustAttrRC4 = 0x00000080
)

// Trust represents a single trustedDomain object
type Trust struct {
	Name           string // target domain DNS name
	FlatName       string // NetBIOS name
	Direction      TrustDirection
	TrustType      TrustType
	Attributes     int64
	SIDFilteringOn bool   // true = safe, false = SID history abuse possible
	IsForest       bool   // forest-wide trust
	IsWithinForest bool   // parent-child or tree-root (within same forest)
	Risks          []string
	Severity       string
	CVSS           float64
}

// FSPFinding — Foreign Security Principal with privileged group membership
// User/group from a trusted domain that has been added to a local privileged group
type FSPFinding struct {
	FSPDN          string   // DN of the FSP object
	ExternalSID    string   // SID of the external principal
	MemberOfGroups []string // privileged groups this FSP is member of
	Severity       string
	CVSS           float64
}

// TrustResult contains all trust-related findings
type TrustResult struct {
	Domain   string
	Trusts   []Trust
	FSPs     []FSPFinding
}

// ============================================================
// LDAP attributes
// ============================================================

var trustAttributes = []string{
	"distinguishedName",
	"name",           // target domain DNS name
	"flatName",       // NetBIOS name
	"trustDirection",
	"trustType",
	"trustAttributes",
	"securityIdentifier",
}

var fspAttributes = []string{
	"distinguishedName",
	"objectSid",
	"memberOf",
	"name",
}

// ============================================================
// Analysis
// ============================================================

// AnalyzeTrusts enumerates domain trusts and finds risky configurations:
//   - SID filtering disabled → SID history abuse possible
//   - Bidirectional forest trust → lateral movement across forest boundary
//   - Foreign Security Principals in privileged groups
func AnalyzeTrusts(client *adldap.Client, result *adldap.EnumerationResult) (*TrustResult, error) {
	r := &TrustResult{Domain: client.GetDomain()}

	// ── 1. Enumerate trustedDomain objects ────────────────────
	entries, err := client.Search("(objectClass=trustedDomain)", trustAttributes)
	if err != nil {
		return nil, fmt.Errorf("trust enumeration failed: %w", err)
	}

	for _, e := range entries {
		direction, _ := strconv.Atoi(e.GetAttributeValue("trustDirection"))
		ttype, _ := strconv.Atoi(e.GetAttributeValue("trustType"))
		attrs, _ := strconv.ParseInt(e.GetAttributeValue("trustAttributes"), 10, 64)

		t := Trust{
			Name:           e.GetAttributeValue("name"),
			FlatName:       e.GetAttributeValue("flatName"),
			Direction:      TrustDirection(direction),
			TrustType:      TrustType(ttype),
			Attributes:     attrs,
			SIDFilteringOn: attrs&trustAttrSIDFilteringEnabled != 0,
			IsForest:       attrs&trustAttrForestTransitive != 0,
			IsWithinForest: attrs&trustAttrWithinForest != 0,
		}

		// ── risk assessment ───────────────────────────────────
		sev := "Info"

		// SID filtering OFF on non-internal trust = High risk
		if !t.SIDFilteringOn && !t.IsWithinForest {
			t.Risks = append(t.Risks,
				"SID filtering disabled — SID history abuse possible: attacker in trusted domain can forge SIDs to escalate in this domain")
			sev = "High"
		}

		// Bidirectional forest trust = higher exposure
		if t.Direction == TrustDirectionBidirectional && t.IsForest {
			t.Risks = append(t.Risks,
				"Bidirectional forest trust — compromise of either forest grants access to the other")
			if sev != "High" {
				sev = "Medium"
			}
		}

		// Bidirectional external trust without SID filtering
		if t.Direction == TrustDirectionBidirectional && !t.SIDFilteringOn && !t.IsWithinForest {
			sev = "Critical"
		}

		// RC4 encryption only (weak)
		if attrs&trustAttrRC4 != 0 {
			t.Risks = append(t.Risks, "Trust uses RC4 encryption — weak, susceptible to Kerberoast-style attacks against trust keys")
			if sev == "Info" {
				sev = "Low"
			}
		}

		var trustVector string
		switch sev {
		case "Critical":
			// Bidirectional external trust without SID filtering: AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H
			trustVector = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
		case "High":
			// SID filtering disabled: AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N
			trustVector = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"
		case "Medium":
			// Bidirectional forest trust: AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N
			trustVector = "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N"
		case "Low":
			// RC4 only: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
			trustVector = "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
		default:
			t.Severity = "Info"
			r.Trusts = append(r.Trusts, t)
			continue
		}
		trustScore := CVSSScore(trustVector)
		t.CVSS = trustScore
		t.Severity = CVSSSeverity(trustScore)
		r.Trusts = append(r.Trusts, t)
	}

	// ── 2. Foreign Security Principals ───────────────────────
	// FSPs live in CN=ForeignSecurityPrincipals,<BaseDN>
	fspBase := "CN=ForeignSecurityPrincipals," + client.GetBaseDN()
	fspEntries, err := client.SearchBase(fspBase, "(objectClass=foreignSecurityPrincipal)", fspAttributes)
	if err == nil {
		// build set of privileged group DNs (lower-cased)
		privGroupDNs := buildPrivGroupDNSet(result)

		for _, e := range fspEntries {
			memberOf := e.GetAttributeValues("memberOf")
			var privGroups []string
			for _, dn := range memberOf {
				if name, ok := privGroupDNs[strings.ToLower(dn)]; ok {
					privGroups = append(privGroups, name)
				}
			}
			if len(privGroups) == 0 {
				continue
			}

			sid := e.GetAttributeValue("objectSid")
			if sid == "" {
				// name attribute holds the SID string for FSPs
				sid = e.GetAttributeValue("name")
			}

			sev := "High"
			for _, g := range privGroups {
				if g == "Domain Admins" || g == "Enterprise Admins" || g == "Administrators" {
					sev = "Critical"
					break
				}
			}

			var fspVector string
			if sev == "Critical" {
				// External principal in DA/EA: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
				fspVector = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
			} else {
				// External principal in other priv group: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
				fspVector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
			}
			fspScore := CVSSScore(fspVector)
			r.FSPs = append(r.FSPs, FSPFinding{
				FSPDN:          e.DN,
				ExternalSID:    sid,
				MemberOfGroups: privGroups,
				CVSS:           fspScore,
				Severity:       CVSSSeverity(fspScore),
			})
		}
	}

	printTrustResult(r, false)
	return r, nil
}

// buildPrivGroupDNSet returns map[lowerDN]→displayName for privileged groups
func buildPrivGroupDNSet(result *adldap.EnumerationResult) map[string]string {
	names := map[string]bool{
		"domain admins": true, "enterprise admins": true,
		"schema admins": true, "administrators": true,
		"backup operators": true, "account operators": true,
		"server operators": true, "print operators": true,
		"dnsadmins": true, "group policy creator owners": true,
	}
	out := make(map[string]string)
	for _, g := range result.Groups {
		if names[strings.ToLower(g.SAMAccountName)] {
			out[strings.ToLower(g.DN)] = g.SAMAccountName
		}
	}
	return out
}

// ============================================================
// Output
// ============================================================

func printTrustResult(r *TrustResult, showNextSteps bool) {
	color.Cyan("\n  TRUSTS")

	if len(r.Trusts) == 0 {
		color.White("  %-32s none found", "domain trusts")
	} else {
		color.White("  %-32s %d", "domain trusts", len(r.Trusts))
		color.White("  %-24s %-16s %-14s %-12s %s",
			"trusted domain", "direction", "type", "SID filter", "severity")
		color.White("  " + strings.Repeat("-", 76))

		for _, t := range r.Trusts {
			sidFilter := "ON  ✓"
			if t.IsWithinForest {
				sidFilter = "Internal"
			} else if !t.SIDFilteringOn {
				sidFilter = "OFF ⚠"
			}
			line := fmt.Sprintf("  %-24s %-16s %-14s %-12s %s",
				t.Name, t.Direction.String(), t.TrustType.String(), sidFilter, t.Severity)
			switch t.Severity {
			case "Critical":
				color.Red(line)
			case "High":
				color.Yellow(line)
			case "Medium":
				color.Yellow(line)
			default:
				color.White(line)
			}
			for _, risk := range t.Risks {
				color.Yellow("    ⚠ %s", risk)
			}
		}
	}

	if len(r.FSPs) > 0 {
		color.Red("\n  FOREIGN SECURITY PRINCIPALS IN PRIVILEGED GROUPS")
		color.Red("  %-48s %-12s %s", "FSP SID", "severity", "groups")
		color.Red("  " + strings.Repeat("-", 76))
		for _, f := range r.FSPs {
			line := fmt.Sprintf("  %-48s %-12s %s",
				f.ExternalSID, f.Severity, strings.Join(f.MemberOfGroups, ", "))
			if f.Severity == "Critical" {
				color.Red(line)
			} else {
				color.Yellow(line)
			}
		}
	}

	// next steps for risky trusts
	hasRisky := false
	for _, t := range r.Trusts {
		if t.Severity == "Critical" || t.Severity == "High" {
			hasRisky = true
			break
		}
	}
	if showNextSteps && (hasRisky || len(r.FSPs) > 0) {
		color.Cyan("\n  NEXT STEPS (Trust abuse)")
		for _, t := range r.Trusts {
			if !t.SIDFilteringOn && !t.IsWithinForest {
				color.White("  SID history abuse (SID filtering OFF on %s):", t.Name)
				color.White("    # Forge inter-realm TGT with DA SID of %s in PAC:", r.Domain)
				color.White("    ticketer.py -nthash <trust_key> -domain %s -domain-sid <SID> \\", t.Name)
				color.White("      -extra-sid <DA_SID_of_%s> -spn krbtgt/%s administrator", r.Domain, r.Domain)
			}
		}
		if len(r.FSPs) > 0 {
			color.White("  Foreign principal in privileged group — use that account's creds directly")
			color.White("  Enumerate from trusted domain: adpath enum -d %s ...", "<trusted_domain>")
		}
	}
}

// PrintTrustResult — public wrapper for standalone trust command (shows next steps)
func PrintTrustResult(r *TrustResult) {
	printTrustResult(r, true)
}
