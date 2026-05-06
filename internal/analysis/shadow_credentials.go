package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// msDS-KeyCredentialLink property write GUID
const guidKeyCredentialLink = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

// Privileged group SAMAccountNames whose members are high-value targets
var shadowCredTargetGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Domain Controllers",
	"Read-Only Domain Controllers",
}

// ShadowCredentialFinding — principal that can write msDS-KeyCredentialLink on a privileged object
type ShadowCredentialFinding struct {
	PrincipalName string
	PrincipalType string
	PrincipalDN   string
	TargetName    string
	TargetType    string
	TargetDN      string
	Right         string
	Severity      string
	CVSS       float64
	CVSSVector string
}

type ShadowCredentialsResult struct {
	Domain   string
	Findings []ShadowCredentialFinding
}

var sdOnlyAttrs = []string{"distinguishedName", "sAMAccountName", "objectClass", "nTSecurityDescriptor"}

// AnalyzeShadowCredentials checks which low-priv principals can write
// msDS-KeyCredentialLink on privileged accounts (DA, EA, DC computers).
// Writing this attribute allows obtaining a TGT without changing the password.
func AnalyzeShadowCredentials(client *adldap.Client, result *adldap.EnumerationResult) (*ShadowCredentialsResult, error) {
	r := &ShadowCredentialsResult{Domain: result.Domain}
	nameMap := buildNameMap(result)

	// Collect privileged target DNs: members of target groups + DC computers
	targets := collectPrivilegedTargets(result)
	if len(targets) == 0 {
		return r, nil
	}

	for targetDN, targetInfo := range targets {
		entries, err := client.SearchBase(targetDN, "(objectClass=*)", sdOnlyAttrs)
		if err != nil || len(entries) == 0 {
			continue
		}
		e := entries[0]
		sdBytes := e.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sdBytes) == 0 {
			continue
		}

		aces, err := parseSecurityDescriptor(sdBytes)
		if err != nil {
			continue
		}

		for _, ace := range aces {
			if ace.ACEType == 0x01 || ace.ACEType == 0x06 { // deny
				continue
			}

			right := shadowCredRight(ace)
			if right == "" {
				continue
			}

			// Skip the target writing to itself
			if strings.EqualFold(ace.SID, targetInfo.sid) {
				continue
			}

			info, ok := nameMap[ace.SID]
			if !ok {
				continue
			}

			// Skip well-known privileged groups that legitimately have these rights
			if isPrivilegedPrincipal(info.Name) {
				continue
			}

			const shadowVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
			shadowScore := CVSSScore(shadowVec)
			r.Findings = append(r.Findings, ShadowCredentialFinding{
				PrincipalName: info.Name,
				PrincipalType: info.Type,
				PrincipalDN:   info.DN,
				TargetName:    targetInfo.name,
				TargetType:    targetInfo.typ,
				TargetDN:      targetDN,
				Right:         right,
				CVSS:          shadowScore,
				CVSSVector:    shadowVec,
				Severity:      CVSSSeverity(shadowScore),
			})
		}
	}

	return r, nil
}

// shadowCredRight returns a human-readable right name if the ACE grants write
// access to msDS-KeyCredentialLink (directly or via broad write rights).
func shadowCredRight(ace ACE) string {
	mask := ace.AccessMask

	// GenericAll or WriteDACL/WriteOwner — full control implies attribute write
	if mask&ADS_RIGHT_GENERIC_ALL != 0 {
		return "GenericAll"
	}
	if mask&ADS_RIGHT_WRITE_DACL != 0 {
		return "WriteDACL"
	}
	if mask&ADS_RIGHT_WRITE_OWNER != 0 {
		return "WriteOwner"
	}
	if mask&ADS_RIGHT_GENERIC_WRITE != 0 {
		return "GenericWrite"
	}

	// WriteProperty on the specific attribute (Object ACE)
	if ace.ACEType == 0x05 && mask&ADS_RIGHT_DS_WRITE_PROP != 0 {
		if strings.EqualFold(ace.ObjectType, guidKeyCredentialLink) {
			return "WriteProperty(msDS-KeyCredentialLink)"
		}
	}

	// WriteProperty on ALL properties (no ObjectType restriction, type 0x00)
	if ace.ACEType == 0x00 && mask&ADS_RIGHT_DS_WRITE_PROP != 0 {
		return "WriteProperty(all)"
	}

	return ""
}

// targetEntry holds lightweight info about a privileged target
type targetEntry struct {
	name string
	typ  string
	sid  string
}

// collectPrivilegedTargets returns a map of DN → targetEntry for all members
// of privileged groups + DC computer accounts.
func collectPrivilegedTargets(result *adldap.EnumerationResult) map[string]targetEntry {
	targets := make(map[string]targetEntry)

	// Build SID → object lookup for quick membership resolution
	sidToUser := make(map[string]adldap.LDAPUser)
	sidToComputer := make(map[string]adldap.LDAPComputer)
	for _, u := range result.Users {
		sidToUser[u.ObjectSid] = u
	}
	for _, c := range result.Computers {
		sidToComputer[c.ObjectSid] = c
	}

	for _, g := range result.Groups {
		if !isTargetGroup(g.SAMAccountName) {
			continue
		}
		isDCGroup := strings.EqualFold(g.SAMAccountName, "Domain Controllers") ||
			strings.EqualFold(g.SAMAccountName, "Read-Only Domain Controllers")

		for _, memberDN := range g.Members {
			// Try to match member DN to user or computer
			ldn := strings.ToLower(memberDN)
			for _, u := range result.Users {
				if strings.ToLower(u.DN) == ldn {
					targets[u.DN] = targetEntry{name: u.SAMAccountName, typ: "user", sid: u.ObjectSid}
					break
				}
			}
			if isDCGroup {
				for _, c := range result.Computers {
					if strings.ToLower(c.DN) == ldn {
						targets[c.DN] = targetEntry{name: c.SAMAccountName, typ: "computer", sid: c.ObjectSid}
						break
					}
				}
			}
		}
	}

	// Also add DC computers via UnconstrainedDelegation flag (DCs always have it)
	for _, c := range result.Computers {
		if c.UnconstrainedDelegation {
			if _, exists := targets[c.DN]; !exists {
				targets[c.DN] = targetEntry{name: c.SAMAccountName, typ: "computer", sid: c.ObjectSid}
			}
		}
	}

	return targets
}

func isTargetGroup(name string) bool {
	for _, g := range shadowCredTargetGroups {
		if strings.EqualFold(name, g) {
			return true
		}
	}
	return false
}

// isPrivilegedPrincipal returns true for built-in accounts that legitimately
// have broad rights and should not be reported as Shadow Credential risks.
func isPrivilegedPrincipal(name string) bool {
	lower := strings.ToLower(name)
	for _, priv := range []string{
		"domain admins", "enterprise admins", "schema admins",
		"administrators", "system", "account operators",
		"domain controllers", "enterprise domain controllers",
	} {
		if lower == priv {
			return true
		}
	}
	return false
}

// ============================================================
// Terminal output
// ============================================================

func PrintShadowCredentialsResult(r *ShadowCredentialsResult) {
	color.Cyan("\n  SHADOW CREDENTIALS")
	if len(r.Findings) == 0 {
		color.White("  %-28s %s", "msDS-KeyCredentialLink", "no dangerous write ACEs found")
		return
	}

	color.Red("  %-28s %d  (TGT obtainable without password change)", "dangerous write ACEs", len(r.Findings))
	color.White("  %-24s %-10s %-30s %s", "principal", "type", "target", "right")
	color.White("  " + strings.Repeat("-", 78))

	for _, f := range r.Findings {
		line := fmt.Sprintf("  %-24s %-10s %-30s %s", f.PrincipalName, f.PrincipalType, f.TargetName, f.Right)
		color.Red(line)
	}

	color.Cyan("\n  NEXT STEPS")
	color.White("  Shadow Credentials — write a key credential to obtain TGT without changing password:")
	color.White("    # Add key credential to target")
	color.White("    pywhisker -d %s -u '<principal>' -p '<pass>' --target '<target>' --action add", r.Domain)
	color.White("    # OR use certipy")
	color.White("    certipy shadow auto -u '<principal>@%s' -p '<pass>' -account '<target>'", r.Domain)
}

// AnalyzeShadowCredentialsSummary — prints summary line only (used by enum command)
func AnalyzeShadowCredentialsSummary(r *ShadowCredentialsResult) {
	if r == nil || len(r.Findings) == 0 {
		return
	}
	color.Red("  %-28s %d  (Shadow Credentials — write msDS-KeyCredentialLink)", "shadow cred risks", len(r.Findings))
}
