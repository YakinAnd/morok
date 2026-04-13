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

// ProtectedUsersResult contains findings about the Protected Users group
type ProtectedUsersResult struct {
	ProtectedUsersExists bool
	Members              []string // SAMAccountNames in Protected Users
	PrivilegedNotProtected []PrivNotProtectedFinding
}

// PrivNotProtectedFinding — a privileged account not in Protected Users
type PrivNotProtectedFinding struct {
	SAMAccountName string
	Groups         []string // privileged groups the account belongs to
	Severity       string
}

// privileged groups whose members should be in Protected Users
var privilegedGroupNames = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
}

// ============================================================
// Analysis
// ============================================================

// AnalyzeProtectedUsers checks which privileged accounts are NOT in Protected Users.
// Protected Users group prevents NTLM auth, RC4, unconstrained delegation, etc.
// DA/EA members outside this group are higher-risk credentials.
func AnalyzeProtectedUsers(result *adldap.EnumerationResult) *ProtectedUsersResult {
	r := &ProtectedUsersResult{}

	// find Protected Users group
	var protectedUsersDN string
	var protectedMemberDNs []string

	for _, g := range result.Groups {
		if strings.EqualFold(g.SAMAccountName, "Protected Users") {
			r.ProtectedUsersExists = true
			protectedUsersDN = g.DN
			_ = protectedUsersDN
			for _, m := range g.Members {
				protectedMemberDNs = append(protectedMemberDNs, strings.ToLower(m))
			}
			break
		}
	}

	// build set of protected members
	protectedSet := make(map[string]bool, len(protectedMemberDNs))
	for _, dn := range protectedMemberDNs {
		protectedSet[dn] = true
		// also index by SAMAccountName if we can find it
	}

	// collect SAMAccountNames of protected members for display
	for _, u := range result.Users {
		if protectedSet[strings.ToLower(u.DN)] {
			r.Members = append(r.Members, u.SAMAccountName)
		}
	}

	// find privileged groups DNs
	privGroupDNs := make(map[string]string) // lower(DN) → display name
	for _, g := range result.Groups {
		for _, pname := range privilegedGroupNames {
			if strings.EqualFold(g.SAMAccountName, pname) {
				privGroupDNs[strings.ToLower(g.DN)] = g.SAMAccountName
				break
			}
		}
	}

	// check each user: if member of a privileged group and NOT in Protected Users → finding
	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		if strings.EqualFold(u.SAMAccountName, "krbtgt") {
			continue
		}

		var memberOfPriv []string
		for _, memberDN := range u.MemberOf {
			if name, ok := privGroupDNs[strings.ToLower(memberDN)]; ok {
				memberOfPriv = append(memberOfPriv, name)
			}
		}
		if len(memberOfPriv) == 0 {
			continue
		}

		// privileged user — check if in Protected Users
		if protectedSet[strings.ToLower(u.DN)] {
			continue // already protected
		}

		sev := "High"
		for _, g := range memberOfPriv {
			if g == "Domain Admins" || g == "Enterprise Admins" {
				sev = "Critical"
				break
			}
		}

		r.PrivilegedNotProtected = append(r.PrivilegedNotProtected, PrivNotProtectedFinding{
			SAMAccountName: u.SAMAccountName,
			Groups:         memberOfPriv,
			Severity:       sev,
		})
	}

	printProtectedUsersResult(r)
	return r
}

// ============================================================
// Output
// ============================================================

func printProtectedUsersResult(r *ProtectedUsersResult) {
	color.Cyan("\n  PROTECTED USERS")

	if !r.ProtectedUsersExists {
		color.Yellow("  %-32s not found  (group may not exist in older domains)", "Protected Users group")
		return
	}

	color.White("  %-32s %d", "members", len(r.Members))

	if len(r.PrivilegedNotProtected) == 0 {
		color.Green("  %-32s all privileged accounts are protected", "status")
		return
	}

	color.Red("  %-32s %d  (NTLM/RC4 auth possible, delegation not blocked)",
		"privileged not in group", len(r.PrivilegedNotProtected))

	for _, f := range r.PrivilegedNotProtected {
		line := fmt.Sprintf("    %-24s [%s]  %s", f.SAMAccountName, f.Severity, strings.Join(f.Groups, ", "))
		if f.Severity == "Critical" {
			color.Red(line)
		} else {
			color.Yellow(line)
		}
	}

	color.Cyan("\n  NEXT STEPS (Protected Users)")
	color.White("  Add privileged accounts to Protected Users to block NTLM, RC4, and delegation:")
	color.White("  Add-ADGroupMember -Identity 'Protected Users' -Members '<samAccountName>'")
}
