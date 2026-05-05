package report

import "fmt"

// TopIssue is a summary finding for the Executive tab.
type TopIssue struct {
	Title       string
	Description string
	Tab         string
	Anchor      string // optional anchor to scroll to after tab switch
	Severity    string
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// BuildTopIssues returns up to 5 highest-priority issues for management consumption.
func BuildTopIssues(d *ReportData) []TopIssue {
	var issues []TopIssue

	// Attack paths to Domain Admins — always #1 if present
	daPaths := 0
	for _, p := range d.AttackPaths {
		if p.TargetGroup == "Domain Admins" {
			daPaths++
		}
	}
	if daPaths > 0 {
		issues = append(issues, TopIssue{
			Title:       fmt.Sprintf("%d attack %s to Domain Admins", daPaths, plural(daPaths, "path", "paths")),
			Description: "Low-privilege accounts can escalate to full domain compromise. Eliminate transitive group memberships and ACL abuse vectors.",
			Tab:         "paths",
			Severity:    "Critical",
		})
	}

	// Critical ACL findings
	critACLs := 0
	if d.ACLResult != nil {
		for _, f := range d.ACLResult.Findings {
			if f.Severity == "Critical" {
				critACLs++
			}
		}
	}
	if critACLs > 0 {
		issues = append(issues, TopIssue{
			Title:       fmt.Sprintf("%d critical ACL %s", critACLs, plural(critACLs, "misconfiguration", "misconfigurations")),
			Description: "Non-admin principals hold WriteDACL, WriteOwner, or GenericAll on privileged groups. These permit privilege escalation without exploiting any vulnerability.",
			Tab:         "acl",
			Severity:    "Critical",
		})
	}

	// Kerberoastable accounts
	if d.KerberosResult != nil && len(d.KerberosResult.KerberoastableAccounts) > 0 {
		n := len(d.KerberosResult.KerberoastableAccounts)
		issues = append(issues, TopIssue{
			Title:       fmt.Sprintf("%d Kerberoastable %s", n, plural(n, "account", "accounts")),
			Description: "Service accounts with SPNs allow offline password cracking. Use managed service accounts (gMSA) or strong random passwords (25+ chars).",
			Tab:         "kerberos",
			Severity:    "High",
		})
	}

	// Vulnerable ADCS templates
	if d.ADCSResult != nil && len(d.ADCSResult.TemplateFindings) > 0 {
		n := len(d.ADCSResult.TemplateFindings)
		issues = append(issues, TopIssue{
			Title:       fmt.Sprintf("%d vulnerable certificate %s", n, plural(n, "template", "templates")),
			Description: "ESC misconfiguration enables persistent domain compromise via certificate-based authentication. Patch templates per Microsoft KB5014754.",
			Tab:         "adcs",
			Severity:    "Critical",
		})
	}

	// Weak password policy
	if d.Summary.WeakPasswordPolicy {
		issues = append(issues, TopIssue{
			Title:       "Weak domain password policy",
			Description: "Minimum length, complexity, or expiry policy fails CIS benchmarks. Update to 14+ chars, complexity enabled, max age 365 days.",
			Tab:         "summary",
			Anchor:      "policy-section",
			Severity:    "Critical",
		})
	}

	if len(issues) > 5 {
		issues = issues[:5]
	}
	return issues
}
