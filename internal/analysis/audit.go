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

// AuditFinding is a single blue-team / audit visibility finding.
type AuditFinding struct {
	Title    string
	Detail   string
	Severity string
}

// AuditResult contains all audit-related findings.
type AuditResult struct {
	Domain string

	// AD Recycle Bin
	RecycleBinEnabled   bool
	RecycleBinSupported bool // forest FFL >= 4 (2008 R2)

	// Legacy Audit Policy (auditingPolicy attribute on domain object)
	AuditingEnabled bool   // at least one category enabled
	AuditCategories []AuditCategory

	// Machine account quota (ms-DS-MachineAccountQuota on domain)
	MachineAccountQuota int // 0 = safe, default 10 = risky

	Findings []AuditFinding
}

// AuditCategory represents one legacy audit policy category.
type AuditCategory struct {
	Name    string
	Success bool
	Failure bool
}

// ============================================================
// LDAP attributes
// ============================================================

var domainAuditAttributes = []string{
	"auditingPolicy",
	"ms-DS-MachineAccountQuota",
	"msDS-Behavior-Version",
}

// auditCategoryNames maps byte offset (1-based) in auditingPolicy to category name.
// Windows legacy audit policy: 9 bytes, byte 0 = AuditingMode, bytes 1-8 = categories.
var auditCategoryNames = []string{
	"System Events",
	"Logon/Logoff",
	"Object Access",
	"Privilege Use",
	"Detailed Tracking",
	"Policy Change",
	"Account Management",
	"Directory Service Access",
	"Account Logon",
}

// criticalCategories are the categories that must be enabled for basic AD visibility.
var criticalCategories = map[string]bool{
	"Account Logon":            true,
	"Account Management":       true,
	"Logon/Logoff":             true,
	"Directory Service Access": true,
}

// recycleBinFeatureCN is the CN of the optional feature for AD Recycle Bin.
const recycleBinFeatureCN = "CN=Recycle Bin Feature"

// ============================================================
// Analysis
// ============================================================

// AnalyzeAuditPolicy checks AD Recycle Bin, legacy audit policy,
// and machine account quota using already-established LDAP connection.
func AnalyzeAuditPolicy(client *adldap.Client, rds *adldap.RootDSEInfo) *AuditResult {
	if rds == nil {
		return nil
	}

	r := &AuditResult{
		Domain:              client.GetDomain(),
		MachineAccountQuota: 10, // default (risky)
	}

	configDN := rds.ConfigurationDN

	// ── AD Recycle Bin ────────────────────────────────────────
	r.RecycleBinSupported = isRecycleBinSupported(rds.ForestFunctionality)
	if r.RecycleBinSupported && configDN != "" {
		r.RecycleBinEnabled = probeRecycleBin(client, configDN)
	}

	// ── Domain object: auditingPolicy + MAQ ───────────────────
	entries, err := client.SearchBase(
		rds.DefaultNamingContext,
		"(objectClass=domain)",
		domainAuditAttributes,
	)
	if err == nil && len(entries) > 0 {
		e := entries[0]

		raw := e.GetRawAttributeValue("auditingPolicy")
		r.AuditCategories = parseLegacyAuditPolicy(raw)
		for _, c := range r.AuditCategories {
			if c.Success || c.Failure {
				r.AuditingEnabled = true
				break
			}
		}

		maq := e.GetAttributeValue("ms-DS-MachineAccountQuota")
		if maq != "" {
			if v, err := strconv.Atoi(maq); err == nil {
				r.MachineAccountQuota = v
			}
		}
	}

	// ── Build findings ────────────────────────────────────────
	if r.RecycleBinSupported && !r.RecycleBinEnabled {
		r.Findings = append(r.Findings, AuditFinding{
			Title:    "AD Recycle Bin disabled",
			Detail:   "AD Recycle Bin is not enabled. Accidentally or maliciously deleted objects (users, computers, GPOs) cannot be restored without an authoritative restore. Enable via: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <domain>",
			Severity: "Medium",
		})
	}

	if !r.AuditingEnabled {
		r.Findings = append(r.Findings, AuditFinding{
			Title:    "Legacy audit policy not configured",
			Detail:   "The domain auditingPolicy attribute is empty — no basic audit categories are enabled. Attacker activity (pass-the-hash, lateral movement, privilege escalation) will not generate Event Log entries. Configure via Default Domain Policy → Computer Configuration → Windows Settings → Security Settings → Local Policies → Audit Policy.",
			Severity: "High",
		})
	} else {
		// Check if critical categories are missing
		missing := []string{}
		for _, c := range r.AuditCategories {
			if criticalCategories[c.Name] && !c.Success && !c.Failure {
				missing = append(missing, c.Name)
			}
		}
		if len(missing) > 0 {
			r.Findings = append(r.Findings, AuditFinding{
				Title:    "Critical audit categories not enabled",
				Detail:   fmt.Sprintf("The following audit categories are disabled, reducing visibility into attacker actions: %s. Enable at minimum 'Success' auditing for Account Logon, Account Management, Logon/Logoff, and Directory Service Access.", strings.Join(missing, ", ")),
				Severity: "Medium",
			})
		}
	}

	if r.MachineAccountQuota > 0 {
		r.Findings = append(r.Findings, AuditFinding{
			Title:    fmt.Sprintf("Machine account quota = %d (any user can add computers)", r.MachineAccountQuota),
			Detail:   fmt.Sprintf("ms-DS-MachineAccountQuota is %d. Any authenticated domain user can add up to %d computer accounts to the domain. This is a common RBCD/resource-based constrained delegation abuse vector. Set to 0 via: Set-ADDomain -Identity <domain> -Replace @{\"ms-DS-MachineAccountQuota\"=\"0\"}", r.MachineAccountQuota, r.MachineAccountQuota),
			Severity: "Medium",
		})
	}

	return r
}

// probeRecycleBin checks if AD Recycle Bin Optional Feature is enabled
// by looking at msDS-EnabledFeature on the Partitions object.
func probeRecycleBin(client *adldap.Client, configDN string) bool {
	partitionsDN := "CN=Partitions," + configDN
	entries, err := client.SearchBase(
		partitionsDN,
		"(objectClass=crossRefContainer)",
		[]string{"msDS-EnabledFeature"},
	)
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, val := range entries[0].GetAttributeValues("msDS-EnabledFeature") {
		if strings.Contains(strings.ToUpper(val), strings.ToUpper(recycleBinFeatureCN)) {
			return true
		}
	}
	return false
}

// isRecycleBinSupported returns true if forest functional level >= 4 (2008 R2).
func isRecycleBinSupported(forestFunctionality string) bool {
	v, err := strconv.Atoi(forestFunctionality)
	if err != nil {
		return false
	}
	return v >= 4
}

// parseLegacyAuditPolicy decodes the 9-byte auditingPolicy blob.
// Byte 0 = AuditingMode (1 = auditing on), bytes 1-9 = category settings.
// Each category byte: bit 0 = Success, bit 1 = Failure.
func parseLegacyAuditPolicy(raw []byte) []AuditCategory {
	cats := make([]AuditCategory, len(auditCategoryNames))
	for i, name := range auditCategoryNames {
		cats[i] = AuditCategory{Name: name}
		byteIdx := i + 1 // skip AuditingMode byte
		if len(raw) > byteIdx {
			b := raw[byteIdx]
			cats[i].Success = b&0x01 != 0
			cats[i].Failure = b&0x02 != 0
		}
	}
	return cats
}

// ============================================================
// Output
// ============================================================

// PrintAuditResult prints the audit policy analysis to the terminal.
func PrintAuditResult(r *AuditResult) {
	if r == nil {
		return
	}

	color.Cyan("\n  AUDIT POLICY / BLUE TEAM")

	// Recycle Bin
	if !r.RecycleBinSupported {
		color.White("  %-28s %s", "AD Recycle Bin", "not supported (forest FFL < 2008 R2)")
	} else if r.RecycleBinEnabled {
		color.White("  %-28s %s", "AD Recycle Bin", "enabled ✓")
	} else {
		color.Yellow("  %-28s %s", "AD Recycle Bin", "DISABLED ⚠")
	}

	// Audit policy
	if !r.AuditingEnabled {
		color.Yellow("  %-28s %s", "legacy audit policy", "NOT configured ⚠")
	} else {
		color.White("  %-28s %s", "legacy audit policy", "configured")
		for _, c := range r.AuditCategories {
			if !c.Success && !c.Failure {
				continue
			}
			parts := []string{}
			if c.Success {
				parts = append(parts, "Success")
			}
			if c.Failure {
				parts = append(parts, "Failure")
			}
			color.White("    %-26s %s", c.Name, strings.Join(parts, "+"))
		}
	}

	// Machine account quota
	if r.MachineAccountQuota > 0 {
		color.Yellow("  %-28s %d ⚠", "machine account quota", r.MachineAccountQuota)
	} else {
		color.White("  %-28s %s", "machine account quota", "0 (safe) ✓")
	}

	// Findings summary
	if len(r.Findings) == 0 {
		return
	}
	color.White("")
	for _, f := range r.Findings {
		line := fmt.Sprintf("  [%s] %s", f.Severity, f.Title)
		switch f.Severity {
		case "High":
			color.Red(line)
		case "Medium":
			color.Yellow(line)
		default:
			color.White(line)
		}
	}
}

// AuditSummaryLine prints a one-line summary for the enum command.
func AuditSummaryLine(r *AuditResult) {
	if r == nil {
		return
	}
	if !r.AuditingEnabled {
		color.Red("  %-28s %s", "audit policy", "NOT configured — no event log visibility")
	} else if r.RecycleBinSupported && !r.RecycleBinEnabled {
		color.Yellow("  %-28s %s", "AD Recycle Bin", "disabled — deleted objects unrecoverable")
	}
	if r.MachineAccountQuota > 0 {
		color.Yellow("  %-28s %d — RBCD abuse vector", "machine acct quota", r.MachineAccountQuota)
	}
}
