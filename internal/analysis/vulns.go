package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// VulnStatus indicates how confident we are in a finding.
type VulnStatus int

const (
	VulnCandidate   VulnStatus = iota // phase 1: OS build suggests vulnerability
	VulnConfirmed                     // phase 2: active probe confirmed
	VulnSafe                          // phase 2: probe ruled it out (don't show)
	VulnUnreachable                   // phase 2: probe attempted but host unreachable
)

// VulnFinding represents a single CVE finding on a host.
type VulnFinding struct {
	Host        string
	FQDN        string
	CVE         string
	Name        string
	Status      VulnStatus
	Detail      string
	Remediation string
	ProbeError  string // non-empty when Status==VulnUnreachable
}

// VulnResult holds all vulnerability findings.
type VulnResult struct {
	Findings []VulnFinding
}

// ============================================================
// OS build thresholds
// ============================================================

// parseBuild extracts the build number from operatingSystemVersion strings like
// "10.0 (17763)" or "6.1 (7601)". Returns 0 if unparseable.
func parseBuild(ver string) int {
	// Format: "major.minor (build)"
	start := strings.Index(ver, "(")
	end := strings.Index(ver, ")")
	if start < 0 || end <= start {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(ver[start+1 : end]))
	if err != nil {
		return 0
	}
	return n
}

// osFamily maps an OperatingSystem string to a short key for threshold lookups.
func osFamily(os string) string {
	os = strings.ToLower(os)
	switch {
	case strings.Contains(os, "xp") || strings.Contains(os, "2003"):
		return "xp"
	case strings.Contains(os, "vista") || strings.Contains(os, "2008") && !strings.Contains(os, "r2"):
		return "2008"
	case strings.Contains(os, "7") || strings.Contains(os, "2008 r2"):
		return "2008r2"
	case strings.Contains(os, "8") && !strings.Contains(os, "8.1") || strings.Contains(os, "2012") && !strings.Contains(os, "r2"):
		return "2012"
	case strings.Contains(os, "8.1") || strings.Contains(os, "2012 r2"):
		return "2012r2"
	case strings.Contains(os, "10") || strings.Contains(os, "2016"):
		return "2016"
	case strings.Contains(os, "2019"):
		return "2019"
	case strings.Contains(os, "11") || strings.Contains(os, "2022"):
		return "2022"
	default:
		return ""
	}
}

// eternalBluePatched returns true if the host's OS build is >= the patched threshold.
// MS17-010 patch: March 2017 (KB4012212 etc.)
// XP/2003: never officially patched via Windows Update (EOL), but MS released emergency KB.
// We treat XP/2003 as always candidate — too old to trust.
func eternalBluePatched(os string, build int) bool {
	switch osFamily(os) {
	case "xp", "2003", "2008", "2008r2", "2012", "2012r2":
		// EOL or too old to distinguish patch level via LDAP build alone — flag all as candidates.
		return false
	case "2016", "2019", "2022":
		return true // not affected / always patched
	default:
		return true // unknown → don't flag
	}
}

// Zerologon (CVE-2020-1472): August 2020 CU.
// Patched build thresholds per OS.
var zerologonPatchedBuilds = map[string]int{
	"2008r2": 7601,  // coarse; realistically 7601.24557+ (Aug 2020 CU)
	"2012":   9200,  // KB4571694 onwards
	"2012r2": 9600,  // KB4571697 onwards
	"2016":   14393, // build 14393.3930+ (KB4571694); flag if < 3930 revision
	"2019":   17763, // build 17763.1457+ (KB4565349); flag if < 1457 revision
	"2022":   20348, // patched from day 1
}

// zerologonRevisionThresholds maps OS family to the minimum SAFE build revision.
// Windows encodes version as "10.0 (14393)" — the revision is in a separate attribute
// (operatingSystemVersion only gives the base build). We can only do coarse checks.
// For 2016/2019 we check the base build; if it's the same major we assume patched
// (revision-level checking requires WMI/RPC, not LDAP).
func zerologonPatched(os string, build int) bool {
	family := osFamily(os)
	switch family {
	case "xp", "2003", "2008":
		// Very old — EOL or borderline; treat all as candidates
		return false
	case "2008r2":
		// Requires Aug 2020 CU. Build 7601 is SP1 base — we can't distinguish
		// revision-level from LDAP alone. Flag all 2008R2 as candidates.
		return false
	case "2012", "2012r2":
		return false // flag all; revision check not possible via LDAP
	case "2016", "2019", "2022":
		// Modern OS — almost certainly patched. Don't flag.
		return true
	default:
		return true
	}
}

// noPac (CVE-2021-42278/42287): November 2021 CU.
// Requires MAQ > 0 AND DC is unpatched.
// Same logic: flag all Server 2008–2019 DCs as candidates (can't check revision via LDAP).
func noPacPatched(os string) bool {
	family := osFamily(os)
	switch family {
	case "xp", "2003", "2008", "2008r2", "2012", "2012r2", "2016", "2019":
		return false // flag as candidate
	case "2022":
		return true // Server 2022 patched from GA
	default:
		return true
	}
}

// PrintNightmare (CVE-2021-1675/34527): July 2021 CU.
// Affects all Windows versions with Print Spooler running.
// We flag XP through 2019 as candidates; 2022 patched from GA.
func printNightmarePatched(os string) bool {
	family := osFamily(os)
	switch family {
	case "2022":
		return true
	case "":
		return true
	default:
		return false // flag all older as candidates
	}
}

// ============================================================
// Phase 1: build-based candidate detection
// ============================================================

// RunVulnChecks runs vulnerability checks against all enumerated computers.
// phase1 always runs; phase2 (active probes) runs only when probe=true.
func RunVulnChecks(computers []adldap.LDAPComputer, maq int, ldapSigning *LDAPSecurityResult, probe bool) *VulnResult {
	r := &VulnResult{}

	for _, c := range computers {
		if !c.Enabled {
			continue
		}
		host := c.DNSHostName
		if host == "" {
			host = c.SAMAccountName
		}
		build := parseBuild(c.OperatingSystemVersion)
		os := c.OperatingSystem

		// ── EternalBlue (MS17-010) — all hosts ──────────────────────────────
		// Phase 1: OS build suggests vulnerability.
		// Phase 2 (probe=true): Trans2 SESSION_SETUP probe confirms via STATUS_INSUFF_SERVER_RESOURCES.
		if !eternalBluePatched(os, build) {
			detail := fmt.Sprintf("%s, build %d", os, build)
			if build == 0 {
				detail = os
			}
			f := VulnFinding{
				Host:        c.SAMAccountName,
				FQDN:        host,
				CVE:         "MS17-010",
				Name:        "EternalBlue",
				Status:      VulnCandidate,
				Detail:      detail,
				Remediation: "Apply KB4012212 (2008R2) / KB4012215 (2012) / KB4012216 (2012R2) / KB4013429 (2016). Disable SMBv1.",
			}
			if probe {
				vulnerable, reachable := eternalBlueProbe(host)
				switch {
				case vulnerable:
					f.Status = VulnConfirmed
				case reachable:
					f.Status = VulnSafe
				default:
					f.Status = VulnUnreachable
					f.ProbeError = "port 445 unreachable — build-based detection only"
				}
			}
			if f.Status != VulnSafe {
				r.Findings = append(r.Findings, f)
			}
		}

		// ── PrintNightmare (CVE-2021-1675) — all hosts ──────────────────────
		if !printNightmarePatched(os) {
			detail := fmt.Sprintf("%s, build %d", os, build)
			if build == 0 {
				detail = os
			}
			f := VulnFinding{
				Host:        c.SAMAccountName,
				FQDN:        host,
				CVE:         "CVE-2021-34527",
				Name:        "PrintNightmare",
				Status:      VulnCandidate,
				Detail:      detail,
				Remediation: "Apply July 2021 CU. Disable Print Spooler on DCs: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled.",
			}
			if probe {
				spoolerRunning, reachable := printNightmareProbe(host)
				switch {
				case spoolerRunning:
					f.Status = VulnConfirmed
				case reachable:
					f.Status = VulnSafe
				default:
					f.Status = VulnUnreachable
					f.ProbeError = "port 445 unreachable — build-based detection only"
				}
			}
			if f.Status != VulnSafe {
				r.Findings = append(r.Findings, f)
			}
		}

		if !c.IsDC {
			continue
		}

		// ── DC-only checks below ─────────────────────────────────────────────

		// ── Zerologon (CVE-2020-1472) ────────────────────────────────────────
		if !zerologonPatched(os, build) {
			f := VulnFinding{
				Host:        c.SAMAccountName,
				FQDN:        host,
				CVE:         "CVE-2020-1472",
				Name:        "Zerologon",
				Status:      VulnCandidate,
				Detail:      fmt.Sprintf("DC running %s (build %d) — pre-August 2020 CU not ruled out via LDAP", os, build),
				Remediation: "Apply August 2020 CU (KB4565349/KB4571694). Enable enforcement mode: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\FullSecureChannelProtection=1.",
			}
			if probe {
				vulnerable, reachable := zerologonProbe(host, c.SAMAccountName)
				switch {
				case vulnerable:
					f.Status = VulnConfirmed
				case reachable:
					f.Status = VulnSafe
				default:
					f.Status = VulnUnreachable
					f.ProbeError = "port 445 unreachable — build-based detection only"
				}
			}
			if f.Status != VulnSafe {
				r.Findings = append(r.Findings, f)
			}
		}

		// ── noPac (CVE-2021-42278/42287) ─────────────────────────────────────
		if maq > 0 && !noPacPatched(os) {
			r.Findings = append(r.Findings, VulnFinding{
				Host:        c.SAMAccountName,
				FQDN:        host,
				CVE:         "CVE-2021-42287",
				Name:        "noPac",
				Status:      VulnCandidate,
				Detail:      fmt.Sprintf("MAQ=%d, DC running %s — November 2021 CU not confirmed via LDAP", maq, os),
				Remediation: "Apply November 2021 CU (KB5008102). Set ms-DS-MachineAccountQuota=0.",
			})
		}

		// ── PetitPotam (CVE-2021-36942) ──────────────────────────────────────
		if ldapSigning != nil && ldapSigning.SigningChecked && !ldapSigning.SigningEnforced {
			r.Findings = append(r.Findings, VulnFinding{
				Host:        c.SAMAccountName,
				FQDN:        host,
				CVE:         "CVE-2021-36942",
				Name:        "PetitPotam",
				Status:      VulnCandidate,
				Detail:      "LDAP signing not enforced — EFS RPC can coerce DC authentication for NTLM relay",
				Remediation: "Apply KB5005413. Enforce LDAP signing and channel binding. Block MS-EFSRPC via firewall.",
			})
		}
	}

	return r
}


// ============================================================
// Output
// ============================================================

// PrintVulnResult prints the [VULNS] section to the terminal.
func PrintVulnResult(r *VulnResult) {
	if r == nil || len(r.Findings) == 0 {
		return
	}

	grey := color.New(color.FgHiBlack)
	color.White("\n[VULNS]")
	for _, f := range r.Findings {
		switch f.Status {
		case VulnConfirmed:
			color.Red("  [!] %-32s CONFIRMED: %s (%s)", f.FQDN, f.Name, f.CVE)
		case VulnCandidate:
			color.Yellow("  [?] %-32s candidate: %s (%s) — %s", f.FQDN, f.Name, f.CVE, f.Detail)
		case VulnUnreachable:
			grey.Printf("  [~] %-32s unverified: %s (%s) — %s\n", f.FQDN, f.Name, f.CVE, f.ProbeError)
		}
	}
}

// VulnSummaryLine prints a compact summary line for the findings footer.
func VulnSummaryLine(r *VulnResult) {
	if r == nil || len(r.Findings) == 0 {
		return
	}
	var confirmed, candidates, unreachable int
	for _, f := range r.Findings {
		switch f.Status {
		case VulnConfirmed:
			confirmed++
		case VulnCandidate:
			candidates++
		case VulnUnreachable:
			unreachable++
		}
	}
	switch {
	case confirmed > 0:
		color.Red("  %-28s %d confirmed, %d candidate, %d unverified", "vuln exposure", confirmed, candidates, unreachable)
	case unreachable > 0:
		color.Yellow("  %-28s %d candidate, %d unverified (--vuln-check could not reach all hosts)", "vuln exposure", candidates, unreachable)
	default:
		color.Yellow("  %-28s %d candidate (run --vuln-check to confirm)", "vuln exposure", candidates)
	}
}
