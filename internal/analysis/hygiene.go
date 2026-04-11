package analysis

import (
	"strings"
	"time"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Models
// ============================================================

// HygieneResult contains AD hygiene / blue team findings
type HygieneResult struct {
	StaleUsers        []adldap.LDAPUser
	StaleComputers    []adldap.LDAPComputer
	PasswordInDesc    []PasswordInDescFinding
	KrbtgtPwdAgeDays  int
	KrbtgtLastSet     string
	KrbtgtAtRisk      bool // true if > 180 days
}

// PasswordInDescFinding is a user/computer with a potential password in description
type PasswordInDescFinding struct {
	SAMAccountName string
	ObjectType     string // "user" or "computer"
	Description    string
}

const (
	staleUserDays     = 90
	staleComputerDays = 45
	krbtgtMaxAgeDays  = 180
)

// passwordKeywords — simple heuristic for description scanning
var passwordKeywords = []string{
	"pass", "pwd", "password", "passwd", "secret", "cred",
	"motdepasse", "пароль", "p@ss",
}

// ============================================================
// Analysis
// ============================================================

// AnalyzeHygiene checks stale accounts, krbtgt age, and passwords in description
func AnalyzeHygiene(result *adldap.EnumerationResult) *HygieneResult {
	color.Blue("\n[*] Analyzing AD hygiene...")

	hr := &HygieneResult{}
	now := time.Now()

	// ── krbtgt + stale users ──────────────────────────────────
	for _, u := range result.Users {
		if strings.EqualFold(u.SAMAccountName, "krbtgt") {
			if u.PasswordLastSet != "" && u.PasswordLastSet != "Never" {
				t, err := time.Parse("2006-01-02 15:04:05", u.PasswordLastSet)
				if err == nil {
					hr.KrbtgtPwdAgeDays = int(now.Sub(t).Hours() / 24)
					hr.KrbtgtLastSet = u.PasswordLastSet
					hr.KrbtgtAtRisk = hr.KrbtgtPwdAgeDays > krbtgtMaxAgeDays
				}
			}
			continue
		}

		if !u.Enabled {
			continue
		}

		// stale: enabled account, no logon in 90+ days
		if isStale(u.LastLogon, now, staleUserDays) {
			hr.StaleUsers = append(hr.StaleUsers, u)
		}

		// password in description
		if hasSuspiciousPassword(u.Description) {
			hr.PasswordInDesc = append(hr.PasswordInDesc, PasswordInDescFinding{
				SAMAccountName: u.SAMAccountName,
				ObjectType:     "user",
				Description:    u.Description,
			})
		}
	}

	// ── stale computers ───────────────────────────────────────
	for _, c := range result.Computers {
		if !c.Enabled {
			continue
		}
		if isStale(c.LastLogon, now, staleComputerDays) {
			hr.StaleComputers = append(hr.StaleComputers, c)
		}
		if hasSuspiciousPassword(c.Description) {
			hr.PasswordInDesc = append(hr.PasswordInDesc, PasswordInDescFinding{
				SAMAccountName: c.SAMAccountName,
				ObjectType:     "computer",
				Description:    c.Description,
			})
		}
	}

	printHygieneResult(hr)
	return hr
}

// ============================================================
// Helpers
// ============================================================

func isStale(lastLogon string, now time.Time, thresholdDays int) bool {
	if lastLogon == "" || lastLogon == "Never" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", lastLogon)
	if err != nil {
		return false
	}
	return now.Sub(t) > time.Duration(thresholdDays)*24*time.Hour
}

func hasSuspiciousPassword(desc string) bool {
	if desc == "" {
		return false
	}
	lower := strings.ToLower(desc)
	for _, kw := range passwordKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func printHygieneResult(hr *HygieneResult) {
	// krbtgt
	if hr.KrbtgtPwdAgeDays > 0 {
		if hr.KrbtgtAtRisk {
			color.Red("[!] krbtgt password age: %d days (>%d) — Golden Ticket risk elevated", hr.KrbtgtPwdAgeDays, krbtgtMaxAgeDays)
		} else {
			color.Green("[+] krbtgt password age: %d days (OK)", hr.KrbtgtPwdAgeDays)
		}
	}

	// stale
	if len(hr.StaleUsers) > 0 {
		color.Yellow("[!] Stale user accounts (90+ days, enabled): %d", len(hr.StaleUsers))
	} else {
		color.Green("[+] No stale user accounts")
	}
	if len(hr.StaleComputers) > 0 {
		color.Yellow("[!] Stale computers (45+ days, enabled): %d", len(hr.StaleComputers))
	} else {
		color.Green("[+] No stale computers")
	}

	// passwords in description
	if len(hr.PasswordInDesc) > 0 {
		color.Red("[!] Potential passwords in description attribute: %d", len(hr.PasswordInDesc))
		for _, f := range hr.PasswordInDesc {
			color.Yellow("    [%s] %s: %q", f.ObjectType, f.SAMAccountName, f.Description)
		}
	} else {
		color.Green("[+] No passwords found in description attributes")
	}
}
