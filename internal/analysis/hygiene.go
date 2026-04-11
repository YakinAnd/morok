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

// DescriptionFinding is any AD object that has a non-empty description field.
// All descriptions are collected — the analyst decides what is interesting.
type DescriptionFinding struct {
	SAMAccountName string
	ObjectType     string // "user", "computer", or "group"
	Description    string
}

// PasswordInDescFinding is an alias kept for backward compat with html template.
type PasswordInDescFinding = DescriptionFinding

const (
	staleUserDays     = 90
	staleComputerDays = 45
	krbtgtMaxAgeDays  = 180
)


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

		if u.Description != "" {
			hr.PasswordInDesc = append(hr.PasswordInDesc, DescriptionFinding{
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
		if c.Description != "" {
			hr.PasswordInDesc = append(hr.PasswordInDesc, DescriptionFinding{
				SAMAccountName: c.SAMAccountName,
				ObjectType:     "computer",
				Description:    c.Description,
			})
		}
	}

	// ── groups with description ───────────────────────────────
	for _, g := range result.Groups {
		if g.Description != "" {
			hr.PasswordInDesc = append(hr.PasswordInDesc, DescriptionFinding{
				SAMAccountName: g.SAMAccountName,
				ObjectType:     "group",
				Description:    g.Description,
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

	// descriptions
	if len(hr.PasswordInDesc) > 0 {
		color.Yellow("[*] Objects with description attribute: %d — review in HTML report", len(hr.PasswordInDesc))
	} else {
		color.Green("[+] No description attributes found")
	}
}
