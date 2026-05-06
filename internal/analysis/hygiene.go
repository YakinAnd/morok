package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
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
	NoLAPSCount       int                  // enabled computers without LAPS
	TotalComputers    int                  // total enabled computers
	NoLAPSComputers   []adldap.LDAPComputer // enabled computers without LAPS
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

	// ── stale computers + LAPS ────────────────────────────────
	for _, c := range result.Computers {
		if !c.Enabled {
			continue
		}
		hr.TotalComputers++
		if !c.LAPSEnabled {
			hr.NoLAPSCount++
			hr.NoLAPSComputers = append(hr.NoLAPSComputers, c)
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

	if !Quiet {
		printHygieneResult(hr)
	}
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
	color.Cyan("\n  EXPOSURE")

	krbtgtAge := "N/A"
	if hr.KrbtgtPwdAgeDays > 0 {
		krbtgtAge = fmt.Sprintf("%d days", hr.KrbtgtPwdAgeDays)
	}
	if hr.KrbtgtAtRisk {
		color.Red("  %-28s %s  (>%dd — Golden Ticket risk)", "krbtgt pwd age", krbtgtAge, krbtgtMaxAgeDays)
	} else {
		color.White("  %-28s %s", "krbtgt pwd age", krbtgtAge)
	}

	if len(hr.StaleUsers) > 0 {
		color.Yellow("  %-28s %d", "stale users (90d+)", len(hr.StaleUsers))
	} else {
		color.White("  %-28s %d", "stale users (90d+)", 0)
	}
	if len(hr.StaleComputers) > 0 {
		color.Yellow("  %-28s %d", "stale computers (45d+)", len(hr.StaleComputers))
	} else {
		color.White("  %-28s %d", "stale computers (45d+)", 0)
	}
	color.White("  %-28s %d", "objects with description", len(hr.PasswordInDesc))
	if hr.TotalComputers > 0 {
		lapsVal := fmt.Sprintf("%d / %d computers", hr.NoLAPSCount, hr.TotalComputers)
		if hr.NoLAPSCount > 0 {
			color.Yellow("  %-28s %s", "no LAPS", lapsVal)
		} else {
			color.White("  %-28s %s", "no LAPS", lapsVal)
		}
	}
}
