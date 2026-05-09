package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Data models
// ============================================================

// KerberoastableAccount — user with an SPN that can be Kerberoasted
type KerberoastableAccount struct {
	SAMAccountName  string
	DN              string
	SPNs            []string
	AdminCount      bool
	PasswordLastSet string
	LastLogon       string
	Description     string
	CVSS            float64
	CVSSVector      string
	Severity        string
	IsMSA           bool   // gMSA/MSA — 240-char random password, cracking is infeasible
	SourceDomain    string // set for accounts from trusted domains
}

// ASREPAccount — account with DONT_REQUIRE_PREAUTH set
type ASREPAccount struct {
	SAMAccountName  string
	DN              string
	AdminCount      bool
	PasswordLastSet string
	LastLogon       string
	Description     string
	CVSS            float64
	CVSSVector      string
	Severity        string
	SourceDomain    string // set for accounts from trusted domains
}

// KerberosResult — Kerberos analysis result
type KerberosResult struct {
	Domain              string
	KerberoastableAccounts []KerberoastableAccount
	ASREPAccounts          []ASREPAccount
	AnalyzedAt          time.Time
}

// ============================================================
// Core functions
// ============================================================

// AnalyzeKerberos collects all Kerberoastable and AS-REP roastable accounts
func AnalyzeKerberos(result *adldap.EnumerationResult) *KerberosResult {
	kr := &KerberosResult{
		Domain:     result.Domain,
		AnalyzedAt: time.Now(),
	}


	// ── Kerberoastable ────────────────────────────────────────
	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		if len(u.SPNs) == 0 {
			continue
		}
		if strings.EqualFold(u.SAMAccountName, "krbtgt") {
			continue
		}

		// gMSA/MSA accounts end in '$' and use 240-char random passwords — cracking is
		// infeasible in practice. Still report them but downgrade to Info severity.
		isMSA := strings.HasSuffix(u.SAMAccountName, "$")
		var score float64
		var vec, sev string
		if isMSA {
			vec = "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"
			score = CVSSScore(vec)
			sev = "Info"
		} else {
			ac := CVSSForKerberoastable(u.AdminCount)
			score, vec, sev = ac.Score, ac.Vector, ac.Severity
		}
		kr.KerberoastableAccounts = append(kr.KerberoastableAccounts, KerberoastableAccount{
			SAMAccountName:  u.SAMAccountName,
			DN:              u.DN,
			SPNs:            u.SPNs,
			AdminCount:      u.AdminCount,
			PasswordLastSet: u.PasswordLastSet,
			LastLogon:       u.LastLogon,
			Description:     u.Description,
			CVSS:            score,
			CVSSVector:      vec,
			Severity:        sev,
			IsMSA:           isMSA,
		})
	}

	// ── AS-REP Roastable ──────────────────────────────────────
	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		if !u.DontReqPreauth {
			continue
		}

		aa := CVSSForASREP(u.AdminCount)
		kr.ASREPAccounts = append(kr.ASREPAccounts, ASREPAccount{
			SAMAccountName:  u.SAMAccountName,
			DN:              u.DN,
			AdminCount:      u.AdminCount,
			PasswordLastSet: u.PasswordLastSet,
			LastLogon:       u.LastLogon,
			Description:     u.Description,
			CVSS:            aa.Score,
			CVSSVector:      aa.Vector,
			Severity:        aa.Severity,
		})
	}

	return kr
}

// ============================================================
// Output functions
// ============================================================

// PrintKerberosResult prints kerberos results to terminal
func PrintKerberosResult(kr *KerberosResult) {
	printKerberoastable(kr)
	printASREP(kr)
	printHashcatHints(kr)
}

func printKerberoastable(kr *KerberosResult) {
	color.Cyan("\n  KERBEROASTABLE  (%d)", len(kr.KerberoastableAccounts))
	if len(kr.KerberoastableAccounts) == 0 {
		color.White("  none found")
		return
	}
	color.White("  %-20s %-22s %-22s %s", "account", "pwd last set", "last logon", "spns")
	color.White("  " + strings.Repeat("-", 78))
	for _, acc := range kr.KerberoastableAccounts {
		risk := ""
		if acc.AdminCount {
			risk = " [ADMIN]"
		}
		color.Yellow("  %-20s %-22s %-22s %d%s",
			acc.SAMAccountName+risk,
			acc.PasswordLastSet,
			acc.LastLogon,
			len(acc.SPNs),
		)
	}
}

func printASREP(kr *KerberosResult) {
	color.Cyan("\n  AS-REP ROASTABLE  (%d)", len(kr.ASREPAccounts))
	if len(kr.ASREPAccounts) == 0 {
		color.White("  none found")
		return
	}
	color.White("  %-20s %-22s %s", "account", "pwd last set", "last logon")
	color.White("  " + strings.Repeat("-", 66))
	for _, acc := range kr.ASREPAccounts {
		risk := ""
		if acc.AdminCount {
			risk = " [ADMIN]"
		}
		color.Yellow("  %-20s %-22s %s", acc.SAMAccountName+risk, acc.PasswordLastSet, acc.LastLogon)
	}
}

func printHashcatHints(kr *KerberosResult) {
	if len(kr.KerberoastableAccounts)+len(kr.ASREPAccounts) == 0 {
		return
	}
	color.Cyan("\n  NEXT STEPS")
	if len(kr.KerberoastableAccounts) > 0 {
		color.White("  kerberoast   GetUserSPNs.py %s/<user>:<pass> -dc-ip <DC> -request", kr.Domain)
		color.White("               hashcat -m 13100 hashes.txt wordlist.txt")
	}
	if len(kr.ASREPAccounts) > 0 {
		color.White("  asrep-roast  GetNPUsers.py %s/ -usersfile users.txt -dc-ip <DC>", kr.Domain)
		color.White("               hashcat -m 18200 hashes.txt wordlist.txt")
	}
}

// ============================================================
// Report export
// ============================================================

// FormatForReport formats results for the HTML report
func FormatForReport(kr *KerberosResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Kerberoastable: %d accounts\n", len(kr.KerberoastableAccounts)))
	for _, acc := range kr.KerberoastableAccounts {
		sb.WriteString(fmt.Sprintf("  - %s (SPNs: %s)\n",
			acc.SAMAccountName,
			strings.Join(acc.SPNs, ", ")))
	}

	sb.WriteString(fmt.Sprintf("\nAS-REP Roastable: %d accounts\n", len(kr.ASREPAccounts)))
	for _, acc := range kr.ASREPAccounts {
		sb.WriteString(fmt.Sprintf("  - %s\n", acc.SAMAccountName))
	}

	return sb.String()
}