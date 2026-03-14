package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Моделі даних
// ============================================================

// KerberoastableAccount — акаунт з SPN який можна кербероастити
type KerberoastableAccount struct {
	SAMAccountName  string
	DN              string
	SPNs            []string
	AdminCount      bool
	PasswordLastSet string
	LastLogon       string
	Description     string
}

// ASREPAccount — акаунт з DONT_REQUIRE_PREAUTH
type ASREPAccount struct {
	SAMAccountName  string
	DN              string
	AdminCount      bool
	PasswordLastSet string
	LastLogon       string
	Description     string
}

// KerberosResult — результат аналізу
type KerberosResult struct {
	Domain              string
	KerberoastableAccounts []KerberoastableAccount
	ASREPAccounts          []ASREPAccount
	AnalyzedAt          time.Time
}

// ============================================================
// Основні функції
// ============================================================

// AnalyzeKerberos збирає всі кербероастабельні і AS-REP акаунти
func AnalyzeKerberos(result *adldap.EnumerationResult) *KerberosResult {
	kr := &KerberosResult{
		Domain:     result.Domain,
		AnalyzedAt: time.Now(),
	}

	color.Blue("\n[*] Analyzing Kerberos attack surface...")

	// ── Kerberoastable ────────────────────────────────────────
	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		if len(u.SPNs) == 0 {
			continue
		}
		// пропускаємо krbtgt — системний акаунт
		if strings.EqualFold(u.SAMAccountName, "krbtgt") {
			continue
		}

		kr.KerberoastableAccounts = append(kr.KerberoastableAccounts, KerberoastableAccount{
			SAMAccountName:  u.SAMAccountName,
			DN:              u.DN,
			SPNs:            u.SPNs,
			AdminCount:      u.AdminCount,
			PasswordLastSet: u.PasswordLastSet,
			LastLogon:       u.LastLogon,
			Description:     u.Description,
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

		kr.ASREPAccounts = append(kr.ASREPAccounts, ASREPAccount{
			SAMAccountName:  u.SAMAccountName,
			DN:              u.DN,
			AdminCount:      u.AdminCount,
			PasswordLastSet: u.PasswordLastSet,
			LastLogon:       u.LastLogon,
			Description:     u.Description,
		})
	}

	return kr
}

// ============================================================
// Вивід результатів
// ============================================================

// PrintKerberosResult виводить результати в термінал
func PrintKerberosResult(kr *KerberosResult) {
	printKerberoastable(kr)
	printASREP(kr)
	printHashcatHints(kr)
}

func printKerberoastable(kr *KerberosResult) {
	color.Yellow("\n[!] Kerberoastable Accounts (%d):\n", len(kr.KerberoastableAccounts))

	if len(kr.KerberoastableAccounts) == 0 {
		color.Green("    None found")
		return
	}

	for _, acc := range kr.KerberoastableAccounts {
		// заголовок акаунту
		if acc.AdminCount {
			color.Red("  ► %s [ADMINCOUNT — HIGH VALUE TARGET]", acc.SAMAccountName)
		} else {
			color.Yellow("  ► %s", acc.SAMAccountName)
		}

		// деталі
		color.White("      DN:               %s", acc.DN)
		color.White("      Password Last Set: %s", acc.PasswordLastSet)
		color.White("      Last Logon:        %s", acc.LastLogon)

		if acc.Description != "" {
			color.White("      Description:      %s", acc.Description)
		}

		// SPNs
		color.White("      SPNs:")
		for _, spn := range acc.SPNs {
			color.Cyan("        - %s", spn)
		}

		// оцінка ризику
		printKerberoastRisk(acc)
		fmt.Println()
	}
}

func printASREP(kr *KerberosResult) {
	color.Yellow("\n[!] AS-REP Roastable Accounts (%d):\n", len(kr.ASREPAccounts))

	if len(kr.ASREPAccounts) == 0 {
		color.Green("    None found")
		return
	}

	for _, acc := range kr.ASREPAccounts {
		if acc.AdminCount {
			color.Red("  ► %s [ADMINCOUNT — CRITICAL]", acc.SAMAccountName)
		} else {
			color.Yellow("  ► %s", acc.SAMAccountName)
		}

		color.White("      DN:               %s", acc.DN)
		color.White("      Password Last Set: %s", acc.PasswordLastSet)
		color.White("      Last Logon:        %s", acc.LastLogon)

		if acc.Description != "" {
			color.White("      Description:      %s", acc.Description)
		}

		fmt.Println()
	}
}

// printKerberoastRisk оцінює ризик конкретного акаунту
func printKerberoastRisk(acc KerberoastableAccount) {
	var risks []string

	if acc.AdminCount {
		risks = append(risks, "AdminCount=1 (privileged account)")
	}
	if acc.PasswordLastSet == "Never" || acc.PasswordLastSet == "" {
		risks = append(risks, "Password never set")
	}
	if acc.LastLogon == "Never" || acc.LastLogon == "" {
		risks = append(risks, "Account never used (weak password likely)")
	}
	if len(acc.SPNs) > 1 {
		risks = append(risks, fmt.Sprintf("Multiple SPNs (%d)", len(acc.SPNs)))
	}

	if len(risks) == 0 {
		color.Green("      Risk: Low")
		return
	}

	color.Red("      Risk: HIGH")
	for _, r := range risks {
		color.Red("        • %s", r)
	}
}

// printHashcatHints виводить підказки для наступних кроків
func printHashcatHints(kr *KerberosResult) {
	total := len(kr.KerberoastableAccounts) + len(kr.ASREPAccounts)
	if total == 0 {
		return
	}

	color.Cyan("\n[*] Next steps:")

	if len(kr.KerberoastableAccounts) > 0 {
		color.White("  Kerberoasting — request TGS tickets:")
		color.White("    impacket:  GetUserSPNs.py %s/jon.snow:password -dc-ip <DC> -request", kr.Domain)
		color.White("    hashcat:   hashcat -m 13100 hashes.txt wordlist.txt")
	}

	if len(kr.ASREPAccounts) > 0 {
		color.White("\n  AS-REP Roasting — request AS-REP hashes:")
		color.White("    impacket:  GetNPUsers.py %s/ -usersfile users.txt -dc-ip <DC>", kr.Domain)
		color.White("    hashcat:   hashcat -m 18200 hashes.txt wordlist.txt")
	}
}

// ============================================================
// Експорт хешів
// ============================================================

// FormatForReport форматує результати для HTML звіту
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