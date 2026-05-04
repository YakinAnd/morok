package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/YakinAnd/adpath/internal/analysis"
	"github.com/YakinAnd/adpath/internal/bloodhound"
	"github.com/YakinAnd/adpath/internal/graph"
	adkerberos "github.com/YakinAnd/adpath/internal/kerberos"
	adldap "github.com/YakinAnd/adpath/internal/ldap"
	"github.com/YakinAnd/adpath/internal/report"
)

// ============================================================
// Глобальні змінні для CLI флагів
// ============================================================

var (
	domain         string
	username       string
	password       string
	ntHash         string // --hash: NT hash for Pass-the-Hash
	ccachePath     string // --ccache: path to ccache file for Pass-the-Ticket
	proxyURL       string // --proxy: SOCKS5 proxy URL (PTT not supported through proxy)
	scopeDN        string // --scope: override base DN for scoped audit
	dc             string
	reportPath     string
	jsonExportPath string // --json: output dir for AD JSON export (compatible with BloodHound CE)
	maxDepth       int
	verbose        bool
	wordlistPath   string // --wordlist: path to username wordlist for kerb-enum
	stealth        bool   // --stealth: minimal LDAP queries, no GC, no heavy analysis
)

// ============================================================
// Cobra команди
// ============================================================

var rootCmd = &cobra.Command{
	Use:   "adpath",
	Short: "AD attack path enumeration tool",
	Long:  `adpath — lightweight Active Directory enumeration and attack path analysis`,
}

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate AD objects and find attack paths",
	RunE:  runEnum,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("adpath v0.9.9")
		color.White("AD Attack Path Enumerator")
		color.White("https://github.com/YakinAnd/adpath")
	},
}

var kerberosCmd = &cobra.Command{
    Use:   "kerberos",
    Short: "Analyze Kerberoastable and AS-REP roastable accounts",
    RunE:  runKerberos,
}

var aclCmd = &cobra.Command{
    Use:   "acl",
    Short: "Analyze dangerous ACL permissions in AD",
    RunE:  runACL,
}

var delegationCmd = &cobra.Command{
    Use:   "delegation",
    Short: "Analyze dangerous delegation configurations in AD",
    RunE:  runDelegation,
}

var gpoCmd = &cobra.Command{
	Use:   "gpo",
	Short: "Analyze Group Policy Objects for security issues",
	RunE:  runGPO,
}

var adcsCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Analyze Active Directory Certificate Services (ESC1-ESC8)",
	RunE:  runADCS,
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Analyze domain/forest trusts and foreign security principals",
	RunE:  runTrust,
}

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Detect principals that can write msDS-KeyCredentialLink on privileged objects",
	RunE:  runShadow,
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Check audit policy, AD Recycle Bin, and blue-team visibility settings",
	RunE:  runAudit,
}

var enumUsersCmd = &cobra.Command{
	Use:   "kerb-enum",
	Short: "Enumerate valid AD usernames via Kerberos AS-REQ (no credentials required)",
	RunE:  runEnumUsers,
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate AD users and display a summary table",
	RunE:  runUsers,
}

var computersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate AD computers and display a summary table",
	RunE:  runComputers,
}

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Check SMB signing status on the domain controller (port 445)",
	RunE:  runSMB,
}

// ============================================================
// Реєстрація флагів
// ============================================================

func init() {
	for _, cmd := range []*cobra.Command{enumCmd, kerberosCmd, aclCmd, delegationCmd, gpoCmd, adcsCmd, trustCmd, shadowCmd, auditCmd, usersCmd, computersCmd, enumUsersCmd, smbCmd} {
		cmd.Flags().SortFlags = false
		cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
		cmd.Flags().StringVarP(&username, "username", "u", "", "Username")
		cmd.Flags().StringVarP(&password, "password", "p", "", "Password")
		cmd.Flags().StringVarP(&ntHash, "hashes", "H", "", "NT hash for Pass-the-Hash (e.g. aad3b435...)")
		cmd.Flags().StringVar(&ccachePath, "ccache", "", "Path to Kerberos ccache file for Pass-the-Ticket")
		cmd.Flags().StringVar(&dc, "dc", "", "Domain controller IP or hostname")
		cmd.Flags().StringVar(&proxyURL, "proxy", "", "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080) — PTT/ccache not supported through proxy")
		cmd.Flags().StringVar(&scopeDN, "scope", "", "Restrict enumeration to specific OU/DN (e.g. OU=Finance,DC=corp,DC=local)")
		cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
		cmd.MarkFlagRequired("domain")
	}

	enumCmd.Flags().StringVar(&reportPath, "report", "", "Save HTML report to file (e.g. report.html)")
	enumCmd.Flags().StringVar(&jsonExportPath, "json", "", "Export AD objects as JSON to directory (e.g. json_out/)")
	enumCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum BFS depth for attack path search")
	enumCmd.Flags().BoolVar(&stealth, "stealth", false, "Stealth mode — minimal LDAP queries, no GC, no ACL/GPO/ADCS/delegation analysis")

	enumUsersCmd.Flags().StringVar(&wordlistPath, "wordlist", "", "Path to username wordlist (one username per line, required)")
	enumUsersCmd.MarkFlagRequired("wordlist")

	rootCmd.AddCommand(aclCmd)
	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(kerberosCmd)
	rootCmd.AddCommand(delegationCmd)
	rootCmd.AddCommand(gpoCmd)
	rootCmd.AddCommand(adcsCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(shadowCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(usersCmd)
	rootCmd.AddCommand(computersCmd)
	rootCmd.AddCommand(enumUsersCmd)
	rootCmd.AddCommand(smbCmd)

	rootCmd.Version = "0.9.8"
}

// ============================================================
// Report path helper
// ============================================================

// resolveReportPath повертає шлях до HTML звіту.
// Якщо explicit задано — використовує його.
// Інакше — генерує назву {domain}_{YYYY-MM-DD_HH-MM-SS}.html
// поруч з бінарним файлом.
func resolveReportPath(explicit, targetDomain string) string {
	if explicit != "" {
		return explicit
	}
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := targetDomain + "_" + timestamp + ".html"

	exe, err := os.Executable()
	if err != nil {
		return filename // fallback: поточна директорія
	}
	return filepath.Join(filepath.Dir(exe), filename)
}

// ============================================================
// Auth helper
// ============================================================

// connectAndBind підключається та автентифікується відповідним методом:
//
//	--ccache  → Kerberos ccache (Pass-the-Ticket)
//	-H/--hashes → NTLM hash (Pass-the-Hash)
//	-u/-p     → simple bind (UPN / NT format)
//	(none)    → anonymous bind (null session)
func connectAndBind() (*adldap.Client, error) {
	client := adldap.NewClient(domain, username, password, dc, verbose)
	client.NTHash = ntHash
	client.CcachePath = ccachePath
	client.ProxyURL = proxyURL
	if scopeDN != "" {
		client.BaseDN = scopeDN
		color.White("  %-28s %s", "scope", scopeDN)
	}

	if proxyURL != "" && ccachePath != "" {
		return nil, fmt.Errorf("--proxy and --ccache cannot be used together: Kerberos ccache is not supported through SOCKS5 proxy")
	}

	if proxyURL != "" {
		color.White("  proxy             %s", proxyURL)
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}

	switch {
	case ccachePath != "":
		if err := client.BindKerberos(); err != nil {
			client.Close()
			return nil, fmt.Errorf("kerberos auth error: %w", err)
		}
	case ntHash != "":
		if err := client.BindNTLM(); err != nil {
			client.Close()
			return nil, fmt.Errorf("NTLM auth error: %w", err)
		}
	case username != "":
		if err := client.Bind(); err != nil {
			client.Close()
			return nil, fmt.Errorf("auth error: %w", err)
		}
	default:
		color.Yellow("  no credentials — anonymous bind (limited enumeration)")
		if err := client.AnonymousBind(); err != nil {
			client.Close()
			return nil, fmt.Errorf("anonymous bind failed: %w", err)
		}
		color.White("  %-28s %s", "RootDSE", "✓ readable")
		color.Yellow("  %-28s %s", "hint", "obtain any domain account for full enumeration")
	}

	return client, nil
}

// ============================================================
// Логіка команди enum
// ============================================================

func runEnum(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	// ── RootDSE ───────────────────────────────────────────────
	var ldapSecResult *analysis.LDAPSecurityResult
	var auditResult *analysis.AuditResult
	var rdsInfo *adldap.RootDSEInfo
	if rds, err := client.QueryRootDSE(); err == nil {
		rdsInfo = rds
		if !stealth {
			ldapSecResult = analysis.AnalyzeLDAPSecurity(client, rds)
			auditResult = analysis.AnalyzeAuditPolicy(client, rds)
		}
	}

	// ── enumeration ───────────────────────────────────────────
	var result *adldap.EnumerationResult
	if stealth {
		users, err := client.EnumerateUsers()
		if err != nil {
			return fmt.Errorf("user enumeration error: %w", err)
		}
		groups, err := client.EnumerateGroups()
		if err != nil {
			return fmt.Errorf("group enumeration error: %w", err)
		}
		result = &adldap.EnumerationResult{
			Domain: client.Domain,
			BaseDN: client.BaseDN,
			Users:  users,
			Groups: groups,
		}
	} else {
		result, err = client.EnumerateAll()
		if err != nil {
			return fmt.Errorf("enumeration error: %w", err)
		}
	}

	// ── graph + attack paths ──────────────────────────────────
	g := graph.Build(result)
	paths := g.FindPathsToPrivilegedGroups(maxDepth)

	// ── analysis ─────────────────────────────────────────────
	kr := analysis.AnalyzeKerberos(result)
	trustResult, _ := analysis.AnalyzeTrusts(client, result)
	smbResult := analysis.CheckSMBSigning(client.Host)

	var aclResult *analysis.ACLResult
	var dr *analysis.DelegationResult
	var gr *analysis.GPOResult
	var hr *analysis.HygieneResult
	var puResult *analysis.ProtectedUsersResult
	var adminSDResult *analysis.AdminSDHolderResult
	var psoResult *analysis.PSOResult
	var adcsResult *analysis.ADCSResult
	var shadowResult *analysis.ShadowCredentialsResult
	var sysvolResult *analysis.SYSVOLResult
	var lapsACLResult *analysis.LAPSACLResult

	if !stealth {
		aclResult, _ = analysis.AnalyzeACL(client, result)
		dr, _ = analysis.AnalyzeDelegation(client)
		gr, _ = analysis.AnalyzeGPO(client)
		hr = analysis.AnalyzeHygiene(result)
		puResult = analysis.AnalyzeProtectedUsers(result)
		adminSDResult, _ = analysis.AnalyzeAdminSDHolder(client, result)
		psoResult, _ = analysis.AnalyzePSO(client)
		adcsResult, _ = analysis.AnalyzeADCS(client)
		shadowResult, _ = analysis.AnalyzeShadowCredentials(client, result)
		sysvolResult = analysis.ScanSYSVOL(client)
		lapsACLResult, _ = analysis.AnalyzeLAPSACL(client, result)
	}

	// ── Variant A terminal output ─────────────────────────────
	printEnumSummary(rdsInfo, result, paths, kr, aclResult, adcsResult, shadowResult, smbResult, hr, ldapSecResult, auditResult)

	// ── HTML report (opt-in via --report) ────────────────────
	if reportPath != "" {
		outPath := resolveReportPath(reportPath, domain)
		authMethod := "Password"
		switch {
		case ccachePath != "":
			authMethod = "PTT (Kerberos ccache)"
		case ntHash != "":
			authMethod = "PTH (NTLM hash)"
		case username == "":
			authMethod = "Anonymous"
		}
		if err := report.Generate(outPath, result, g, paths, kr, aclResult, dr, gr, hr, psoResult, adcsResult, puResult, adminSDResult, trustResult, shadowResult, ldapSecResult, auditResult, smbResult, sysvolResult, lapsACLResult, authMethod); err != nil {
			return fmt.Errorf("report error: %w", err)
		}
		fmt.Println()
		color.Cyan("  REPORT")
		color.White("  %-28s %s", "saved to", outPath)
	}

	// ── JSON export ───────────────────────────────────────────
	if jsonExportPath != "" {
		if err := bloodhound.Export(jsonExportPath, result); err != nil {
			color.Yellow("  json export failed: %v", err)
		} else {
			fmt.Println()
			color.Cyan("  JSON EXPORT")
			color.White("  %-28s %s", "output dir", jsonExportPath)
			color.White("  %-28s %s", "files", "users.json, groups.json, computers.json, domains.json")
		}
	}

	return nil
}

// ============================================================
// Variant A — minimalist enum summary
// ============================================================

const enumMaxItems = 5 // max notable items to show per category before truncating

// bold returns a bold+red string for CRITICAL findings.
var (
	critPrefix = color.New(color.FgRed, color.Bold).SprintFunc()
	highPrefix = color.New(color.FgRed).SprintFunc()
	medPrefix  = color.New(color.FgYellow).SprintFunc()
	dimText    = color.New(color.Faint).SprintFunc()
)

// joinTrunc joins up to max names with " / " and appends "(+N more)" if needed.
func joinTrunc(names []string, max int) string {
	if len(names) == 0 {
		return ""
	}
	if len(names) <= max {
		return strings.Join(names, " / ")
	}
	shown := strings.Join(names[:max], " / ")
	return fmt.Sprintf("%s  (+%d more)", shown, len(names)-max)
}

func printEnumSummary(
	rds *adldap.RootDSEInfo,
	result *adldap.EnumerationResult,
	paths []graph.AttackPath,
	kr *analysis.KerberosResult,
	acl *analysis.ACLResult,
	adcs *analysis.ADCSResult,
	shadow *analysis.ShadowCredentialsResult,
	smb *analysis.SMBSigningResult,
	hr *analysis.HygieneResult,
	ldapSec *analysis.LDAPSecurityResult,
	audit *analysis.AuditResult,
) {
	fmt.Println()

	// ── DOMAIN ────────────────────────────────────────────────
	color.Cyan("  DOMAIN")
	if rds != nil {
		dcName := rds.ServerName
		if dcName == "" {
			dcName = domain
		}
		osName := adldap.FunctionalityLevelName(rds.DomainFunctionality)
		color.White("  %-14s %s", "domain", rds.DefaultNamingContext)
		color.White("  %-14s %s", "DC", dcName)
		if osName != "" {
			color.White("  %-14s %s", "level", osName)
		}
	} else {
		color.White("  %-14s %s", "domain", domain)
	}

	// ── LDAP / SMB flags ──────────────────────────────────────
	if ldapSec != nil {
		for _, f := range ldapSec.Findings {
			switch f.Severity {
			case "High":
				fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "ldap", f.Title)
			default:
				fmt.Printf("  %s  %-20s %s\n", medPrefix("[-]"), "ldap", f.Title)
			}
		}
	}
	if smb != nil && smb.Reachable && !smb.SigningRequired {
		fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "smb signing", "not required — NTLM relay risk")
	}
	if audit != nil {
		for _, f := range audit.Findings {
			fmt.Printf("  %s  %-20s %s\n", medPrefix("[-]"), "audit", f.Title)
		}
	}

	// ── USERS ─────────────────────────────────────────────────
	if result != nil {
		fmt.Println()
		totalUsers := len(result.Users)
		enabledUsers, disabledUsers, asrepUsers, adminUsers, pwdNeverUsers := 0, 0, []string{}, 0, 0
		for _, u := range result.Users {
			if u.Enabled {
				enabledUsers++
			} else {
				disabledUsers++
			}
			if u.DontReqPreauth && u.Enabled {
				asrepUsers = append(asrepUsers, u.SAMAccountName)
			}
			if u.AdminCount {
				adminUsers++
			}
			if u.PasswordNeverExpires && u.Enabled {
				pwdNeverUsers++
			}
		}
		color.Cyan("  USERS    %s", dimText(fmt.Sprintf("%d total · %d enabled · %d disabled", totalUsers, enabledUsers, disabledUsers)))
		if len(asrepUsers) > 0 {
			fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "AS-REP roastable", joinTrunc(asrepUsers, enumMaxItems))
		}
		if adminUsers > 0 {
			fmt.Printf("  %s  %-20s %d accounts\n", medPrefix("[-]"), "adminCount=1", adminUsers)
		}
		if pwdNeverUsers > 0 {
			fmt.Printf("  %s  %-20s %d accounts\n", medPrefix("[-]"), "pwd never expires", pwdNeverUsers)
		}
		if hr != nil {
			if len(hr.StaleUsers) > 0 {
				fmt.Printf("  %s  %-20s %d accounts  %s\n", medPrefix("[-]"), "stale (>90d)", len(hr.StaleUsers), dimText("no logon"))
			}
			if hr.KrbtgtAtRisk {
				fmt.Printf("  %s  %-20s %s  %s\n", highPrefix("[!]"), "krbtgt age", fmt.Sprintf("%d days", hr.KrbtgtPwdAgeDays), dimText("golden ticket risk"))
			}
		}

		// ── COMPUTERS ─────────────────────────────────────────────
		if len(result.Computers) > 0 {
			fmt.Println()
			totalComp := len(result.Computers)
			enabledComp, disabledComp, unconstrComp, noLAPSComp := 0, 0, []string{}, 0
			for _, c := range result.Computers {
				if c.Enabled {
					enabledComp++
					if !c.LAPSEnabled {
						noLAPSComp++
					}
				} else {
					disabledComp++
				}
				if c.UnconstrainedDelegation {
					h := c.DNSHostName
					if h == "" {
						h = c.SAMAccountName
					}
					unconstrComp = append(unconstrComp, h)
				}
			}
			scopeLabel := ""
			if result.ForestWide {
				scopeLabel = "  " + dimText("(forest-wide)")
			}
			color.Cyan("  COMPUTERS  %s%s", dimText(fmt.Sprintf("%d total · %d enabled · %d disabled", totalComp, enabledComp, disabledComp)), scopeLabel)
			if noLAPSComp > 0 {
				fmt.Printf("  %s  %-20s %d hosts\n", medPrefix("[-]"), "no LAPS", noLAPSComp)
			}
			if len(unconstrComp) > 0 {
				fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "unconstrained deleg", joinTrunc(unconstrComp, enumMaxItems))
			}
			if hr != nil && len(hr.StaleComputers) > 0 {
				fmt.Printf("  %s  %-20s %d hosts  %s\n", medPrefix("[-]"), "stale (>45d)", len(hr.StaleComputers), dimText("no logon"))
			}
		}
	}

	// ── KERBEROS ──────────────────────────────────────────────
	if kr != nil && (len(kr.KerberoastableAccounts) > 0 || len(kr.ASREPAccounts) > 0) {
		fmt.Println()
		color.Cyan("  KERBEROS")
		if len(kr.KerberoastableAccounts) > 0 {
			names := make([]string, len(kr.KerberoastableAccounts))
			for i, a := range kr.KerberoastableAccounts {
				names[i] = a.SAMAccountName
			}
			fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "kerberoastable", joinTrunc(names, enumMaxItems))
		}
		if len(kr.ASREPAccounts) > 0 {
			names := make([]string, len(kr.ASREPAccounts))
			for i, a := range kr.ASREPAccounts {
				names[i] = a.SAMAccountName
			}
			fmt.Printf("  %s  %-20s %s\n", highPrefix("[!]"), "AS-REP roastable", joinTrunc(names, enumMaxItems))
		}
	}

	// ── ACL ───────────────────────────────────────────────────
	if acl != nil && (len(acl.Findings) > 0 || len(acl.DCSyncFindings) > 0) {
		fmt.Println()
		critCount, highCount := 0, 0
		for _, f := range acl.Findings {
			if f.Severity == "Critical" {
				critCount++
			} else {
				highCount++
			}
		}
		critCount += len(acl.DCSyncFindings)
		color.Cyan("  ACL      %s", dimText(fmt.Sprintf("%d critical · %d high", critCount, highCount)))
		shown := 0
		for _, f := range acl.DCSyncFindings {
			if shown >= enumMaxItems {
				break
			}
			fmt.Printf("  %s  %-18s %-14s →  %s\n", critPrefix("[!!]"), f.PrincipalName, "DCSync", domain)
			shown++
		}
		for _, f := range acl.Findings {
			if shown >= enumMaxItems {
				break
			}
			pfx := highPrefix("[!] ")
			if f.Severity == "Critical" {
				pfx = critPrefix("[!!]")
			}
			fmt.Printf("  %s  %-18s %-14s →  %s\n", pfx, f.PrincipalName, string(f.Right), f.TargetName)
			shown++
		}
		total := len(acl.Findings) + len(acl.DCSyncFindings)
		if total > enumMaxItems {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: adpath acl -d %s ...)", total-enumMaxItems, domain)))
		}
	}

	// ── ADCS ──────────────────────────────────────────────────
	if adcs != nil && len(adcs.TemplateFindings) > 0 {
		fmt.Println()
		critCount, highCount := 0, 0
		for _, f := range adcs.TemplateFindings {
			if f.Severity == "Critical" {
				critCount++
			} else {
				highCount++
			}
		}
		color.Cyan("  ADCS     %s", dimText(fmt.Sprintf("%d critical · %d high", critCount, highCount)))
		shown := 0
		for _, f := range adcs.TemplateFindings {
			if shown >= enumMaxItems {
				break
			}
			pfx := highPrefix("[!] ")
			if f.Severity == "Critical" {
				pfx = critPrefix("[!!]")
			}
			escLabel := ""
			if len(f.VulnTypes) > 0 {
				escLabel = string(f.VulnTypes[0])
			}
			fmt.Printf("  %s  %-18s %s  %s\n", pfx, f.TemplateName, dimText("("+escLabel+")"), "")
			shown++
		}
		if len(adcs.TemplateFindings) > enumMaxItems {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: adpath adcs -d %s ...)", len(adcs.TemplateFindings)-enumMaxItems, domain)))
		}
	}

	// ── SHADOW CREDENTIALS ────────────────────────────────────
	if shadow != nil && len(shadow.Findings) > 0 {
		fmt.Println()
		color.Cyan("  SHADOW CREDS  %s", dimText(fmt.Sprintf("%d finding(s)", len(shadow.Findings))))
		shown := 0
		for _, f := range shadow.Findings {
			if shown >= enumMaxItems {
				break
			}
			pfx := highPrefix("[!] ")
			if f.Severity == "Critical" {
				pfx = critPrefix("[!!]")
			}
			fmt.Printf("  %s  %-18s →  %s\n", pfx, f.PrincipalName, f.TargetName)
			shown++
		}
		if len(shadow.Findings) > enumMaxItems {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: adpath shadow -d %s ...)", len(shadow.Findings)-enumMaxItems, domain)))
		}
	}

	// ── ATTACK PATHS ──────────────────────────────────────────
	if len(paths) > 0 {
		fmt.Println()
		color.Cyan("  ATTACK PATHS  %s", dimText(fmt.Sprintf("%d found", len(paths))))
		shown := 0
		for _, p := range paths {
			if shown >= enumMaxItems {
				break
			}
			names := make([]string, len(p.Nodes))
			for i, n := range p.Nodes {
				names[i] = n.SAMAccountName
			}
			chain := strings.Join(names, " → ")
			fmt.Printf("  %s  %s  %s\n", critPrefix("[!!]"), chain, dimText(fmt.Sprintf("(depth %d → %s)", p.Depth, p.TargetGroup)))
			shown++
		}
		if len(paths) > enumMaxItems {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more)", len(paths)-enumMaxItems)))
		}
	} else if result != nil {
		fmt.Println()
		color.Cyan("  ATTACK PATHS  %s", dimText("0 found"))
	}

	// ── RISK SUMMARY ──────────────────────────────────────────
	fmt.Println()
	color.White("  " + strings.Repeat("─", 60))

	// count totals for risk rating
	critTotal, highTotal, medTotal := 0, 0, 0
	if acl != nil {
		critTotal += len(acl.DCSyncFindings)
		for _, f := range acl.Findings {
			if f.Severity == "Critical" {
				critTotal++
			} else {
				highTotal++
			}
		}
	}
	if adcs != nil {
		for _, f := range adcs.TemplateFindings {
			if f.Severity == "Critical" {
				critTotal++
			} else {
				highTotal++
			}
		}
	}
	if shadow != nil {
		for _, f := range shadow.Findings {
			if f.Severity == "Critical" {
				critTotal++
			} else {
				highTotal++
			}
		}
	}
	if kr != nil {
		highTotal += len(kr.KerberoastableAccounts) + len(kr.ASREPAccounts)
	}
	for _, p := range paths {
		if p.Depth <= 2 {
			critTotal++
		} else {
			medTotal++
		}
	}
	if smb != nil && smb.Reachable && !smb.SigningRequired {
		highTotal++
	}
	if ldapSec != nil {
		for _, f := range ldapSec.Findings {
			if f.Severity == "High" {
				highTotal++
			} else {
				medTotal++
			}
		}
	}

	riskLabel := "LOW"
	riskColor := color.New(color.FgGreen)
	if critTotal > 0 {
		riskLabel = "CRITICAL"
		riskColor = color.New(color.FgRed, color.Bold)
	} else if highTotal > 0 {
		riskLabel = "HIGH"
		riskColor = color.New(color.FgRed)
	} else if medTotal > 0 {
		riskLabel = "MEDIUM"
		riskColor = color.New(color.FgYellow)
	}

	fmt.Printf("  RISK  ")
	riskColor.Printf("%s", riskLabel)
	fmt.Printf("   %s  %s  %s\n",
		critPrefix(fmt.Sprintf("[!!] %d critical", critTotal)),
		highPrefix(fmt.Sprintf("[!] %d high", highTotal)),
		medPrefix(fmt.Sprintf("[-] %d medium", medTotal)),
	)
	fmt.Println()
	if reportPath == "" {
		color.White("  %s", dimText("tip: add --report report.html to generate a full HTML report"))
	}
}


// ============================================================
// Логіка команди Kerberoasting
// ============================================================
func runKerberos(cmd *cobra.Command, args []string) error {
    printBanner()

    client, err := connectAndBind()
    if err != nil {
        return err
    }
    defer client.Close()

    // enumeration
    result, err := client.EnumerateAll()
    if err != nil {
        return fmt.Errorf("enumeration error: %w", err)
    }

    // kerberos аналіз
    kr := analysis.AnalyzeKerberos(result)
    analysis.PrintKerberosResult(kr)

    return nil
}


// ============================================================
// Логіка команди ACL аналіз
// ============================================================
func runACL(cmd *cobra.Command, args []string) error {
    printBanner()

    client, err := connectAndBind()
    if err != nil {
        return err
    }
    defer client.Close()

    result, err := client.EnumerateAll()
    if err != nil {
        return fmt.Errorf("enumeration error: %w", err)
    }

    aclResult, err := analysis.AnalyzeACL(client, result)
    if err != nil {
        return fmt.Errorf("ACL analysis error: %w", err)
    }

    analysis.PrintACLResult(aclResult)

    return nil
}

// ============================================================
// Логіка команди Delegation
// ============================================================

func runDelegation(cmd *cobra.Command, args []string) error {
    printBanner()

    client, err := connectAndBind()
    if err != nil {
        return err
    }
    defer client.Close()

    dr, err := analysis.AnalyzeDelegation(client)
    if err != nil {
        return fmt.Errorf("delegation analysis error: %w", err)
    }

    analysis.PrintDelegationResult(dr)

    return nil
}

// ============================================================
// Логіка команди GPO
// ============================================================

func runGPO(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	gr, err := analysis.AnalyzeGPO(client)
	if err != nil {
		return fmt.Errorf("GPO analysis error: %w", err)
	}

	analysis.PrintGPOResult(gr)

	return nil
}

// ============================================================
// Логіка команди ADCS
// ============================================================

func runADCS(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	r, err := analysis.AnalyzeADCS(client)
	if err != nil {
		return fmt.Errorf("ADCS analysis error: %w", err)
	}

	analysis.PrintADCSResult(r)
	return nil
}

// ============================================================
// Логіка команди Trust
// ============================================================

func runTrust(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	result, err := client.EnumerateAll()
	if err != nil {
		return fmt.Errorf("enumeration error: %w", err)
	}

	r, err := analysis.AnalyzeTrusts(client, result)
	if err != nil {
		return fmt.Errorf("trust analysis error: %w", err)
	}
	analysis.PrintTrustResult(r)
	return nil
}

func runAudit(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	rds, err := client.QueryRootDSE()
	if err != nil {
		return fmt.Errorf("rootDSE query failed: %w", err)
	}

	r := analysis.AnalyzeAuditPolicy(client, rds)
	analysis.PrintAuditResult(r)
	return nil
}

func runShadow(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	result, err := client.EnumerateAll()
	if err != nil {
		return fmt.Errorf("enumeration error: %w", err)
	}

	r, err := analysis.AnalyzeShadowCredentials(client, result)
	if err != nil {
		return fmt.Errorf("shadow credentials analysis error: %w", err)
	}
	analysis.PrintShadowCredentialsResult(r)
	return nil
}

// ============================================================
// Логіка команди Enum-Users (Kerberos AS-REQ, no creds)
// ============================================================

func runEnumUsers(cmd *cobra.Command, args []string) error {
	printBanner()

	targetDC := dc
	if targetDC == "" {
		targetDC = domain
	}

	_, err := adkerberos.EnumUsers(domain, targetDC, wordlistPath)
	if err != nil {
		return fmt.Errorf("kerb-enum: %w", err)
	}
	return nil
}

// ============================================================
// Логіка команди Users
// ============================================================

func runUsers(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	color.Cyan("\n  USERS")
	users, err := client.EnumerateUsers()
	if err != nil {
		return fmt.Errorf("user enumeration error: %w", err)
	}

	color.White("  %-28s %d", "total users", len(users))
	enabled, disabled, adminCount, asrep, pwdNeverExpires := 0, 0, 0, 0, 0
	for _, u := range users {
		if u.Enabled {
			enabled++
		} else {
			disabled++
		}
		if u.AdminCount {
			adminCount++
		}
		if u.DontReqPreauth {
			asrep++
		}
		if u.PasswordNeverExpires {
			pwdNeverExpires++
		}
	}
	color.White("  %-28s %d", "enabled", enabled)
	color.White("  %-28s %d", "disabled", disabled)
	if adminCount > 0 {
		color.Yellow("  %-28s %d", "adminCount=1 (protected)", adminCount)
	}
	if asrep > 0 {
		color.Red("  %-28s %d  (AS-REP roastable)", "no pre-auth", asrep)
	}
	if pwdNeverExpires > 0 {
		color.Yellow("  %-28s %d", "password never expires", pwdNeverExpires)
	}

	const (
		wUser = 22
		wDisp = 24
	)
	fmt.Println()
	color.White("  %-*s  %-*s  %-7s  %-10s  %-6s  %-13s  %-19s  %s",
		wUser, "USERNAME", wDisp, "DISPLAY NAME",
		"ENABLED", "ADMINCOUNT", "AS-REP", "PWD NEVER EXP", "LAST LOGON", "SPNS")
	color.White("  " + strings.Repeat("─", wUser+wDisp+75))
	for _, u := range users {
		enabledStr := "yes"
		if !u.Enabled {
			enabledStr = "no"
		}
		adminStr := ""
		if u.AdminCount {
			adminStr = "yes"
		}
		asrepStr := ""
		if u.DontReqPreauth {
			asrepStr = "yes"
		}
		pwdStr := ""
		if u.PasswordNeverExpires {
			pwdStr = "yes"
		}
		spnCount := ""
		if len(u.SPNs) > 0 {
			spnCount = fmt.Sprintf("%d", len(u.SPNs))
		}
		lastLogon := u.LastLogon
		if lastLogon == "" {
			lastLogon = "never"
		}
		line := fmt.Sprintf("  %-*s  %-*s  %-7s  %-10s  %-6s  %-13s  %-19s  %s",
			wUser, trunc(u.SAMAccountName, wUser),
			wDisp, trunc(u.DisplayName, wDisp),
			enabledStr, adminStr, asrepStr, pwdStr, lastLogon, spnCount)
		if !u.Enabled {
			color.White("\033[2m" + line + "\033[0m") // dim
		} else if u.DontReqPreauth {
			color.Red(line)
		} else if u.AdminCount {
			color.Yellow(line)
		} else {
			color.White(line)
		}
	}
	return nil
}

// ============================================================
// Логіка команди Computers
// ============================================================

func runComputers(cmd *cobra.Command, args []string) error {
	printBanner()

	client, err := connectAndBind()
	if err != nil {
		return err
	}
	defer client.Close()

	color.Cyan("\n  COMPUTERS")
	computers, forestWide, err := client.EnumerateComputersForest()
	if err != nil {
		return fmt.Errorf("computer enumeration error: %w", err)
	}
	if forestWide {
		color.White("  %-28s forest-wide (GC)", "scope")
	}

	color.White("  %-28s %d", "total computers", len(computers))
	enabled, disabled, laps, unconstr := 0, 0, 0, 0
	for _, c := range computers {
		if c.Enabled {
			enabled++
		} else {
			disabled++
		}
		if c.LAPSEnabled {
			laps++
		}
		if c.UnconstrainedDelegation {
			unconstr++
		}
	}
	color.White("  %-28s %d", "enabled", enabled)
	color.White("  %-28s %d", "disabled", disabled)
	if laps > 0 {
		color.Green("  %-28s %d", "LAPS enabled", laps)
	} else {
		color.Yellow("  %-28s 0  (no LAPS managed hosts detected)", "LAPS enabled")
	}
	if unconstr > 0 {
		color.Red("  %-28s %d  (unconstrained delegation)", "dangerous delegation", unconstr)
	}

	// compute column widths dynamically
	maxHost, maxOS := len("HOSTNAME"), len("OS")
	for _, c := range computers {
		h := c.DNSHostName
		if h == "" {
			h = c.SAMAccountName
		}
		if len(h) > maxHost {
			maxHost = len(h)
		}
		osStr := c.OperatingSystem
		if c.OperatingSystemVersion != "" {
			osStr += " " + c.OperatingSystemVersion
		}
		if len(osStr) > maxOS {
			maxOS = len(osStr)
		}
	}

	fmt.Println()
	color.White("  %-*s  %-*s  %s", maxHost, "HOSTNAME", maxOS, "OS", "ENABLED")
	color.White("  " + strings.Repeat("─", maxHost+maxOS+12))
	for _, c := range computers {
		enabledStr := "yes"
		if !c.Enabled {
			enabledStr = "no"
		}
		hostname := c.DNSHostName
		if hostname == "" {
			hostname = c.SAMAccountName
		}
		osStr := c.OperatingSystem
		if c.OperatingSystemVersion != "" {
			osStr += " " + c.OperatingSystemVersion
		}
		line := fmt.Sprintf("  %-*s  %-*s  %s", maxHost, hostname, maxOS, osStr, enabledStr)
		if !c.Enabled {
			color.White("\033[2m" + line + "\033[0m")
		} else {
			color.White(line)
		}
	}
	return nil
}

// trunc truncates s to maxLen runes, appending "…" if cut.
func trunc(s string, maxLen int) string {
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return string(r[:maxLen-1]) + "…"
}

// ============================================================
// Banner
// ============================================================

func printBanner() {
	color.Cyan(`    _      ____    ____      _      _____   _   _`)
	color.Cyan(`   / \    |  _ \  |  _ \    / \    |_   _| | | | |`)
	color.Cyan(`  / _ \   | | | | | |_) |  / _ \     | |   | |_| |`)
	color.Cyan(` / ___ \  | |_| | |  __/  / ___ \    | |   |  _  |`)
	color.Cyan(`/_/   \_\ |____/  |_|    /_/   \_\   |_|   |_| |_|`)
	color.White(``)
	color.White(`  v0.9.9  //  AD Attack Path Enumerator`)
	color.White(`  ` + strings.Repeat("─", 40))
}

// ============================================================
// Логіка команди SMB
// ============================================================

func runSMB(cmd *cobra.Command, args []string) error {
	printBanner()

	targetDC := dc
	if targetDC == "" {
		targetDC = domain
	}

	r := analysis.CheckSMBSigning(targetDC)
	analysis.PrintSMBSigningResult(r)
	return nil
}

// ============================================================
// Entrypoint
// ============================================================

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}