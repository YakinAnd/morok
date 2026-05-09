package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/YakinAnd/morok/internal/analysis"
	"github.com/YakinAnd/morok/internal/bloodhound"
	"github.com/YakinAnd/morok/internal/graph"
	adkerberos "github.com/YakinAnd/morok/internal/kerberos"
	adldap "github.com/YakinAnd/morok/internal/ldap"
	"github.com/YakinAnd/morok/internal/report"
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
	quietMode      bool   // --quiet: suppress detailed output, print only risk verdict (CI mode)
	wordlistPath   string // --wordlist: path to username wordlist for kerb-enum
	stealth        bool   // --stealth: minimal LDAP queries, no GC, no heavy analysis
)

// ============================================================
// Cobra команди
// ============================================================

var rootCmd = &cobra.Command{
	Use:   "morok",
	Short: "AD attack path enumeration tool",
	Long:  `morok — Active Directory enumeration and attack path analysis`,
}

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate AD objects and find attack paths",
	Example: `  morok enum -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok enum -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --report report.html
  morok enum -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1
  morok enum -d corp.local --ccache /tmp/admin.ccache --dc 10.0.0.1
  morok enum -d corp.local -u svc_audit -p 'Password1' --dc 10.0.0.1 --quiet
  morok enum -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --stealth`,
	RunE: runEnum,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		color.New(color.FgYellow).Println("morok v1.0")
		color.New(color.FgHiBlack).Println("AD attack path enumerator  ·  see through the fog")
		color.White("https://github.com/YakinAnd/morok")
	},
}

var kerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Analyze Kerberoastable and AS-REP roastable accounts",
	Example: `  morok kerberos -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok kerberos -d corp.local --ccache /tmp/admin.ccache --dc 10.0.0.1`,
	RunE: runKerberos,
}

var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "Analyze dangerous ACL permissions in AD",
	Example: `  morok acl -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok acl -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --verbose`,
	RunE: runACL,
}

var delegationCmd = &cobra.Command{
	Use:   "delegation",
	Short: "Analyze dangerous delegation configurations in AD",
	Example: `  morok delegation -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok delegation -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1`,
	RunE: runDelegation,
}

var gpoCmd = &cobra.Command{
	Use:   "gpo",
	Short: "Analyze Group Policy Objects for security issues",
	Example: `  morok gpo -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1`,
	RunE:  runGPO,
}

var adcsCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Analyze Active Directory Certificate Services (ESC1-ESC8)",
	Example: `  morok adcs -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok adcs -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --verbose`,
	RunE: runADCS,
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Analyze domain/forest trusts and foreign security principals",
	Example: `  morok trust -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1`,
	RunE:  runTrust,
}

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Detect principals that can write msDS-KeyCredentialLink on privileged objects",
	Example: `  morok shadow -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1`,
	RunE:  runShadow,
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Check audit policy, AD Recycle Bin, and blue-team visibility settings",
	Example: `  morok audit -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1`,
	RunE:  runAudit,
}

var enumUsersCmd = &cobra.Command{
	Use:   "kerb-enum",
	Short: "Enumerate valid AD usernames via Kerberos AS-REQ (no credentials required)",
	Example: `  morok kerb-enum -d corp.local --dc 10.0.0.1 --wordlist /path/to/users.txt
  morok kerb-enum -d corp.local --dc 10.0.0.1 --wordlist /usr/share/seclists/Usernames/Names/names.txt`,
	RunE: runEnumUsers,
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate AD users and display a summary table",
	Example: `  morok users -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1
  morok users -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1 --verbose`,
	RunE: runUsers,
}

var computersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate AD computers and display a summary table",
	Example: `  morok computers -d corp.local -u administrator -p 'Password1' --dc 10.0.0.1`,
	RunE:  runComputers,
}

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Check SMB signing status on the domain controller (port 445)",
	Example: `  morok smb -d corp.local --dc 10.0.0.1
  morok smb -d corp.local --dc 10.0.0.1 -u administrator -p 'Password1'`,
	RunE: runSMB,
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
		cmd.Flags().BoolVar(&verbose, "verbose", false, "Show all findings without truncation (disables 5-item limit per section)")
		cmd.MarkFlagRequired("domain")
	}

	enumCmd.Flags().StringVar(&reportPath, "report", "", "Save HTML report to file (e.g. report.html)")
	enumCmd.Flags().StringVar(&jsonExportPath, "json", "", "Export AD objects as JSON to directory (e.g. json_out/)")
	enumCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum BFS depth for attack path search")
	enumCmd.Flags().BoolVar(&stealth, "stealth", false, "Stealth mode — minimal LDAP queries, no GC, no ACL/GPO/ADCS/delegation analysis")
	enumCmd.Flags().BoolVar(&quietMode, "quiet", false, "Quiet mode — print only risk verdict line (for CI/scripting)")

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

	// Version intentionally not set on rootCmd — use `adpath version` subcommand.
	// Setting rootCmd.Version would cause cobra to auto-add a duplicate -v/--version flag.
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
	client.Quiet = quietMode
	if scopeDN != "" {
		client.BaseDN = scopeDN
		if !quietMode {
			color.White("  %-28s %s", "scope", scopeDN)
		}
	}

	if proxyURL != "" && ccachePath != "" {
		return nil, fmt.Errorf("--proxy and --ccache cannot be used together: Kerberos ccache is not supported through SOCKS5 proxy")
	}

	if proxyURL != "" && !quietMode {
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
		if !quietMode {
			color.Yellow("  no credentials — anonymous bind (limited enumeration)")
		}
		if err := client.AnonymousBind(); err != nil {
			client.Close()
			return nil, fmt.Errorf("anonymous bind failed: %w", err)
		}
		if !quietMode {
			color.White("  %-28s %s", "RootDSE", "✓ readable")
			color.Yellow("  %-28s %s", "hint", "obtain any domain account for full enumeration")
		}
	}

	return client, nil
}

// ============================================================
// Логіка команди enum
// ============================================================

func runEnum(cmd *cobra.Command, args []string) error {
	startTime := time.Now()
	analysis.Quiet = quietMode
	if !quietMode {
		printBanner()
	}

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

	// ── tag all primary domain objects with their domain ─────
	for i := range result.Users {
		result.Users[i].SourceDomain = domain
	}
	for i := range result.Groups {
		result.Groups[i].SourceDomain = domain
	}
	for i := range result.Computers {
		if result.Computers[i].Domain == "" {
			result.Computers[i].Domain = domain
		}
	}

	// ── graph + attack paths ──────────────────────────────────
	g := graph.Build(result)
	paths := g.FindPathsToPrivilegedGroups(maxDepth)
	for i := range paths {
		paths[i].SourceDomain = domain
	}

	// ── analysis ─────────────────────────────────────────────
	kr := analysis.AnalyzeKerberos(result)
	for i := range kr.KerberoastableAccounts {
		kr.KerberoastableAccounts[i].SourceDomain = domain
	}
	for i := range kr.ASREPAccounts {
		kr.ASREPAccounts[i].SourceDomain = domain
	}
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
		if aclResult != nil {
			for i := range aclResult.Findings {
				aclResult.Findings[i].SourceDomain = domain
			}
			for i := range aclResult.DCSyncFindings {
				aclResult.DCSyncFindings[i].SourceDomain = domain
			}
		}
		dr, _ = analysis.AnalyzeDelegation(client, result)
		gr, _ = analysis.AnalyzeGPO(client)
		hr = analysis.AnalyzeHygiene(result)
		puResult = analysis.AnalyzeProtectedUsers(result)
		adminSDResult, _ = analysis.AnalyzeAdminSDHolder(client, result)
		psoResult, _ = analysis.AnalyzePSO(client)
		adcsResult, _ = analysis.AnalyzeADCS(client)
		if adcsResult != nil {
			for i := range adcsResult.TemplateFindings {
				adcsResult.TemplateFindings[i].SourceDomain = domain
			}
		}
		shadowResult, _ = analysis.AnalyzeShadowCredentials(client, result)
		if shadowResult != nil {
			for i := range shadowResult.Findings {
				shadowResult.Findings[i].SourceDomain = domain
			}
		}
		sysvolResult = analysis.ScanSYSVOL(client)
		lapsACLResult, _ = analysis.AnalyzeLAPSACL(client, result)
	}

	// ── Trusted domain enumeration (Variant A — follow trusts automatically) ──
	var trustedData []*trustedDomainData
	if trustResult != nil && !stealth {
		for _, t := range trustResult.Trusts {
			if t.Direction == analysis.TrustDirectionDisabled {
				continue
			}
			if !t.IsWithinForest && t.Direction != analysis.TrustDirectionBidirectional {
				continue
			}
			if !quietMode {
				color.White("  querying %s...", t.Name)
			}
			trustedData = append(trustedData, enumerateTrustedDomain(t.Name, result))
		}
	}
	// build simplified list for HTML Trusts tab (only failed domains shown)
	var trustedResults []*report.TrustedDomainEnumResult
	for _, td := range trustedData {
		if td.Error != "" {
			trustedResults = append(trustedResults, &report.TrustedDomainEnumResult{Domain: td.Domain, Error: td.Error})
		}
	}

	// ── Merge trusted domain findings into main result ────────────
	for _, td := range trustedData {
		if td.Error != "" {
			continue
		}
		result.Users = append(result.Users, td.Users...)
		result.Groups = append(result.Groups, td.Groups...)
		result.Computers = append(result.Computers, td.Computers...)
		if kr != nil && td.KerberosResult != nil {
			kr.KerberoastableAccounts = append(kr.KerberoastableAccounts, td.KerberosResult.KerberoastableAccounts...)
			kr.ASREPAccounts = append(kr.ASREPAccounts, td.KerberosResult.ASREPAccounts...)
		}
		if aclResult != nil && td.ACLResult != nil {
			aclResult.Findings = append(aclResult.Findings, td.ACLResult.Findings...)
			aclResult.DCSyncFindings = append(aclResult.DCSyncFindings, td.ACLResult.DCSyncFindings...)
		}
		if shadowResult != nil && td.ShadowCredsResult != nil {
			shadowResult.Findings = append(shadowResult.Findings, td.ShadowCredsResult.Findings...)
		} else if shadowResult == nil && td.ShadowCredsResult != nil && len(td.ShadowCredsResult.Findings) > 0 {
			shadowResult = &analysis.ShadowCredentialsResult{Domain: domain}
			shadowResult.Findings = append(shadowResult.Findings, td.ShadowCredsResult.Findings...)
		}
		paths = append(paths, td.AttackPaths...)
	}

	// ── Compute risk totals (single source of truth for CLI + HTML) ──
	cliRiskData := &report.ReportData{
		AttackPaths:             paths,
		ACLResult:               aclResult,
		KerberosResult:          kr,
		DelegationResult:        dr,
		ADCSResult:              adcsResult,
		HygieneResult:           hr,
		ShadowCredentialsResult: shadowResult,
		LDAPSecurityResult:      ldapSecResult,
		SMBSigningResult:        smbResult,
		GPOResult:               gr,
		AdminSDHolderResult:     adminSDResult,
		TrustResult:             trustResult,
	}
	if result != nil {
		for _, c := range result.Computers {
			if c.Enabled && !c.LAPSEnabled {
				cliRiskData.Summary.NoLAPSCount++
			}
		}
	}
	if gr != nil && gr.DefaultPolicy != nil {
		pp := gr.DefaultPolicy
		cliRiskData.Summary.WeakPasswordPolicy = pp.MinLength < 8 || !pp.Complexity || pp.LockoutThreshold == 0
	}
	cliCrit, cliHigh, cliMed := report.CountRiskTotals(cliRiskData)
	cliRiskScore := report.CalculateRiskScore(cliRiskData)

	// ── Variant A terminal output ─────────────────────────────
	printEnumSummary(rdsInfo, result, paths, kr, aclResult, adcsResult, shadowResult, smbResult, hr, ldapSecResult, auditResult, trustResult, trustedResults, cliCrit, cliHigh, cliMed, cliRiskScore)

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
		if err := report.Generate(outPath, result, g, paths, kr, aclResult, dr, gr, hr, psoResult, adcsResult, puResult, adminSDResult, trustResult, shadowResult, ldapSecResult, auditResult, smbResult, sysvolResult, lapsACLResult, trustedResults, authMethod); err != nil {
			return fmt.Errorf("report error: %w", err)
		}
		if !quietMode {
			fmt.Println()
			color.Cyan("  REPORT")
			color.White("  %-28s %s", "saved to", outPath)
		}
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

	// ── Timing footer ─────────────────────────────────────────
	if !quietMode {
		fmt.Println()
		color.White("  %s", dimText(fmt.Sprintf("enumeration completed in %s", fmtDuration(time.Since(startTime)))))
	}

	return nil
}

// ============================================================
// Trusted domain enumeration helpers (Variant A — follow trusts)
// ============================================================

// trustedDomainData holds full enumeration results from a trusted domain before merging.
type trustedDomainData struct {
	Domain              string
	Error               string
	Users               []adldap.LDAPUser
	Groups              []adldap.LDAPGroup
	Computers           []adldap.LDAPComputer
	KerberosResult      *analysis.KerberosResult
	ACLResult           *analysis.ACLResult
	AttackPaths         []graph.AttackPath
	ShadowCredsResult   *analysis.ShadowCredentialsResult
}

// enumerateTrustedDomain connects to a trusted domain using the same credentials
// and runs a full enumeration. Returns a result struct (never nil).
func enumerateTrustedDomain(trustDomain string, primaryResult *adldap.EnumerationResult) *trustedDomainData {
	tr := &trustedDomainData{Domain: trustDomain}

	client := adldap.NewClient(trustDomain, username, password, "", verbose)
	client.NTHash = ntHash
	client.CcachePath = ccachePath
	client.ProxyURL = proxyURL
	client.Quiet = true
	client.PrimaryDomain = domain // authenticate with primary domain credentials

	if err := client.Connect(); err != nil {
		tr.Error = fmt.Sprintf("connection failed: %v", err)
		return tr
	}
	defer client.Close()

	var bindErr error
	switch {
	case ccachePath != "":
		bindErr = client.BindKerberos()
	case ntHash != "":
		bindErr = client.BindNTLM()
	case username != "":
		bindErr = client.Bind()
	default:
		bindErr = client.AnonymousBind()
	}
	if bindErr != nil {
		tr.Error = fmt.Sprintf("auth failed: %v", bindErr)
		return tr
	}

	result, err := client.EnumerateAll()
	if err != nil {
		tr.Error = fmt.Sprintf("enumeration failed: %v", err)
		return tr
	}

	// tag all objects with their source domain
	for i := range result.Users {
		result.Users[i].SourceDomain = trustDomain
	}
	for i := range result.Groups {
		result.Groups[i].SourceDomain = trustDomain
	}
	for i := range result.Computers {
		if result.Computers[i].Domain == "" {
			result.Computers[i].Domain = trustDomain
		}
	}

	kr := analysis.AnalyzeKerberos(result)
	for i := range kr.KerberoastableAccounts {
		kr.KerberoastableAccounts[i].SourceDomain = trustDomain
	}
	for i := range kr.ASREPAccounts {
		kr.ASREPAccounts[i].SourceDomain = trustDomain
	}

	aclRes, aclErr := analysis.AnalyzeACL(client, result, primaryResult)
	if aclErr != nil {
		color.Yellow("    [trust/%s] ACL search failed: %v", trustDomain, aclErr)
	} else if aclRes != nil {
		color.White("    [trust/%s] ACL: %d findings, %d DCSync", trustDomain, len(aclRes.Findings), len(aclRes.DCSyncFindings))
		for i := range aclRes.Findings {
			aclRes.Findings[i].SourceDomain = trustDomain
		}
		for i := range aclRes.DCSyncFindings {
			aclRes.DCSyncFindings[i].SourceDomain = trustDomain
		}
	}

	g := graph.Build(result)
	attackPaths := g.FindPathsToPrivilegedGroups(maxDepth)
	for i := range attackPaths {
		attackPaths[i].SourceDomain = trustDomain
	}

	shadowRes, _ := analysis.AnalyzeShadowCredentials(client, result)
	if shadowRes != nil {
		for i := range shadowRes.Findings {
			shadowRes.Findings[i].SourceDomain = trustDomain
		}
	}

	tr.Users = result.Users
	tr.Groups = result.Groups
	tr.Computers = result.Computers
	tr.KerberosResult = kr
	tr.ACLResult = aclRes
	tr.AttackPaths = attackPaths
	tr.ShadowCredsResult = shadowRes
	return tr
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

// truncateTargets joins targets, breaking only on item boundaries and appending "+N more"
// when the combined string would exceed maxLen. Never cuts mid-word.
func truncateTargets(targets []string, maxLen int) string {
	if len(targets) == 0 {
		return ""
	}
	const sep = ", "
	var included []string
	total := 0
	for i, t := range targets {
		addLen := len(t)
		if i > 0 {
			addLen += len(sep)
		}
		remaining := len(targets) - i - 1
		suffix := ""
		if remaining > 0 {
			suffix = fmt.Sprintf(", +%d more", remaining)
		}
		if total+addLen+len(suffix) > maxLen && len(included) > 0 {
			return strings.Join(included, sep) + fmt.Sprintf(", +%d more", len(targets)-len(included))
		}
		included = append(included, t)
		total += addLen
	}
	return strings.Join(included, sep)
}

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

// fmtDuration formats elapsed time as Xms / X.Xs / XmYs.
func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

// riskVerdict maps a risk grade to a verbal severity label.
func riskVerdict(s report.RiskScore) string {
	switch s.Grade {
	case "F":
		return "CRITICAL"
	case "D":
		return "HIGH"
	case "C":
		return "MEDIUM"
	case "B":
		return "LOW"
	case "A":
		return "MINIMAL"
	}
	return "UNKNOWN"
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
	trustResult *analysis.TrustResult,
	trustedResults []*report.TrustedDomainEnumResult,
	critTotal, highTotal, medTotal int,
	riskScore report.RiskScore,
) {
	// Quiet mode: single machine-readable line for CI
	if quietMode {
		verdict := riskVerdict(riskScore)
		fmt.Printf("RISK %s (%s · %d/100) — %d critical, %d high, %d medium\n",
			verdict, riskScore.Grade, riskScore.Total, critTotal, highTotal, medTotal)
		return
	}

	// Verbose mode disables per-section truncation
	limit := enumMaxItems
	if verbose {
		limit = 0 // 0 = no limit (checked with: limit > 0 && shown >= limit)
	}

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

	// ── DOMAIN SUMMARY one-liner ──────────────────────────────
	if result != nil {
		adminCount := 0
		for _, u := range result.Users {
			if u.AdminCount {
				adminCount++
			}
		}
		trustCount := 0
		if trustResult != nil {
			trustCount = len(trustResult.Trusts)
		}
		aclCount := 0
		if acl != nil {
			aclCount = len(acl.Findings) + len(acl.DCSyncFindings)
		}
		adcsCount := 0
		if adcs != nil {
			adcsCount = len(adcs.TemplateFindings)
			for _, cf := range adcs.CAFindings {
				if !cf.Unverified {
					adcsCount++
				}
			}
		}
		krbtgtAge := 0
		if hr != nil {
			krbtgtAge = hr.KrbtgtPwdAgeDays
		}
		trustSuffix := ""
		if trustCount > 0 {
			trustSuffix = fmt.Sprintf(" · %d trust(s)", trustCount)
		}
		fmt.Println()
		color.Cyan("  SUMMARY")
		color.White("  %s · %d users · %d computers · %d groups · %d admins%s",
			domain, len(result.Users), len(result.Computers), len(result.Groups), adminCount, trustSuffix)
		color.White("  %d attack paths · %d ACL findings · %d ADCS · krbtgt: %dd",
			len(paths), aclCount, adcsCount, krbtgtAge)
	}

	// ── TRUSTED DOMAIN SKIP MESSAGES ─────────────────────────
	for _, tr := range trustedResults {
		fmt.Printf("\n  %s  %s — skipped (auth failed, provide creds for this domain)\n",
			medPrefix("[-]"), tr.Domain)
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
				fmt.Printf("  %s  %-20s %d accounts  %s\n", medPrefix("[-]"), "stale (>90d)", len(hr.StaleUsers), dimText("no logon · CIS: 90d threshold"))
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
				fmt.Printf("  %s  %-20s %d hosts  %s\n", medPrefix("[-]"), "stale (>45d)", len(hr.StaleComputers), dimText("no logon · CIS: 45d threshold"))
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

	// ── ACL (grouped by principal) ────────────────────────────
	if acl != nil && (len(acl.Findings) > 0 || len(acl.DCSyncFindings) > 0) {
		fmt.Println()
		aclCrit, aclHigh := 0, 0
		for _, f := range acl.Findings {
			if f.Severity == "Critical" {
				aclCrit++
			} else {
				aclHigh++
			}
		}
		aclCrit += len(acl.DCSyncFindings)
		color.Cyan("  ACL      %s", dimText(fmt.Sprintf("%d critical · %d high", aclCrit, aclHigh)))

		// group: principal → right → []targets
		type aclEntry struct {
			rights map[string][]string
			sev    string
		}
		groups := make(map[string]*aclEntry)
		var groupOrder []string
		addGroup := func(principal, right, target, sev string) {
			if _, ok := groups[principal]; !ok {
				groups[principal] = &aclEntry{rights: make(map[string][]string), sev: sev}
				groupOrder = append(groupOrder, principal)
			}
			g := groups[principal]
			g.rights[right] = append(g.rights[right], target)
			if sev == "Critical" {
				g.sev = "Critical"
			}
		}
		for _, f := range acl.DCSyncFindings {
			addGroup(f.PrincipalName, "DCSync", domain, "Critical")
		}
		for _, f := range acl.Findings {
			if strings.TrimSpace(f.TargetName) == "" {
				continue // skip unresolvable targets
			}
			addGroup(f.PrincipalName, string(f.Right), f.TargetName, f.Severity)
		}
		shown := 0
		for _, name := range groupOrder {
			if limit > 0 && shown >= limit {
				break
			}
			g := groups[name]
			// Check if this principal has any non-empty targets
			hasValid := false
			for _, targets := range g.rights {
				for _, t := range targets {
					if strings.TrimSpace(t) != "" {
						hasValid = true
						break
					}
				}
				if hasValid {
					break
				}
			}
			if !hasValid {
				continue
			}
			pfx := highPrefix("[!] ")
			if g.sev == "Critical" {
				pfx = critPrefix("[!!]")
			}
			fmt.Printf("  %s  %s\n", pfx, name)
			for right, targets := range g.rights {
				// Filter empty targets (unresolved SIDs)
				valid := make([]string, 0, len(targets))
				for _, t := range targets {
					if strings.TrimSpace(t) != "" {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					continue
				}
				var targetStr string
				if verbose {
					targetStr = strings.Join(valid, ", ")
				} else {
					targetStr = truncateTargets(valid, 70)
				}
				fmt.Printf("        %-20s → %s\n", dimText(right), targetStr)
			}
			shown++
		}
		if limit > 0 && len(groups) > limit {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: morok acl -d %s ...)", len(groups)-limit, domain)))
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
			if limit > 0 && shown >= limit {
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
			fmt.Printf("  %s  %-18s %s\n", pfx, f.TemplateName, dimText("("+escLabel+")"))
			shown++
		}
		if limit > 0 && len(adcs.TemplateFindings) > limit {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: morok adcs -d %s ...)", len(adcs.TemplateFindings)-limit, domain)))
		}
	}

	// ── SHADOW CREDENTIALS (grouped by principal) ─────────────
	if shadow != nil && len(shadow.Findings) > 0 {
		fmt.Println()
		color.Cyan("  SHADOW CREDS  %s  %s",
			dimText(fmt.Sprintf("%d finding(s)", len(shadow.Findings))),
			dimText("(detection only — exploit: pywhisker / certipy shadow)"))

		// group by principal → []targets
		shadowGroups := make(map[string][]string)
		var shadowOrder []string
		for _, f := range shadow.Findings {
			if _, ok := shadowGroups[f.PrincipalName]; !ok {
				shadowOrder = append(shadowOrder, f.PrincipalName)
			}
			shadowGroups[f.PrincipalName] = append(shadowGroups[f.PrincipalName], f.TargetName)
		}
		shown := 0
		for _, name := range shadowOrder {
			if limit > 0 && shown >= limit {
				break
			}
			fmt.Printf("  %s  %s\n", critPrefix("[!!]"), name)
			var targetStr string
			if verbose {
				targetStr = strings.Join(shadowGroups[name], ", ")
			} else {
				targetStr = truncateTargets(shadowGroups[name], 70)
			}
			fmt.Printf("        %s %s\n", dimText("→"), targetStr)
			shown++
		}
		if limit > 0 && len(shadowOrder) > limit {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more — run: morok shadow -d %s ...)", len(shadowOrder)-limit, domain)))
		}
	}

	// ── ATTACK PATHS ──────────────────────────────────────────
	if len(paths) > 0 {
		fmt.Println()
		color.Cyan("  ATTACK PATHS  %s", dimText(fmt.Sprintf("%d found", len(paths))))
		shown := 0
		for _, p := range paths {
			if limit > 0 && shown >= limit {
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
		if limit > 0 && len(paths) > limit {
			fmt.Printf("  %s\n", dimText(fmt.Sprintf("       (+%d more)", len(paths)-limit)))
		}
	} else if result != nil {
		fmt.Println()
		color.Cyan("  ATTACK PATHS  %s", dimText("0 found"))
	}

	// ── RISK SUMMARY ──────────────────────────────────────────
	fmt.Println()
	color.White("  " + strings.Repeat("─", 60))

	verdict := riskVerdict(riskScore)
	scoreColor := color.New(color.FgGreen)
	switch riskScore.Grade {
	case "F":
		scoreColor = color.New(color.FgRed, color.Bold)
	case "D":
		scoreColor = color.New(color.FgRed)
	case "C":
		scoreColor = color.New(color.FgYellow)
	case "B":
		scoreColor = color.New(color.FgCyan)
	}

	fmt.Printf("  RISK  ")
	scoreColor.Printf("%s  (%s · %d/100)", verdict, riskScore.Grade, riskScore.Total)
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

    dr, err := analysis.AnalyzeDelegation(client, nil)
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
	color.New(color.FgYellow, color.Bold).Println(`  MOROK`)
	color.New(color.FgHiBlack).Println(`  AD attack path enumerator  ·  v1.0`)
	color.New(color.FgHiBlack).Println(`  see through the fog`)
	color.New(color.FgHiBlack).Println(`  ` + strings.Repeat("─", 40))
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