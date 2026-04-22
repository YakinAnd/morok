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
	bloodhoundPath string // --bloodhound: output dir for BloodHound CE JSON
	maxDepth       int
	verbose        bool
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
		color.Cyan("adpath v0.9.4")
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

// ============================================================
// Реєстрація флагів
// ============================================================

func init() {
	for _, cmd := range []*cobra.Command{enumCmd, kerberosCmd, aclCmd, delegationCmd, gpoCmd, adcsCmd, trustCmd, shadowCmd, auditCmd} {
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
	enumCmd.Flags().StringVar(&bloodhoundPath, "bloodhound", "", "Export BloodHound CE JSON to directory (e.g. bh_out/)")
	enumCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum BFS depth for attack path search")

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

	rootCmd.Version = "0.9.4"
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

	// ── RootDSE (no auth required) ────────────────────────────
	var ldapSecResult *analysis.LDAPSecurityResult
	var auditResult *analysis.AuditResult
	if rds, err := client.QueryRootDSE(); err == nil {
		color.Cyan("\n  DOMAIN INFO")
		color.White("  %-28s %s", "domain", rds.DefaultNamingContext)
		color.White("  %-28s %s", "forest", rds.ForestNamingContext)
		color.White("  %-28s %s  (%s)", "domain level",
			rds.DomainFunctionality,
			adldap.FunctionalityLevelName(rds.DomainFunctionality))
		color.White("  %-28s %s", "responding DC", rds.ServerName)
		ldapSecResult = analysis.AnalyzeLDAPSecurity(client, rds)
		analysis.LDAPSecuritySummaryLine(ldapSecResult)
		auditResult = analysis.AnalyzeAuditPolicy(client, rds)
		analysis.AuditSummaryLine(auditResult)
	}

	// ── enumeration ───────────────────────────────────────────
	result, err := client.EnumerateAll()
	if err != nil {
		return fmt.Errorf("enumeration error: %w", err)
	}

	// ── граф + attack paths ───────────────────────────────────
	g := graph.Build(result)
	nodes, edges := g.Stats()
	color.Cyan("\n  GRAPH")
	color.White("  %-12s %d", "nodes", nodes)
	color.White("  %-12s %d", "edges", edges)

	paths := g.FindPathsToPrivilegedGroups(maxDepth)
	g.PrintPaths(paths)

	// ── аналіз ───────────────────────────────────────────────
	outPath := resolveReportPath(reportPath, domain)

	kr := analysis.AnalyzeKerberos(result)

	aclResult, err := analysis.AnalyzeACL(client, result)
	if err != nil {
		color.Yellow("  acl analysis failed: %v", err)
		aclResult = nil
	}

	dr, err := analysis.AnalyzeDelegation(client)
	if err != nil {
		color.Yellow("  delegation analysis failed: %v", err)
		dr = nil
	}

	gr, err := analysis.AnalyzeGPO(client)
	if err != nil {
		color.Yellow("  gpo analysis failed: %v", err)
		gr = nil
	}

	hr := analysis.AnalyzeHygiene(result)

	puResult := analysis.AnalyzeProtectedUsers(result)

	adminSDResult, err := analysis.AnalyzeAdminSDHolder(client, result)
	if err != nil {
		color.Yellow("  adminsdholder analysis failed: %v", err)
		adminSDResult = nil
	}

	trustResult, err := analysis.AnalyzeTrusts(client, result)
	if err != nil {
		color.Yellow("  trust analysis failed: %v", err)
		trustResult = nil
	}

	psoResult, err := analysis.AnalyzePSO(client)
	if err != nil {
		color.Yellow("  pso analysis failed: %v", err)
		psoResult = nil
	}

	adcsResult, err := analysis.AnalyzeADCS(client)
	if err != nil {
		color.Yellow("  adcs analysis failed: %v", err)
		adcsResult = nil
	}
	if adcsResult != nil {
		analysis.PrintADCSResultSummary(adcsResult)
	}

	shadowResult, err := analysis.AnalyzeShadowCredentials(client, result)
	if err != nil {
		color.Yellow("  shadow credentials analysis failed: %v", err)
		shadowResult = nil
	}
	analysis.AnalyzeShadowCredentialsSummary(shadowResult)

	authMethod := "Password"
	switch {
	case ccachePath != "":
		authMethod = "PTT (Kerberos ccache)"
	case ntHash != "":
		authMethod = "PTH (NTLM hash)"
	case username == "":
		authMethod = "Anonymous"
	}

	if err := report.Generate(outPath, result, g, paths, kr, aclResult, dr, gr, hr, psoResult, adcsResult, puResult, adminSDResult, trustResult, shadowResult, ldapSecResult, auditResult, authMethod); err != nil {
		return fmt.Errorf("report error: %w", err)
	}

	if bloodhoundPath != "" {
		if err := bloodhound.Export(bloodhoundPath, result); err != nil {
			color.Yellow("  bloodhound export failed: %v", err)
		} else {
			color.Cyan("\n  BLOODHOUND EXPORT")
			color.White("  %-28s %s", "output dir", bloodhoundPath)
			color.White("  %-28s %s", "files", "users.json, groups.json, computers.json, domains.json")
			color.White("  %-28s %s", "import", "BloodHound CE → Administration → File Ingest")
		}
	}

	return nil
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
	_ = r
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
// Banner
// ============================================================

func printBanner() {
	color.Cyan(`    _      ____    ____      _      _____   _   _`)
	color.Cyan(`   / \    |  _ \  |  _ \    / \    |_   _| | | | |`)
	color.Cyan(`  / _ \   | | | | | |_) |  / _ \     | |   | |_| |`)
	color.Cyan(` / ___ \  | |_| | |  __/  / ___ \    | |   |  _  |`)
	color.Cyan(`/_/   \_\ |____/  |_|    /_/   \_\   |_|   |_| |_|`)
	color.White(``)
	color.White(`  v0.9.4  //  AD Attack Path Enumerator made by M4t`)
	color.White(`  ` + strings.Repeat("─", 40))
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