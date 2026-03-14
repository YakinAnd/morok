package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/YakinAnd/adpath/internal/analysis"
	"github.com/YakinAnd/adpath/internal/graph"
	adldap "github.com/YakinAnd/adpath/internal/ldap"
	"github.com/YakinAnd/adpath/internal/report"
)

// ============================================================
// Глобальні змінні для CLI флагів
// ============================================================

var (
	domain     string
	username   string
	password   string
	dc         string
	reportPath string
	maxDepth   int
	verbose    bool
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
		color.Cyan("adpath v0.1.0")
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

// ============================================================
// Реєстрація флагів
// ============================================================

func init() {
	enumCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	enumCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	enumCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	enumCmd.Flags().StringVar(&dc, "dc", "", "Domain controller IP or hostname")
	enumCmd.Flags().StringVar(&reportPath, "report", "", "Save HTML report to file (e.g. report.html)")
	enumCmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum BFS depth for attack path search")
	enumCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	enumCmd.MarkFlagRequired("domain")

	kerberosCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
  kerberosCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
  kerberosCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
  kerberosCmd.Flags().StringVar(&dc, "dc", "", "Domain controller IP or hostname")
  kerberosCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	kerberosCmd.MarkFlagRequired("domain")

	aclCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (required)")
	aclCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	aclCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	aclCmd.Flags().StringVar(&dc, "dc", "", "Domain controller IP or hostname")
	aclCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	aclCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(aclCmd)
	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(kerberosCmd)

	rootCmd.Version = "0.1.0"
}

// ============================================================
// Логіка команди enum
// ============================================================

func runEnum(cmd *cobra.Command, args []string) error {
	printBanner()

	// ── підключення ──────────────────────────────────────────
	client := adldap.NewClient(domain, username, password, dc, verbose)

	if err := client.Connect(); err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer client.Close()

	// ── автентифікація ────────────────────────────────────────
	if username != "" {
		if err := client.Bind(); err != nil {
			return fmt.Errorf("auth error: %w", err)
		}
	} else {
		color.Yellow("[!] No credentials provided, trying anonymous bind...")
		if err := client.AnonymousBind(); err != nil {
			return fmt.Errorf("anonymous bind failed: %w", err)
		}
	}

	color.Green("[+] BaseDN: %s", client.GetBaseDN())

	// ── enumeration ───────────────────────────────────────────
	result, err := client.EnumerateAll()
	if err != nil {
		return fmt.Errorf("enumeration error: %w", err)
	}

	// ── побудова графа ────────────────────────────────────────
	g := graph.Build(result)
	nodes, edges := g.Stats()
	color.Blue("[*] Graph: %d nodes, %d edges", nodes, edges)

	// ── пошук attack paths ────────────────────────────────────
	paths := g.FindPathsToDA(maxDepth)
	g.PrintPaths(paths)

	// ── HTML звіт (опціонально) ───────────────────────────────
	if reportPath != "" {
		if err := report.Generate(reportPath, result, g, paths); err != nil {
			return fmt.Errorf("report error: %w", err)
		}
	}

	return nil
}


// ============================================================
// Логіка команди Kerberoasting
// ============================================================
func runKerberos(cmd *cobra.Command, args []string) error {
    printBanner()

    // підключення
    client := adldap.NewClient(domain, username, password, dc, verbose)
    if err := client.Connect(); err != nil {
        return fmt.Errorf("connection error: %w", err)
    }
    defer client.Close()

    // автентифікація
    if username != "" {
        if err := client.Bind(); err != nil {
            return fmt.Errorf("auth error: %w", err)
        }
    } else {
        color.Yellow("[!] No credentials provided, trying anonymous bind...")
        if err := client.AnonymousBind(); err != nil {
            return fmt.Errorf("anonymous bind failed: %w", err)
        }
    }

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

    client := adldap.NewClient(domain, username, password, dc, verbose)
    if err := client.Connect(); err != nil {
        return fmt.Errorf("connection error: %w", err)
    }
    defer client.Close()

    if username != "" {
        if err := client.Bind(); err != nil {
            return fmt.Errorf("auth error: %w", err)
        }
    } else {
        color.Yellow("[!] No credentials provided, trying anonymous bind...")
        if err := client.AnonymousBind(); err != nil {
            return fmt.Errorf("anonymous bind failed: %w", err)
        }
    }

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
// Banner
// ============================================================

func printBanner() {
	color.Cyan(`
  █████╗ ██████╗ ██████╗  █████╗ ████████╗██╗  ██╗
 ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
 ███████║██║  ██║██████╔╝███████║   ██║   ███████║
 ██╔══██║██║  ██║██╔═══╝ ██╔══██║   ██║   ██╔══██║
 ██║  ██║██████╔╝██║     ██║  ██║   ██║   ██║  ██║
 ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
   AD Attack Path Enumerator v0.1 by Ma43t3
`)
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