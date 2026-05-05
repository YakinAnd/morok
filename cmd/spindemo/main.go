package main

import (
	"fmt"
	"time"

	"github.com/YakinAnd/adpath/internal/spinner"
	"github.com/fatih/color"
)

func main() {
	bold := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgWhite, color.Faint)
	green := color.New(color.FgGreen)

	bold.Println("\n  adpath v0.9.4  —  Active Directory path analysis")
	dim.Println("  domain: corp.local  |  dc: 10.0.0.1  |  user: pentest")
	fmt.Println()
	dim.Println("  enumerating objects...")
	time.Sleep(600 * time.Millisecond)
	dim.Println("  found 312 users, 47 groups, 28 computers")
	fmt.Println()

	spin := spinner.New("analyzing 387 objects...")
	spin.Start()
	time.Sleep(3 * time.Second)
	spin.Stop()

	fmt.Println()
	green.Println("  [+] Kerberoastable accounts  : 4")
	green.Println("  [+] AS-REP roastable          : 2")
	green.Println("  [+] Dangerous ACLs            : 11")
	green.Println("  [+] Delegation issues         : 3")
	green.Println("  [+] ADCS findings             : 2 (ESC1 Critical)")
	fmt.Println()
	dim.Println("  report saved → report_corp.local.html")
	fmt.Println()
}
