package graph

import (
	"strings"

	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// Build будує граф з результатів enumeration
func Build(result *adldap.EnumerationResult) *Graph {
	g := NewGraph()

	color.Blue("[*] Building AD object graph...")

	// --------------------------------------------------------
	// Крок 1: додаємо всі вузли
	// --------------------------------------------------------
	for i := range result.Users {
		u := &result.Users[i]
		g.AddNode(&Node{
			DN:                   u.DN,
			SAMAccountName:       u.SAMAccountName,
			DisplayName:          u.DisplayName,
			Type:                 NodeUser,
			AdminCount:           u.AdminCount,
			Enabled:              u.Enabled,
			Kerberoastable:       len(u.SPNs) > 0,
			ASREPRoastable:       u.DontReqPreauth,
			PasswordNeverExpires: u.PasswordNeverExpires,
		})
	}

	for i := range result.Groups {
		grp := &result.Groups[i]
		g.AddNode(&Node{
			DN:             grp.DN,
			SAMAccountName: grp.SAMAccountName,
			Type:           NodeGroup,
			AdminCount:     grp.AdminCount,
			Enabled:        true, // групи не мають поняття "disabled"
		})
	}

	for i := range result.Computers {
		comp := &result.Computers[i]
		g.AddNode(&Node{
			DN:                      comp.DN,
			SAMAccountName:          comp.SAMAccountName,
			DisplayName:             comp.DNSHostName,
			Type:                    NodeComputer,
			Enabled:                 comp.Enabled,
			UnconstrainedDelegation: comp.UnconstrainedDelegation,
			Kerberoastable:          len(comp.SPNs) > 0,
		})
	}

	// --------------------------------------------------------
	// Крок 2: додаємо зв'язки MemberOf
	// --------------------------------------------------------

	// users → groups
	for i := range result.Users {
		u := &result.Users[i]
		for _, groupDN := range u.MemberOf {
			// перевіряємо що цільова група існує в нашому графі
			if _, exists := g.Nodes[groupDN]; exists {
				g.AddEdge(Edge{
					From: u.DN,
					To:   groupDN,
					Type: EdgeMemberOf,
				})
			}
		}
	}

	// groups → groups (вкладені групи)
	for i := range result.Groups {
		grp := &result.Groups[i]
		for _, memberDN := range grp.Members {
			// перевіряємо чи member є групою
			if node, exists := g.Nodes[memberDN]; exists {
				if node.Type == NodeGroup {
					g.AddEdge(Edge{
						From: memberDN,
						To:   grp.DN,
						Type: EdgeMemberOf,
					})
				}
			}
		}
	}

	// computers → groups
	for i := range result.Computers {
		comp := &result.Computers[i]
		for _, groupDN := range findComputerGroups(result, comp.DN) {
			if _, exists := g.Nodes[groupDN]; exists {
				g.AddEdge(Edge{
					From: comp.DN,
					To:   groupDN,
					Type: EdgeMemberOf,
				})
			}
		}
	}

	nodes, edges := g.Stats()
	color.Green("[+] Graph built: %d nodes, %d edges", nodes, edges)

	return g
}

// findComputerGroups шукає групи в яких є комп'ютер як member
// AD не завжди повертає memberOf для комп'ютерів — шукаємо через groups
func findComputerGroups(result *adldap.EnumerationResult, computerDN string) []string {
	var groups []string
	for _, grp := range result.Groups {
		for _, memberDN := range grp.Members {
			if strings.EqualFold(memberDN, computerDN) {
				groups = append(groups, grp.DN)
				break
			}
		}
	}
	return groups
}