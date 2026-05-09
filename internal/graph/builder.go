package graph

import (
	"strings"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// Build constructs the graph from enumeration results.
func Build(result *adldap.EnumerationResult) *Graph {
	g := NewGraph()


	// --------------------------------------------------------
	// Step 1: add all nodes
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
			SourceDomain:         u.SourceDomain,
		})
	}

	for i := range result.Groups {
		grp := &result.Groups[i]
		g.AddNode(&Node{
			DN:             grp.DN,
			SAMAccountName: grp.SAMAccountName,
			Type:           NodeGroup,
			AdminCount:     grp.AdminCount,
			Enabled:        true, // groups have no disabled state
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
	// Step 2: add MemberOf edges
	// --------------------------------------------------------

	// users → groups
	for i := range result.Users {
		u := &result.Users[i]
		for _, groupDN := range u.MemberOf {
			// verify target group exists in the graph
			if _, exists := g.Nodes[groupDN]; exists {
				g.AddEdge(Edge{
					From: u.DN,
					To:   groupDN,
					Type: EdgeMemberOf,
				})
			}
		}
	}

	// groups → groups (nested membership)
	for i := range result.Groups {
		grp := &result.Groups[i]
		for _, memberDN := range grp.Members {
			// check if member is a group
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

	return g
}

// findComputerGroups returns groups that list the given computer as a member.
// AD does not always populate memberOf for computers — look up via groups.
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