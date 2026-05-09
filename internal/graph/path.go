package graph

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// ============================================================
// BFS attack path search
// ============================================================

// privilegedGroups lists all high-value AD groups to search paths to.
var privilegedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Backup Operators",
	"Account Operators",
	"Server Operators",
	"Print Operators",
	"DNSAdmins",
	"Group Policy Creator Owners",
}

// FindPathsToDA finds paths to Domain Admins (backward compat).
func (g *Graph) FindPathsToDA(maxDepth int) []AttackPath {
	return g.findPathsToGroup("Domain Admins", maxDepth, 200)
}

// FindPathsToPrivilegedGroups finds paths to all privileged groups.
func (g *Graph) FindPathsToPrivilegedGroups(maxDepth int) []AttackPath {
	if maxDepth <= 0 {
		maxDepth = 10
	}

	var all []AttackPath
	for _, groupName := range privilegedGroups {
		paths := g.findPathsToGroup(groupName, maxDepth, 50)
		all = append(all, paths...)
	}
	return all
}

// findPathsToGroup is the common BFS runner for a named group.
func (g *Graph) findPathsToGroup(groupName string, maxDepth, limit int) []AttackPath {
	targetDN := g.findBySAM(groupName)
	if targetDN == "" {
		return nil
	}

	var allPaths []AttackPath
	for dn, node := range g.Nodes {
		if strings.EqualFold(dn, targetDN) {
			continue
		}
		if !node.Enabled && node.Type != NodeGroup {
			continue
		}
		paths := g.bfs(dn, targetDN, maxDepth)
		for i := range paths {
			paths[i].TargetGroup = groupName
		}
		allPaths = append(allPaths, paths...)
		if len(allPaths) >= limit {
			break
		}
	}


	return allPaths
}

// FindPathsToTarget finds paths to an arbitrary node by SAMAccountName.
func (g *Graph) FindPathsToTarget(targetSAM string, maxDepth int) []AttackPath {
	targetDN := g.findBySAM(targetSAM)
	if targetDN == "" {
		color.White("  target '%s' not found in graph", targetSAM)
		return nil
	}


	if maxDepth <= 0 {
		maxDepth = 10
	}

	var allPaths []AttackPath

	for dn := range g.Nodes {
		if strings.EqualFold(dn, targetDN) {
			continue
		}
		paths := g.bfs(dn, targetDN, maxDepth)
		allPaths = append(allPaths, paths...)

		if len(allPaths) >= 200 {
			break
		}
	}

	return allPaths
}

// ============================================================
// BFS — core traversal algorithm
// ============================================================

// bfsState holds the traversal state for a single node.
type bfsState struct {
	dn    string  // current DN
	path  []Edge  // edges that led here
	depth int     // current depth
}

// bfs performs a breadth-first search from startDN to targetDN.
func (g *Graph) bfs(startDN, targetDN string, maxDepth int) []AttackPath {
	var foundPaths []AttackPath

	// Track visited DNs per-path (not globally) so all paths are found.
	queue := []bfsState{
		{dn: startDN, path: []Edge{}, depth: 0},
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		for _, edge := range g.Adj[current.dn] {
			// skip if this node is already on the current path
			if pathContains(current.path, edge.To) {
				continue
			}

			// build new path = previous path + current edge
			newPath := make([]Edge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			if strings.EqualFold(edge.To, targetDN) {
				ap := g.buildAttackPath(newPath)
				foundPaths = append(foundPaths, ap)
				continue // keep searching for other paths
			}

			queue = append(queue, bfsState{
				dn:    edge.To,
				path:  newPath,
				depth: current.depth + 1,
			})
		}
	}

	return foundPaths
}

// buildAttackPath assembles an AttackPath from an edge list.
func (g *Graph) buildAttackPath(edges []Edge) AttackPath {
	nodeMap := make(map[string]bool)
	var nodes []Node

	for _, edge := range edges {
		if !nodeMap[edge.From] {
			if n := g.GetNode(edge.From); n != nil {
				nodes = append(nodes, *n)
				nodeMap[edge.From] = true
			}
		}
		if !nodeMap[edge.To] {
			if n := g.GetNode(edge.To); n != nil {
				nodes = append(nodes, *n)
				nodeMap[edge.To] = true
			}
		}
	}

	return AttackPath{
		Nodes: nodes,
		Edges: edges,
		Depth: len(edges),
	}
}

// ============================================================
// Helper functions
// ============================================================

// findBySAM returns the DN of an object by SAMAccountName.
func (g *Graph) findBySAM(sam string) string {
	for dn, node := range g.Nodes {
		if strings.EqualFold(node.SAMAccountName, sam) {
			return dn
		}
	}
	return ""
}

// pathContains reports whether the given DN is already on the path (cycle guard).
func pathContains(path []Edge, dn string) bool {
	for _, edge := range path {
		if strings.EqualFold(edge.From, dn) ||
			strings.EqualFold(edge.To, dn) {
			return true
		}
	}
	return false
}

// PrintPaths prints discovered attack paths to the terminal.
func (g *Graph) PrintPaths(paths []AttackPath) {
	color.Cyan("\n  ATTACK PATHS")
	if len(paths) == 0 {
		color.White("  none found")
		return
	}
	color.Red("  %d path(s) to privileged groups\n", len(paths))

	for i, path := range paths {
		target := path.TargetGroup
		if target == "" {
			target = "Domain Admins"
		}
		color.Red("  #%-3d → %-30s  depth: %d", i+1, target, path.Depth)

		for j, node := range path.Nodes {
			prefix := "  │   ├─"
			if j == len(path.Nodes)-1 {
				prefix = "  │   └─"
			}
			extras := ""
			if node.Type == NodeUser || node.Type == NodeComputer {
				extras = nodeExtras(node)
			}
			typeTag := strings.ToUpper(string(node.Type))
			color.White("%s [%-8s] %s%s", prefix, typeTag, node.SAMAccountName, extras)

			if j < len(path.Edges) {
				color.White("  │        via %s", path.Edges[j].Type)
			}
		}
		fmt.Println()
	}
}

// nodeExtras returns a bracketed string of node flags.
func nodeExtras(node Node) string {
	var extras []string
	if node.Kerberoastable {
		extras = append(extras, "KERBEROASTABLE")
	}
	if node.ASREPRoastable {
		extras = append(extras, "ASREP")
	}
	if node.PasswordNeverExpires {
		extras = append(extras, "PWD_NEVER_EXPIRES")
	}
	if node.UnconstrainedDelegation {
		extras = append(extras, "UNCONSTRAINED_DELEG")
	}
	if node.AdminCount {
		extras = append(extras, "ADMINCOUNT")
	}
	if len(extras) == 0 {
		return ""
	}
	return " [" + strings.Join(extras, ", ") + "]"
}