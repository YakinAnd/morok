package graph

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// ============================================================
// BFS пошук attack paths
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

// FindPathsToDA знаходить шляхи до Domain Admins (backward compat).
func (g *Graph) FindPathsToDA(maxDepth int) []AttackPath {
	return g.findPathsToGroup("Domain Admins", maxDepth, 200)
}

// FindPathsToPrivilegedGroups знаходить шляхи до всіх привілейованих груп.
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

// FindPathsToTarget знаходить шляхи до довільного вузла за SAMAccountName
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
// BFS — основний алгоритм обходу
// ============================================================

// bfsState зберігає стан одного вузла під час обходу
type bfsState struct {
	dn    string  // поточний DN
	path  []Edge  // шлях який привів сюди
	depth int     // поточна глибина
}

// bfs виконує пошук в ширину від startDN до targetDN
func (g *Graph) bfs(startDN, targetDN string, maxDepth int) []AttackPath {
	var foundPaths []AttackPath

	// visited — запобігає циклам: зберігаємо DN які вже відвідали
	// на поточному шляху (не глобально — щоб знайти всі шляхи)
	queue := []bfsState{
		{dn: startDN, path: []Edge{}, depth: 0},
	}

	for len(queue) > 0 {
		// беремо перший елемент з черги
		current := queue[0]
		queue = queue[1:]

		// досягли максимальної глибини — не йдемо далі
		if current.depth >= maxDepth {
			continue
		}

		// перебираємо всіх сусідів поточного вузла
		for _, edge := range g.Adj[current.dn] {
			// перевіряємо чи не було цього вузла вже на цьому шляху
			if pathContains(current.path, edge.To) {
				continue
			}

			// будуємо новий шлях = попередній + поточний edge
			newPath := make([]Edge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = edge

			// знайшли ціль
			if strings.EqualFold(edge.To, targetDN) {
				ap := g.buildAttackPath(newPath)
				foundPaths = append(foundPaths, ap)
				continue // продовжуємо шукати інші шляхи
			}

			// не знайшли — додаємо сусіда в чергу
			queue = append(queue, bfsState{
				dn:    edge.To,
				path:  newPath,
				depth: current.depth + 1,
			})
		}
	}

	return foundPaths
}

// buildAttackPath будує AttackPath struct зі списку edges
func (g *Graph) buildAttackPath(edges []Edge) AttackPath {
	// збираємо унікальні вузли вздовж шляху
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
// Допоміжні функції
// ============================================================

// findDomainAdmins шукає DN групи Domain Admins у графі
func (g *Graph) findDomainAdmins() string {
	for dn, node := range g.Nodes {
		if node.Type == NodeGroup &&
			strings.EqualFold(node.SAMAccountName, "Domain Admins") {
			return dn
		}
	}
	return ""
}

// findBySAM шукає DN об'єкта за SAMAccountName
func (g *Graph) findBySAM(sam string) string {
	for dn, node := range g.Nodes {
		if strings.EqualFold(node.SAMAccountName, sam) {
			return dn
		}
	}
	return ""
}

// pathContains перевіряє чи вже є DN у поточному шляху
// запобігає циклам типу A→B→C→B
func pathContains(path []Edge, dn string) bool {
	for _, edge := range path {
		if strings.EqualFold(edge.From, dn) ||
			strings.EqualFold(edge.To, dn) {
			return true
		}
	}
	return false
}

// PrintPaths виводить знайдені шляхи в термінал
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

// nodeExtras формує рядок з додатковими прапорами вузла
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