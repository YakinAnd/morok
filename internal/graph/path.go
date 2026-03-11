package graph

import (
	"strings"

	"github.com/fatih/color"
)

// ============================================================
// BFS пошук attack paths
// ============================================================

// FindPathsToDA знаходить всі шляхи від будь-якого вузла до Domain Admins
func (g *Graph) FindPathsToDA(maxDepth int) []AttackPath {
	color.Blue("[*] Searching for attack paths to Domain Admins...")

	// знаходимо DN групи Domain Admins
	daDN := g.findDomainAdmins()
	if daDN == "" {
		color.Yellow("[!] Domain Admins group not found in graph")
		return nil
	}

	if maxDepth <= 0 {
		maxDepth = 10
	}

	var allPaths []AttackPath

	// запускаємо BFS від кожного увімкненого не-DA вузла
	for dn, node := range g.Nodes {
		// пропускаємо сам DA і відключені акаунти
		if strings.EqualFold(dn, daDN) {
			continue
		}
		if !node.Enabled && node.Type != NodeGroup {
			continue
		}

		paths := g.bfs(dn, daDN, maxDepth)
		allPaths = append(allPaths, paths...)

		// захист від переповнення: не більше 200 шляхів
		if len(allPaths) >= 200 {
			color.Yellow("[!] Over 200 attack paths found, truncating results")
			break
		}
	}

	if len(allPaths) == 0 {
		color.Green("[+] No direct attack paths to Domain Admins found")
	} else {
		color.Red("[!] Found %d attack path(s) to Domain Admins", len(allPaths))
	}

	return allPaths
}

// FindPathsToTarget знаходить шляхи до довільного вузла за SAMAccountName
func (g *Graph) FindPathsToTarget(targetSAM string, maxDepth int) []AttackPath {
	targetDN := g.findBySAM(targetSAM)
	if targetDN == "" {
		color.Yellow("[!] Target '%s' not found in graph", targetSAM)
		return nil
	}

	color.Blue("[*] Searching for attack paths to '%s'...", targetSAM)

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
	if len(paths) == 0 {
		return
	}

	color.Red("\n[!] Attack Paths to Domain Admins:\n")

	for i, path := range paths {
		color.Yellow("  Path %d (depth: %d):", i+1, path.Depth)

		for j, node := range path.Nodes {
			prefix := "  "
			if j < len(path.Nodes)-1 {
				prefix = "  ├─"
			} else {
				prefix = "  └─"
			}

			// колір залежно від типу вузла
			switch node.Type {
			case NodeUser:
				extras := nodeExtras(node)
				color.Cyan("%s [USER] %s%s", prefix, node.SAMAccountName, extras)
			case NodeGroup:
				color.Magenta("%s [GROUP] %s", prefix, node.SAMAccountName)
			case NodeComputer:
				extras := nodeExtras(node)
				color.Blue("%s [COMPUTER] %s%s", prefix, node.SAMAccountName, extras)
			}

			// показуємо тип зв'язку між вузлами
			if j < len(path.Edges) {
				color.White("  │   └─[%s]", path.Edges[j].Type)
			}
		}
		color.White("")
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