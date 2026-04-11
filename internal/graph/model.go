package graph

// ============================================================
// Типи вузлів і зв'язків
// ============================================================

// NodeType визначає тип об'єкта AD
type NodeType string

const (
	NodeUser     NodeType = "user"
	NodeGroup    NodeType = "group"
	NodeComputer NodeType = "computer"
)

// EdgeType визначає тип зв'язку між об'єктами
type EdgeType string

const (
	EdgeMemberOf EdgeType = "MemberOf" // user/group → group
)

// ============================================================
// Основні структури
// ============================================================

// Node представляє один об'єкт AD у графі
type Node struct {
	DN             string
	SAMAccountName string
	DisplayName    string
	Type           NodeType

	// прапори що впливають на пріоритет у звіті
	AdminCount              bool
	Enabled                 bool
	Kerberoastable          bool
	ASREPRoastable          bool
	PasswordNeverExpires    bool
	UnconstrainedDelegation bool
}

// Edge представляє спрямований зв'язок між двома вузлами
type Edge struct {
	From string   // DN вихідного вузла
	To   string   // DN цільового вузла
	Type EdgeType
}

// Graph — граф усіх об'єктів AD та їх зв'язків
type Graph struct {
	Nodes map[string]*Node  // DN → Node
	Edges []Edge
	Adj   map[string][]Edge // DN → список вихідних зв'язків (adjacency list)
}

// AttackPath — один знайдений шлях атаки
type AttackPath struct {
	Nodes       []Node
	Edges       []Edge
	Depth       int
	TargetGroup string // e.g. "Domain Admins", "Backup Operators"
}

// ============================================================
// Конструктор
// ============================================================

// NewGraph створює порожній граф
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make([]Edge, 0),
		Adj:   make(map[string][]Edge),
	}
}

// ============================================================
// Методи графа
// ============================================================

// AddNode додає вузол у граф (якщо вже є — не перезаписує)
func (g *Graph) AddNode(node *Node) {
	if _, exists := g.Nodes[node.DN]; !exists {
		g.Nodes[node.DN] = node
	}
}

// AddEdge додає зв'язок у граф і оновлює adjacency list
func (g *Graph) AddEdge(edge Edge) {
	g.Edges = append(g.Edges, edge)
	g.Adj[edge.From] = append(g.Adj[edge.From], edge)
}

// GetNode повертає вузол за DN або nil якщо не знайдено
func (g *Graph) GetNode(dn string) *Node {
	return g.Nodes[dn]
}

// Stats повертає базову статистику графа
func (g *Graph) Stats() (nodes int, edges int) {
	return len(g.Nodes), len(g.Edges)
}