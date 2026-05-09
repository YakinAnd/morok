package graph

// ============================================================
// Node and edge types
// ============================================================

// NodeType represents an AD object type.
type NodeType string

const (
	NodeUser     NodeType = "user"
	NodeGroup    NodeType = "group"
	NodeComputer NodeType = "computer"
)

// EdgeType represents the relationship type between objects.
type EdgeType string

const (
	EdgeMemberOf EdgeType = "MemberOf" // user/group → group
)

// ============================================================
// Core structures
// ============================================================

// Node represents a single AD object in the graph.
type Node struct {
	DN             string
	SAMAccountName string
	DisplayName    string
	Type           NodeType

	// flags that affect priority in the report
	AdminCount              bool
	Enabled                 bool
	Kerberoastable          bool
	ASREPRoastable          bool
	PasswordNeverExpires    bool
	UnconstrainedDelegation bool
	SourceDomain            string // set for nodes from trusted domains
}

// Edge represents a directed relationship between two nodes.
type Edge struct {
	From string   // source DN
	To   string   // target DN
	Type EdgeType
}

// Graph holds all AD objects and their relationships.
type Graph struct {
	Nodes map[string]*Node  // DN → Node
	Edges []Edge
	Adj   map[string][]Edge // DN → outgoing edges (adjacency list)
}

// AttackPath represents a single discovered attack path.
type AttackPath struct {
	Nodes        []Node
	Edges        []Edge
	Depth        int
	TargetGroup  string // e.g. "Domain Admins", "Backup Operators"
	SourceDomain string // set for paths from trusted domains
}

// ============================================================
// Constructor
// ============================================================

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make([]Edge, 0),
		Adj:   make(map[string][]Edge),
	}
}

// ============================================================
// Graph methods
// ============================================================

// AddNode inserts a node into the graph; no-op if the DN already exists.
func (g *Graph) AddNode(node *Node) {
	if _, exists := g.Nodes[node.DN]; !exists {
		g.Nodes[node.DN] = node
	}
}

// AddEdge adds an edge to the graph and updates the adjacency list.
func (g *Graph) AddEdge(edge Edge) {
	g.Edges = append(g.Edges, edge)
	g.Adj[edge.From] = append(g.Adj[edge.From], edge)
}

// GetNode returns the node for the given DN, or nil if not found.
func (g *Graph) GetNode(dn string) *Node {
	return g.Nodes[dn]
}

// Stats returns basic graph metrics.
func (g *Graph) Stats() (nodes int, edges int) {
	return len(g.Nodes), len(g.Edges)
}