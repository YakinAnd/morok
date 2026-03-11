package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/YakinAnd/adpath/internal/graph"
	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Структури для шаблону
// ============================================================

// ReportData — всі дані що передаються в HTML шаблон
type ReportData struct {
	Domain      string
	GeneratedAt string
	Summary     Summary
	Users       []adldap.LDAPUser
	Groups      []adldap.LDAPGroup
	Computers   []adldap.LDAPComputer
	AttackPaths []graph.AttackPath
	GraphJSON   template.JS // серіалізований граф для D3.js
}

// Summary — короткий підсумок для executive section
type Summary struct {
	TotalUsers              int
	TotalGroups             int
	TotalComputers          int
	EnabledUsers            int
	KerberoastableCount     int
	ASREPCount              int
	AdminCount              int
	PasswordNeverExpires    int
	UnconstrainedDelegation int
	AttackPathsCount        int
	CriticalCount           int // paths з глибиною <= 2
}

// GraphNode і GraphEdge для D3.js JSON
type GraphNode struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Type           string `json:"type"`
	AdminCount     bool   `json:"adminCount"`
	Kerberoastable bool   `json:"kerberoastable"`
	ASREPRoastable bool   `json:"asrepRoastable"`
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type D3Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// ============================================================
// Генерація звіту
// ============================================================

// Generate створює HTML звіт і зберігає у файл
func Generate(
	outputPath string,
	result *adldap.EnumerationResult,
	g *graph.Graph,
	paths []graph.AttackPath,
) error {
	color.Blue("[*] Generating HTML report...")

	data := ReportData{
		Domain:      result.Domain,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Users:       result.Users,
		Groups:      result.Groups,
		Computers:   result.Computers,
		AttackPaths: paths,
		Summary:     buildSummary(result, paths),
		GraphJSON:   template.JS(buildD3JSON(g, paths)),
	}

	// парсимо шаблон
	tmpl, err := template.New("report").Funcs(templateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	// створюємо файл
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create report file: %w", err)
	}
	defer f.Close()

	// рендеримо шаблон у файл
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("template render error: %w", err)
	}

	color.Green("[+] Report saved to: %s", outputPath)
	return nil
}

// ============================================================
// Побудова Summary
// ============================================================

func buildSummary(result *adldap.EnumerationResult, paths []graph.AttackPath) Summary {
	s := Summary{
		TotalUsers:     len(result.Users),
		TotalGroups:    len(result.Groups),
		TotalComputers: len(result.Computers),
		AttackPathsCount: len(paths),
	}

	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		s.EnabledUsers++
		if len(u.SPNs) > 0 {
			s.KerberoastableCount++
		}
		if u.DontReqPreauth {
			s.ASREPCount++
		}
		if u.AdminCount {
			s.AdminCount++
		}
		if u.PasswordNeverExpires {
			s.PasswordNeverExpires++
		}
	}

	for _, c := range result.Computers {
		if c.UnconstrainedDelegation && c.Enabled {
			s.UnconstrainedDelegation++
		}
	}

	for _, p := range paths {
		if p.Depth <= 2 {
			s.CriticalCount++
		}
	}

	return s
}

// ============================================================
// Побудова D3.js JSON
// ============================================================

// buildD3JSON серіалізує граф attack paths у JSON для D3.js
// включаємо тільки вузли і зв'язки що є в знайдених шляхах
func buildD3JSON(g *graph.Graph, paths []graph.AttackPath) string {
	nodeMap := make(map[string]GraphNode)
	edgeMap := make(map[string]GraphEdge)

	for _, path := range paths {
		for _, n := range path.Nodes {
			nodeMap[n.DN] = GraphNode{
				ID:             n.DN,
				Label:          n.SAMAccountName,
				Type:           string(n.Type),
				AdminCount:     n.AdminCount,
				Kerberoastable: n.Kerberoastable,
				ASREPRoastable: n.ASREPRoastable,
			}
		}
		for _, e := range path.Edges {
			key := e.From + "→" + e.To
			edgeMap[key] = GraphEdge{
				Source: e.From,
				Target: e.To,
				Type:   string(e.Type),
			}
		}
	}

	// конвертуємо map → slice
	d3 := D3Graph{}
	for _, n := range nodeMap {
		d3.Nodes = append(d3.Nodes, n)
	}
	for _, e := range edgeMap {
		d3.Edges = append(d3.Edges, e)
	}

	// простий JSON без encoding/json щоб уникнути зайвого import
	return marshalD3(d3)
}

// marshalD3 — простий JSON серіалізатор для D3Graph
func marshalD3(d3 D3Graph) string {
	var sb strings.Builder
	sb.WriteString(`{"nodes":[`)

	for i, n := range d3.Nodes {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(
			`{"id":%q,"label":%q,"type":%q,"adminCount":%v,"kerberoastable":%v,"asrepRoastable":%v}`,
			n.ID, n.Label, n.Type, n.AdminCount, n.Kerberoastable, n.ASREPRoastable,
		))
	}

	sb.WriteString(`],"edges":[`)

	for i, e := range d3.Edges {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(
			`{"source":%q,"target":%q,"type":%q}`,
			e.Source, e.Target, e.Type,
		))
	}

	sb.WriteString(`]}`)
	return sb.String()
}

// ============================================================
// Template functions
// ============================================================

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(count int) string {
			if count == 0 {
				return "badge-ok"
			} else if count <= 3 {
				return "badge-medium"
			}
			return "badge-critical"
		},
		"pathSeverity": func(depth int) string {
			if depth <= 2 {
				return "Critical"
			} else if depth <= 4 {
				return "High"
			}
			return "Medium"
		},
		"pathSeverityClass": func(depth int) string {
			if depth <= 2 {
				return "sev-critical"
			} else if depth <= 4 {
				return "sev-high"
			}
			return "sev-medium"
		},
		"nodeTypeIcon": func(t string) string {
			switch t {
			case "user":
				return "👤"
			case "group":
				return "👥"
			case "computer":
				return "💻"
			}
			return "❓"
		},
		"joinSPNs": func(spns []string) string {
			if len(spns) == 0 {
				return "—"
			}
			return strings.Join(spns, ", ")
		},
		"yesNo": func(b bool) string {
			if b {
				return "Yes"
			}
			return "No"
		},
	}
}

// ============================================================
// HTML шаблон
// ============================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>adpath — AD Security Report: {{.Domain}}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; }

/* Header */
.header { background: linear-gradient(135deg, #1a1f2e 0%, #0f1117 100%);
  border-bottom: 1px solid #2d3748; padding: 24px 40px; }
.header h1 { font-size: 1.6rem; color: #63b3ed; letter-spacing: 0.05em; }
.header .meta { color: #718096; font-size: 0.85rem; margin-top: 4px; }
.header .domain { color: #f6ad55; font-weight: 600; }

/* Nav tabs */
.nav { display: flex; gap: 2px; padding: 0 40px;
  background: #1a1f2e; border-bottom: 1px solid #2d3748; }
.nav button { padding: 12px 20px; border: none; background: transparent;
  color: #718096; cursor: pointer; font-size: 0.9rem; border-bottom: 2px solid transparent;
  transition: all 0.2s; }
.nav button:hover { color: #e2e8f0; }
.nav button.active { color: #63b3ed; border-bottom-color: #63b3ed; }

/* Content */
.content { padding: 32px 40px; max-width: 1400px; }
.tab-pane { display: none; }
.tab-pane.active { display: block; }

/* Summary cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px; margin-bottom: 32px; }
.card { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px;
  padding: 20px; }
.card .value { font-size: 2rem; font-weight: 700; color: #63b3ed; }
.card .label { font-size: 0.8rem; color: #718096; margin-top: 4px;
  text-transform: uppercase; letter-spacing: 0.05em; }
.card.critical .value { color: #fc8181; }
.card.warning .value { color: #f6ad55; }
.card.ok .value { color: #68d391; }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: #1c4532; color: #68d391; }
.badge-medium { background: #744210; color: #f6ad55; }
.badge-critical { background: #742a2a; color: #fc8181; }

/* Severity */
.sev-critical { color: #fc8181; font-weight: 700; }
.sev-high     { color: #f6ad55; font-weight: 600; }
.sev-medium   { color: #faf089; }

/* Tables */
.table-wrap { overflow-x: auto; border-radius: 8px;
  border: 1px solid #2d3748; margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #1a1f2e; color: #718096; padding: 10px 14px;
  text-align: left; font-weight: 500; text-transform: uppercase;
  font-size: 0.75rem; letter-spacing: 0.05em; }
td { padding: 10px 14px; border-top: 1px solid #2d3748; }
tr:hover td { background: #1a1f2e; }
.mono { font-family: monospace; font-size: 0.8rem; color: #a0aec0; }

/* Attack paths */
.path-card { background: #1a1f2e; border: 1px solid #2d3748;
  border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.path-header { padding: 12px 16px; display: flex; align-items: center;
  gap: 12px; border-bottom: 1px solid #2d3748; }
.path-body { padding: 16px; }
.path-chain { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.path-node { display: flex; align-items: center; gap: 6px;
  background: #2d3748; border-radius: 6px; padding: 6px 12px;
  font-size: 0.85rem; }
.path-node.is-admin { border: 1px solid #fc8181; }
.path-node.is-kerb  { border: 1px solid #f6ad55; }
.path-arrow { color: #4a5568; font-size: 1.2rem; }
.path-edge-label { font-size: 0.7rem; color: #4a5568; }

/* D3 Graph */
#graph-container { background: #1a1f2e; border: 1px solid #2d3748;
  border-radius: 8px; height: 500px; position: relative; overflow: hidden; }
#graph-svg { width: 100%; height: 100%; }
.node-label { font-size: 11px; fill: #e2e8f0; pointer-events: none; }
.link { stroke: #4a5568; stroke-opacity: 0.6; stroke-width: 1.5px; }
.node circle { stroke-width: 2px; cursor: pointer; }

/* Section title */
.section-title { font-size: 1.1rem; color: #e2e8f0; margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid #2d3748; }
.section-title span { color: #718096; font-size: 0.85rem; font-weight: 400;
  margin-left: 8px; }
</style>
</head>
<body>

<div class="header">
  <h1>⚔ adpath — AD Security Report</h1>
  <div class="meta">
    Domain: <span class="domain">{{.Domain}}</span> &nbsp;|&nbsp;
    Generated: {{.GeneratedAt}}
  </div>
</div>

<div class="nav">
  <button class="active" onclick="showTab('summary')">Summary</button>
  <button onclick="showTab('paths')">Attack Paths ({{.Summary.AttackPathsCount}})</button>
  <button onclick="showTab('graph')">Graph</button>
  <button onclick="showTab('users')">Users ({{.Summary.TotalUsers}})</button>
  <button onclick="showTab('groups')">Groups ({{.Summary.TotalGroups}})</button>
  <button onclick="showTab('computers')">Computers ({{.Summary.TotalComputers}})</button>
</div>

<div class="content">

<!-- SUMMARY TAB -->
<div id="tab-summary" class="tab-pane active">
  <div class="cards">
    <div class="card {{if gt .Summary.AttackPathsCount 0}}critical{{else}}ok{{end}}">
      <div class="value">{{.Summary.AttackPathsCount}}</div>
      <div class="label">Attack Paths</div>
    </div>
    <div class="card {{if gt .Summary.CriticalCount 0}}critical{{else}}ok{{end}}">
      <div class="value">{{.Summary.CriticalCount}}</div>
      <div class="label">Critical Paths</div>
    </div>
    <div class="card {{if gt .Summary.KerberoastableCount 0}}warning{{else}}ok{{end}}">
      <div class="value">{{.Summary.KerberoastableCount}}</div>
      <div class="label">Kerberoastable</div>
    </div>
    <div class="card {{if gt .Summary.ASREPCount 0}}warning{{else}}ok{{end}}">
      <div class="value">{{.Summary.ASREPCount}}</div>
      <div class="label">AS-REP Roastable</div>
    </div>
    <div class="card {{if gt .Summary.UnconstrainedDelegation 0}}critical{{else}}ok{{end}}">
      <div class="value">{{.Summary.UnconstrainedDelegation}}</div>
      <div class="label">Unconstrained Deleg.</div>
    </div>
    <div class="card">
      <div class="value">{{.Summary.EnabledUsers}}</div>
      <div class="label">Enabled Users</div>
    </div>
    <div class="card {{if gt .Summary.PasswordNeverExpires 0}}warning{{else}}ok{{end}}">
      <div class="value">{{.Summary.PasswordNeverExpires}}</div>
      <div class="label">Pwd Never Expires</div>
    </div>
    <div class="card {{if gt .Summary.AdminCount 0}}warning{{else}}ok{{end}}">
      <div class="value">{{.Summary.AdminCount}}</div>
      <div class="label">AdminCount=1</div>
    </div>
  </div>
</div>

<!-- ATTACK PATHS TAB -->
<div id="tab-paths" class="tab-pane">
  <h2 class="section-title">
    Attack Paths to Domain Admins
    <span>{{.Summary.AttackPathsCount}} path(s) found</span>
  </h2>
  {{if eq .Summary.AttackPathsCount 0}}
    <p style="color:#68d391">✓ No attack paths to Domain Admins found.</p>
  {{else}}
  {{range $i, $path := .AttackPaths}}
  <div class="path-card">
    <div class="path-header">
      <span class="badge {{pathSeverityClass $path.Depth}}">
        {{pathSeverity $path.Depth}}
      </span>
      <span style="color:#718096; font-size:0.85rem">
        Path {{inc $i}} &nbsp;|&nbsp; Depth: {{$path.Depth}}
      </span>
    </div>
    <div class="path-body">
      <div class="path-chain">
        {{range $j, $node := $path.Nodes}}
          <div class="path-node
            {{if $node.AdminCount}}is-admin{{end}}
            {{if $node.Kerberoastable}}is-kerb{{end}}">
            {{nodeTypeIcon $node.Type}} {{$node.SAMAccountName}}
          </div>
          {{if lt $j (dec (len $path.Nodes))}}
            <div class="path-arrow">→</div>
          {{end}}
        {{end}}
      </div>
    </div>
  </div>
  {{end}}
  {{end}}
</div>

<!-- GRAPH TAB -->
<div id="tab-graph" class="tab-pane">
  <h2 class="section-title">Attack Path Graph <span>D3.js force-directed</span></h2>
  <div id="graph-container">
    <svg id="graph-svg"></svg>
  </div>
  <div style="margin-top:12px; font-size:0.8rem; color:#718096">
    🔴 Domain Admins / AdminCount &nbsp;|&nbsp;
    🟡 Kerberoastable &nbsp;|&nbsp;
    🔵 User &nbsp;|&nbsp;
    🟣 Group &nbsp;|&nbsp;
    ⚪ Computer
  </div>
</div>

<!-- USERS TAB -->
<div id="tab-users" class="tab-pane">
  <h2 class="section-title">Users <span>{{.Summary.TotalUsers}} total</span></h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>Display Name</th>
        <th>Enabled</th>
        <th>Admin</th>
        <th>Kerberoastable</th>
        <th>AS-REP</th>
        <th>Pwd Never Exp</th>
        <th>Last Logon</th>
        <th>Pwd Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .Users}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.DisplayName}}</td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:#2d3748;color:#718096">No</span>{{end}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td>{{if .SPNs}}<span class="badge badge-medium">Yes</span>{{else}}—{{end}}</td>
      <td>{{if .DontReqPreauth}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td>{{if .PasswordNeverExpires}}<span class="badge badge-medium">Yes</span>{{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- GROUPS TAB -->
<div id="tab-groups" class="tab-pane">
  <h2 class="section-title">Groups <span>{{.Summary.TotalGroups}} total</span></h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Type</th>
        <th>Members</th>
        <th>AdminCount</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
    {{range .Groups}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.GroupType}}</td>
      <td>{{len .Members}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td style="color:#718096">{{.Description}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- COMPUTERS TAB -->
<div id="tab-computers" class="tab-pane">
  <h2 class="section-title">Computers <span>{{.Summary.TotalComputers}} total</span></h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>DNS</th>
        <th>OS</th>
        <th>Enabled</th>
        <th>Unconstrained Deleg.</th>
        <th>Last Logon</th>
      </tr>
    </thead>
    <tbody>
    {{range .Computers}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td class="mono">{{.DNSHostName}}</td>
      <td>{{.OperatingSystem}} {{.OperatingSystemVersion}}</td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:#2d3748;color:#718096">No</span>{{end}}</td>
      <td>{{if .UnconstrainedDelegation}}
            <span class="badge badge-critical">Yes</span>
          {{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

</div><!-- /content -->

<script>
// ============================================================
// Tab navigation
// ============================================================
function showTab(name) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'graph') initGraph();
}

// ============================================================
// D3.js force-directed graph
// ============================================================
let graphInitialized = false;

function initGraph() {
  if (graphInitialized) return;
  graphInitialized = true;

  const data = {{.GraphJSON}};
  if (!data.nodes || data.nodes.length === 0) {
    document.getElementById('graph-container').innerHTML =
      '<p style="padding:20px;color:#718096">No attack paths to visualize.</p>';
    return;
  }

  const svg = d3.select('#graph-svg');
  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight;

  // zoom
  const zoom = d3.zoom().scaleExtent([0.3, 3])
    .on('zoom', e => g.attr('transform', e.transform));
  svg.call(zoom);
  const g = svg.append('g');

  // стрілки для edges
  svg.append('defs').append('marker')
    .attr('id', 'arrow')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 20).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#4a5568');

  // simulation
  const simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.edges)
      .id(d => d.id).distance(120))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(40));

  // edges
  const link = g.append('g').selectAll('line')
    .data(data.edges).enter().append('line')
    .attr('class', 'link')
    .attr('marker-end', 'url(#arrow)');

  // nodes
  const node = g.append('g').selectAll('g')
    .data(data.nodes).enter().append('g')
    .call(d3.drag()
      .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (e, d) => { d.fx=e.x; d.fy=e.y; })
      .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }));

  node.append('circle').attr('r', 16)
    .attr('fill', d => nodeColor(d))
    .attr('stroke', d => nodeStroke(d));

  node.append('text').attr('class', 'node-label')
    .attr('dy', 28).attr('text-anchor', 'middle')
    .text(d => d.label);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
  });
}

function nodeColor(d) {
  if (d.adminCount)     return '#fc8181'; // червоний — DA/admin
  if (d.kerberoastable) return '#f6ad55'; // жовтий — kerberoastable
  if (d.type === 'group')    return '#b794f4'; // фіолетовий
  if (d.type === 'computer') return '#90cdf4'; // блакитний
  return '#63b3ed'; // синій — звичайний user
}

function nodeStroke(d) {
  if (d.asrepRoastable) return '#fc8181';
  return 'transparent';
}
</script>

</body>
</html>`