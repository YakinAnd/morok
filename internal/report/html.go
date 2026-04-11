package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/YakinAnd/adpath/internal/analysis"
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
	AuthMethod  string // "PTH (NTLM)", "PTT (Kerberos)", "Password", "Anonymous"
	Summary     Summary
	Users       []adldap.LDAPUser
	Groups      []adldap.LDAPGroup
	Computers   []adldap.LDAPComputer
	AttackPaths []graph.AttackPath
	GraphJSON   template.JS
	ForestWide  bool
	// v0.2
	KerberosResult *analysis.KerberosResult
	ACLResult      *analysis.ACLResult
	// v0.3
	DelegationResult *analysis.DelegationResult
	GPOResult        *analysis.GPOResult
	// v0.6
	HygieneResult *analysis.HygieneResult
	PSOResult     *analysis.PSOResult
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
	CriticalCount           int
	// v0.2
	DangerousACLCount       int
	DCSyncCount             int
	// v0.3
	DelegationCount         int
	WeakPasswordPolicy      bool
	// v0.6
	StaleUsersCount         int
	StaleComputersCount     int
	PasswordInDescCount     int
	KrbtgtAtRisk            bool
	KrbtgtPwdAgeDays        int
	WeakPSOCount            int
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
	kr *analysis.KerberosResult,
	aclResult *analysis.ACLResult,
	dr *analysis.DelegationResult,
	gr *analysis.GPOResult,
	hr *analysis.HygieneResult,
	psoResult *analysis.PSOResult,
	authMethod string,
) error {
	color.Blue("[*] Generating HTML report...")

	data := ReportData{
	Domain:           result.Domain,
	GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
	AuthMethod:       authMethod,
	Users:            result.Users,
	Groups:           result.Groups,
	Computers:        result.Computers,
	AttackPaths:      paths,
	Summary:          buildSummary(result, paths, kr, aclResult, dr, gr, hr),
	GraphJSON:        template.JS(buildD3JSON(g, paths)),
	KerberosResult:   kr,
	ACLResult:        aclResult,
	DelegationResult: dr,
	GPOResult:        gr,
	HygieneResult:   hr,
	PSOResult:        psoResult,
	ForestWide:       result.ForestWide,
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

func buildSummary(
	result *adldap.EnumerationResult,
	paths []graph.AttackPath,
	kr *analysis.KerberosResult,
	aclResult *analysis.ACLResult,
	dr *analysis.DelegationResult,
	gr *analysis.GPOResult,
	hr *analysis.HygieneResult,
) Summary {
	s := Summary{
		TotalUsers:       len(result.Users),
		TotalGroups:      len(result.Groups),
		TotalComputers:   len(result.Computers),
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

	if aclResult != nil {
		s.DangerousACLCount = len(aclResult.Findings)
		s.DCSyncCount = len(aclResult.DCSyncFindings)
	}

	if dr != nil {
		s.DelegationCount = len(dr.Findings)
	}

	if gr != nil && gr.DefaultPolicy != nil {
		pp := gr.DefaultPolicy
		s.WeakPasswordPolicy = pp.MinLength < 8 || !pp.Complexity || pp.LockoutThreshold == 0
	}

	if hr != nil {
		s.StaleUsersCount = len(hr.StaleUsers)
		s.StaleComputersCount = len(hr.StaleComputers)
		s.PasswordInDescCount = len(hr.PasswordInDesc)
		s.KrbtgtAtRisk = hr.KrbtgtAtRisk
		s.KrbtgtPwdAgeDays = hr.KrbtgtPwdAgeDays
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
		"inc": func(i int) int { return i + 1 },
    "dec": func(i int) int { return i - 1 },
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
		"nodeTypeIcon": func(t graph.NodeType) string {
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
		"aclExploit": func(right, principal, target, domain string) string {
			switch right {
			case "GenericAll":
				return "bloodyAD -u " + principal + " -p '<pass>' -d " + domain + " --host <DC> add groupMember 'Domain Admins' " + principal
			case "WriteDACL":
				return "dacledit.py -action write -rights FullControl -principal " + principal + " -target " + target + " '" + domain + "/" + principal + ":<pass>'"
			case "WriteOwner":
				return "owneredit.py -action write -new-owner " + principal + " -target " + target + " '" + domain + "/" + principal + ":<pass>'"
			case "ForceChangePassword":
				return "bloodyAD -u " + principal + " -p '<pass>' -d " + domain + " --host <DC> set password " + target + " 'NewPass123!'"
			case "AddMember":
				return "bloodyAD -u " + principal + " -p '<pass>' -d " + domain + " --host <DC> add groupMember '" + target + "' " + principal
			case "GenericWrite":
				return "bloodyAD -u " + principal + " -p '<pass>' -d " + domain + " --host <DC> set object " + target + " -a servicePrincipalName=fake/spn"
			default:
				return "Use BloodHound / dacledit.py to abuse this ACL right"
			}
		},
		"aclFix": func(right string) string {
			switch right {
			case "GenericAll":
				return "Remove GenericAll from non-admin principals; audit AdminSDHolder inheritance"
			case "WriteDACL":
				return "Restrict WriteDACL to Domain Admins; enable Protected Users group for privileged accounts"
			case "WriteOwner":
				return "Set object owner to Domain Admins; enable AdminSDHolder for sensitive objects"
			case "ForceChangePassword":
				return "Remove ForceChangePassword; use 'User must change password at next logon' instead"
			case "AddMember":
				return "Remove AddMember from sensitive groups; use AD Tiered Administration model"
			case "GenericWrite":
				return "Remove GenericWrite; restrict attribute modification to delegated OUs only"
			default:
				return "Review and remove unnecessary privilege delegation for this principal"
			}
		},
		"delegExploit": func(delegType string) string {
			switch delegType {
			case "Unconstrained":
				return "Rubeus.exe monitor /interval:5 /filteruser:DC$ — trigger with SpoolSample.exe <DC> <host> to capture DC TGT → pass-the-ticket as DA"
			case "Constrained":
				return "getST.py -spn cifs/<target> -impersonate administrator '<domain>/<account>:<pass>'"
			case "Resource-Based Constrained":
				return "getST.py -spn cifs/<target> -impersonate administrator -self '<domain>/<account>:<pass>' (RBCD S4U2Self)"
			default:
				return "Use impacket getST.py to abuse S4U2Proxy for service impersonation"
			}
		},
		"delegFix": func(delegType string) string {
			switch delegType {
			case "Unconstrained":
				return "Replace unconstrained delegation with Resource-Based CD; add host to Protected Users; enable 'Account is sensitive and cannot be delegated'"
			case "Constrained":
				return "Restrict constrained delegation to minimum required SPNs; avoid TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition)"
			default:
				return "Audit msDS-AllowedToActOnBehalfOfOtherIdentity; remove unnecessary RBCD grants"
			}
		},
		"pathExploit": func(nodes []graph.Node) string {
			for _, n := range nodes {
				if n.Kerberoastable {
					return "Kerberoast " + n.SAMAccountName + ": GetUserSPNs.py domain/user:pass → crack TGS → use creds to reach DA"
				}
				if n.ASREPRoastable {
					return "AS-REP roast " + n.SAMAccountName + ": GetNPUsers.py domain/ -usersfile users.txt → crack hash → use creds"
				}
				if n.UnconstrainedDelegation {
					return "Compromise " + n.SAMAccountName + " (unconstrained delegation) → harvest DA TGT via SpoolSample/PetitPotam"
				}
			}
			return "Account has transitive DA membership — existing credentials grant DA access (net use \\\\DC\\IPC$ or WinRM)"
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
.card.critical .value { color: #e53e3e; }
.card.warning .value { color: #f6ad55; }
.card.ok .value { color: #68d391; }
.card[onclick] { cursor: pointer; transition: border-color 0.15s, transform 0.12s; }
.card[onclick]:hover { border-color: #63b3ed; transform: translateY(-2px); }

/* Accordion */
.acc-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer;
  margin-top: 10px; padding: 7px 12px; background: #2d3748; border-radius: 6px;
  font-size: 0.78rem; color: #a0aec0; user-select: none; border: none; width: 100%;
  text-align: left; }
.acc-toggle:hover { background: #374151; color: #e2e8f0; }
.acc-body { display: none; padding: 12px 14px; margin-top: 2px;
  background: #111827; border: 1px solid #2d3748; border-radius: 6px;
  font-size: 0.82rem; line-height: 1.6; }
.acc-body.open { display: block; }
.acc-cmd { font-family: monospace; background: #0a0e1a; padding: 4px 8px;
  border-radius: 4px; color: #68d391; font-size: 0.78rem; display: block; margin-top: 4px;
  word-break: break-all; }
.acc-label { color: #718096; font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; margin-top: 8px; }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: #1c4532; color: #68d391; }
.badge-medium { background: #744210; color: #f6ad55; }
.badge-critical { background: #742a2a; color: #e53e3e; }

/* Severity */
.sev-critical { color: #e53e3e; font-weight: 700; }
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
  <h1>⚔ adpath v0.4 — AD Security Report</h1>
  <div class="meta">
    Domain: <span class="domain">{{.Domain}}</span> &nbsp;|&nbsp;
    Auth: <span style="color:#68d391">{{.AuthMethod}}</span> &nbsp;|&nbsp;
    Generated: {{.GeneratedAt}}
  </div>
</div>

<div class="nav">
  <button class="active" onclick="showTab('summary')">Summary</button>
  <button onclick="showTab('paths')">Attack Paths ({{.Summary.AttackPathsCount}})</button>
  <button onclick="showTab('graph')">Graph</button>
  <button onclick="showTab('kerberos')">Kerberos</button>
  <button onclick="showTab('acl')">ACL ({{.Summary.DangerousACLCount}})</button>
  <button onclick="showTab('delegation')">Delegation ({{.Summary.DelegationCount}})</button>
  <button onclick="showTab('hygiene')">Hygiene</button>
  <button onclick="showTab('gpo')">GPO</button>
  <button onclick="showTab('users')">Users ({{.Summary.TotalUsers}})</button>
  <button onclick="showTab('groups')">Groups ({{.Summary.TotalGroups}})</button>
  <button onclick="showTab('computers')">Computers ({{.Summary.TotalComputers}})</button>
</div>

<div class="content">

<!-- SUMMARY TAB -->
<div id="tab-summary" class="tab-pane active">

  <!-- Findings Overview -->
  <div style="padding:20px 24px;background:#1a1f2e;border:1px solid #2d3748;border-radius:8px;margin-bottom:24px">
   <div style="font-size:14px;font-weight:500;color:#e2e8f0;margin-bottom:16px">
    Findings Overview — {{.Domain}}
   </div>
   <div id="findings-chart" style="display:flex;flex-direction:column;gap:10px"></div>
  </div>

  <!-- Attack Surface -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Attack Surface</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px">
    <div class="card {{if gt .Summary.AttackPathsCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'paths')" title="View Attack Paths">
      <div class="value">{{.Summary.AttackPathsCount}}</div>
      <div class="label">Attack Paths to DA</div>
    </div>
    <div class="card {{if gt .Summary.CriticalCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'paths')" title="View Critical Paths">
      <div class="value">{{.Summary.CriticalCount}}</div>
      <div class="label">Critical Paths (depth ≤ 2)</div>
    </div>
    <div class="card {{if gt .Summary.KerberoastableCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'kerberos')" title="View Kerberoastable accounts">
      <div class="value">{{.Summary.KerberoastableCount}}</div>
      <div class="label">Kerberoastable</div>
    </div>
    <div class="card {{if gt .Summary.ASREPCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'kerberos')" title="View AS-REP Roastable accounts">
      <div class="value">{{.Summary.ASREPCount}}</div>
      <div class="label">AS-REP Roastable</div>
    </div>
    <div class="card {{if gt .Summary.DelegationCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'delegation')" title="View Delegation findings">
      <div class="value">{{.Summary.DelegationCount}}</div>
      <div class="label">Delegation Issues</div>
    </div>
    <div class="card {{if gt .Summary.DangerousACLCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'acl')" title="View ACL findings">
      <div class="value">{{.Summary.DangerousACLCount}}</div>
      <div class="label">Dangerous ACLs</div>
    </div>
    <div class="card {{if gt .Summary.DCSyncCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'acl')" title="View DCSync findings">
      <div class="value">{{.Summary.DCSyncCount}}</div>
      <div class="label">DCSync Rights</div>
    </div>
  </div>

  <!-- Account Hygiene -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Account Hygiene</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px">
    <div class="card {{if gt .Summary.PasswordNeverExpires 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'users')" title="View users with non-expiring passwords">
      <div class="value">{{.Summary.PasswordNeverExpires}}</div>
      <div class="label">Pwd Never Expires</div>
    </div>
    <div class="card {{if gt .Summary.AdminCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'users')" title="View admin-flagged users">
      <div class="value">{{.Summary.AdminCount}}</div>
      <div class="label">AdminCount = 1</div>
    </div>
    <div class="card" onclick="showTabByClick(event,'users')" title="View all users">
      <div class="value">{{.Summary.EnabledUsers}}</div>
      <div class="label">Enabled Users</div>
    </div>
    <div class="card" onclick="showTabByClick(event,'computers')" title="View computers">
      <div class="value">{{.Summary.TotalComputers}}</div>
      <div class="label">Computers</div>
    </div>
    <div class="card {{if gt .Summary.StaleUsersCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'hygiene')" title="View stale accounts">
      <div class="value">{{.Summary.StaleUsersCount}}</div>
      <div class="label">Stale Users (90d)</div>
    </div>
    <div class="card {{if gt .Summary.PasswordInDescCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'hygiene')" title="View password leaks">
      <div class="value">{{.Summary.PasswordInDescCount}}</div>
      <div class="label">Pwd in Description</div>
    </div>
    <div class="card {{if .Summary.KrbtgtAtRisk}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'hygiene')" title="View krbtgt status">
      <div class="value">{{if eq .Summary.KrbtgtPwdAgeDays 0}}?{{else}}{{.Summary.KrbtgtPwdAgeDays}}d{{end}}</div>
      <div class="label">Krbtgt Pwd Age</div>
    </div>
  </div>

  <!-- Policy & Configuration -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Policy & Configuration</div>
  <div style="background:#1a1f2e;border:1px solid #2d3748;border-radius:8px;overflow:hidden">
    {{if .GPOResult}}{{if .GPOResult.DefaultPolicy}}
    {{$pp := .GPOResult.DefaultPolicy}}
    {{if not $pp.Complexity}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:#e2e8f0">Password complexity disabled</span>
    </div>
    {{end}}
    {{if lt $pp.MinLength 8}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:#e2e8f0">Minimum password length: {{$pp.MinLength}} chars</span>
    </div>
    {{end}}
    {{if or (eq $pp.MaxAge 0) (gt $pp.MaxAge 3650)}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:#e2e8f0">Passwords never expire</span>
    </div>
    {{end}}
    {{if $pp.ReversibleEncryption}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:#e2e8f0">Reversible encryption enabled</span>
    </div>
    {{end}}
    {{if eq $pp.LockoutThreshold 0}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:#e2e8f0">Account lockout disabled — brute force possible</span>
    </div>
    {{else}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid #2d3748">
      <span class="badge badge-ok">OK</span>
      <span style="font-size:13px;color:#e2e8f0">Account lockout configured (threshold: {{$pp.LockoutThreshold}})</span>
    </div>
    {{end}}
    {{if not $pp.ReversibleEncryption}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px">
      <span class="badge badge-ok">OK</span>
      <span style="font-size:13px;color:#e2e8f0">Reversible encryption disabled</span>
    </div>
    {{end}}
    {{end}}{{else}}
    <div style="padding:16px;color:#718096;font-size:13px">GPO data not collected — run with --report to include policy analysis</div>
    {{end}}
  </div>

</div>

<!-- ATTACK PATHS TAB -->
<div id="tab-paths" class="tab-pane">
  <h2 class="section-title">
    Attack Paths to Privileged Groups
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
      {{if $path.TargetGroup}}
      <span class="badge" style="background:#2d3748;color:#fc8181">→ {{$path.TargetGroup}}</span>
      {{end}}
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
      <button class="acc-toggle" onclick="toggleAcc(this)">
        ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix
      </button>
      <div class="acc-body">
        <div class="acc-label">Exploit</div>
        <span class="acc-cmd">{{pathExploit $path.Nodes}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:#a0aec0">Enforce least-privilege group membership; remove transitive paths to Domain Admins; use AD Tiered Administration model. Audit with: <span class="acc-cmd">Get-ADGroupMember 'Domain Admins' -Recursive</span></div>
      </div>
    </div>
  </div>
  {{end}}
  {{end}}
</div>

<!-- GRAPH TAB -->
<div id="tab-graph" class="tab-pane">
  <h2 class="section-title">Attack Path Graph <span>Layered path view — nodes sized by path count</span></h2>
  <div style="display:flex;gap:16px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
    <div style="font-size:0.8rem;color:#718096">
      <span style="color:#fc8181">●</span> DA/Admin &nbsp;
      <span style="color:#f6ad55">●</span> Kerberoastable &nbsp;
      <span style="color:#b794f4">●</span> Group &nbsp;
      <span style="color:#90cdf4">●</span> Computer &nbsp;
      <span style="color:#63b3ed">●</span> User
    </div>
    <button onclick="resetZoom()" style="margin-left:auto;padding:4px 12px;background:#2d3748;border:none;color:#a0aec0;border-radius:4px;cursor:pointer;font-size:0.8rem">Reset Zoom</button>
  </div>
  <div id="graph-container" style="position:relative">
    <svg id="graph-svg"></svg>
    <div id="graph-tooltip" style="display:none;position:absolute;background:#1a1f2e;border:1px solid #2d3748;border-radius:6px;padding:10px 14px;font-size:0.8rem;pointer-events:none;max-width:280px;z-index:10"></div>
  </div>
  <div style="margin-top:8px;font-size:0.75rem;color:#4a5568">
    Drag to pan · Scroll to zoom · Hover node for details · Node size = number of paths through it
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
  <h2 class="section-title">
    Computers
    <span>{{.Summary.TotalComputers}} total{{if .ForestWide}} — forest-wide{{end}}</span>
  </h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Domain</th>
        <th>OS</th>
        <th>Version</th>
        <th>Enabled</th>
        <th>LAPS</th>
        <th>Uncons. Deleg.</th>
        <th>Last Logon</th>
        <th>Created</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
    {{range .Computers}}
    <tr>
      <td class="mono" style="white-space:nowrap">
        {{.SAMAccountName}}
        {{if .IsGC}}<span style="color:#4a5568;font-size:0.7rem" title="Partial data from Global Catalog">&nbsp;(GC)</span>{{end}}
        {{if .DNSHostName}}<div style="color:#718096;font-size:0.75rem">{{.DNSHostName}}</div>{{end}}
      </td>
      <td style="font-size:0.78rem;color:#a0aec0">{{.Domain}}</td>
      <td style="white-space:nowrap">
        {{if .OperatingSystem}}{{.OperatingSystem}}
        {{else}}<span style="color:#4a5568">—</span>{{end}}
      </td>
      <td class="mono" style="font-size:0.78rem;white-space:nowrap">
        {{if .OperatingSystemVersion}}{{.OperatingSystemVersion}}
        {{if .OperatingSystemSP}}&nbsp;{{.OperatingSystemSP}}{{end}}
        {{else}}—{{end}}
      </td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:#2d3748;color:#718096">No</span>{{end}}</td>
      <td>{{if .LAPSEnabled}}<span class="badge badge-ok">✓</span>
          {{else}}<span class="badge badge-medium">No</span>{{end}}</td>
      <td>{{if .UnconstrainedDelegation}}<span class="badge badge-critical">Yes</span>
          {{else}}—{{end}}</td>
      <td class="mono" style="font-size:0.78rem">{{.LastLogon}}</td>
      <td class="mono" style="font-size:0.78rem">{{.WhenCreated}}</td>
      <td style="font-size:0.78rem;color:#718096">{{.Description}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- KERBEROS TAB -->
<div id="tab-kerberos" class="tab-pane">
  <h2 class="section-title">Kerberos Attack Surface</h2>
  {{if .KerberosResult}}

  <h3 class="section-title" style="font-size:0.95rem; margin-top:16px">
    Kerberoastable Accounts
    <span>{{len .KerberosResult.KerberoastableAccounts}}</span>
  </h3>
  {{if .KerberosResult.KerberoastableAccounts}}
  <div style="margin-bottom:8px">
    <button class="acc-toggle" onclick="toggleAcc(this)" style="background:#1a2a1a;color:#68d391;margin-bottom:4px">
      ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix — Kerberoasting
    </button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">GetUserSPNs.py domain/user:pass -dc-ip &lt;DC&gt; -request-user &lt;account&gt; -outputfile kerberoast.txt</span>
      <span class="acc-cmd" style="margin-top:4px">hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:#a0aec0">Use managed service accounts (gMSA) — auto-rotating 120-char passwords, not crackable. Remove SPNs from regular user accounts. Enable AES-only Kerberos encryption (no RC4).</div>
    </div>
  </div>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>SPNs</th>
        <th>Admin</th>
        <th>Last Logon</th>
        <th>Password Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .KerberosResult.KerberoastableAccounts}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td class="mono" style="font-size:0.75rem">{{joinSPNs .SPNs}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391">✓ No Kerberoastable accounts found.</p>{{end}}

  <h3 class="section-title" style="font-size:0.95rem; margin-top:24px">
    AS-REP Roastable Accounts
    <span>{{len .KerberosResult.ASREPAccounts}}</span>
  </h3>
  {{if .KerberosResult.ASREPAccounts}}
  <div style="margin-bottom:8px">
    <button class="acc-toggle" onclick="toggleAcc(this)" style="background:#1a2a1a;color:#68d391;margin-bottom:4px">
      ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix — AS-REP Roasting
    </button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip &lt;DC&gt;</span>
      <span class="acc-cmd" style="margin-top:4px">hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:#a0aec0">Enable "Do not require Kerberos preauthentication" only if absolutely needed. Enforce strong passwords (&gt;25 chars) on affected accounts. Add to Protected Users security group (prevents AS-REP roasting).</div>
    </div>
  </div>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>Admin</th>
        <th>Last Logon</th>
        <th>Password Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .KerberosResult.ASREPAccounts}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391">✓ No AS-REP Roastable accounts found.</p>{{end}}

  {{else}}<p style="color:#718096">Kerberos data not available.</p>{{end}}
</div>

<!-- ACL TAB -->
<div id="tab-acl" class="tab-pane">
  <h2 class="section-title">
    Dangerous ACL Permissions
    <span>{{.Summary.DangerousACLCount}} finding(s)</span>
  </h2>

  {{if .ACLResult}}{{if .ACLResult.DCSyncFindings}}
  <div style="background:#2d1515;border:1px solid #e53e3e;border-radius:8px;padding:16px;margin-bottom:20px">
    <div style="font-size:0.9rem;font-weight:600;color:#fc8181;margin-bottom:10px">
      ☠ DCSync Rights Detected — {{len .ACLResult.DCSyncFindings}} principal(s) can dump all domain password hashes
    </div>
    {{range .ACLResult.DCSyncFindings}}
    <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #742a2a">
      <span class="badge badge-critical">{{.PrincipalType}}</span>
      <span class="mono">{{.PrincipalName}}</span>
    </div>
    {{end}}
    <button class="acc-toggle" onclick="toggleAcc(this)" style="margin-top:10px">▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix</button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">secretsdump.py domain/user:pass@DC -just-dc-ntlm</span>
      <span class="acc-cmd" style="margin-top:4px">secretsdump.py -hashes :&lt;NThash&gt; domain/user@DC -just-dc-ntlm</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:#a0aec0">Remove DS-Replication-Get-Changes-All from non-DC accounts. Run: <span class="acc-cmd">Get-ObjectAcl -DistinguishedName "DC=domain,DC=local" | ? {$_.ActiveDirectoryRights -match "Replication"}</span> to audit. Only Domain Controllers and Administrators should have DCSync rights.</div>
    </div>
  </div>
  {{end}}{{end}}
  {{if .ACLResult}}
  {{if .ACLResult.Findings}}
  {{range $i, $f := .ACLResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq $f.Severity "Critical"}}badge-critical{{else if eq $f.Severity "High"}}badge-medium{{else}}badge-ok{{end}}">{{$f.Severity}}</span>
      <span class="badge badge-critical" style="font-family:monospace">{{$f.Right}}</span>
      <span class="mono" style="color:#e2e8f0">{{$f.PrincipalName}}</span>
      <span style="color:#4a5568">─▶</span>
      <span class="mono" style="color:#f6ad55">{{$f.TargetName}}</span>
      <span class="badge" style="background:#2d3748;color:#a0aec0;margin-left:auto">{{$f.PrincipalType}} → {{$f.TargetType}}</span>
    </div>
    <div style="padding:0 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{$f.Right}})</div>
        <span class="acc-cmd">{{aclExploit (print $f.Right) $f.PrincipalName $f.TargetName $.ACLResult.Domain}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:#a0aec0">{{aclFix (print $f.Right)}}</div>
      </div>
    </div>
  </div>
  {{end}}
  {{else}}<p style="color:#68d391">✓ No dangerous ACL findings.</p>{{end}}
  {{else}}<p style="color:#718096">ACL data not available.</p>{{end}}
</div>

<!-- DELEGATION TAB -->
<div id="tab-delegation" class="tab-pane">
  <h2 class="section-title">
    Delegation Configurations
    <span>{{.Summary.DelegationCount}} finding(s)</span>
  </h2>
  {{if .DelegationResult}}
  {{if .DelegationResult.Findings}}
  {{range .DelegationResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge badge-critical">{{.DelegationType}}</span>
      <span class="mono" style="color:#e2e8f0">{{.SAMAccountName}}</span>
      <span class="badge" style="background:#2d3748;color:#a0aec0">{{.ObjectType}}</span>
      {{if .AllowedServices}}<span style="color:#718096;font-size:0.78rem">→ {{joinSPNs .AllowedServices}}</span>{{end}}
    </div>
    <div style="padding:4px 16px 0">
      <div style="color:#fc8181;font-size:0.8rem;padding-bottom:4px">⚠ {{.RiskReason}}</div>
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{.DelegationType}})</div>
        <span class="acc-cmd">{{delegExploit (print .DelegationType)}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:#a0aec0">{{delegFix (print .DelegationType)}}</div>
      </div>
    </div>
  </div>
  {{end}}
  {{else}}<p style="color:#68d391">✓ No dangerous delegation configurations.</p>{{end}}
  {{else}}<p style="color:#718096">Delegation data not available.</p>{{end}}
</div>

<!-- HYGIENE TAB -->
<div id="tab-hygiene" class="tab-pane">
  <h2 class="section-title">AD Hygiene &amp; Blue Team Checks</h2>

  <!-- krbtgt -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Kerberos Ticket Granting Ticket</div>
  <div style="background:#1a1f2e;border:1px solid #2d3748;border-radius:8px;padding:14px 18px;margin-bottom:20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    {{if .HygieneResult}}
    {{if .HygieneResult.KrbtgtAtRisk}}
    <span class="badge badge-critical">⚠ Golden Ticket Risk</span>
    <span style="color:#fc8181;font-size:0.9rem">krbtgt password last changed <strong>{{.HygieneResult.KrbtgtPwdAgeDays}} days ago</strong> ({{.HygieneResult.KrbtgtLastSet}})</span>
    <div style="width:100%;font-size:0.8rem;color:#718096;margin-top:4px">Recommendation: reset krbtgt password twice (interval &gt;10h) to invalidate all existing Kerberos tickets</div>
    {{else if gt .HygieneResult.KrbtgtPwdAgeDays 0}}
    <span class="badge badge-ok">✓ OK</span>
    <span style="color:#68d391;font-size:0.9rem">krbtgt password age: <strong>{{.HygieneResult.KrbtgtPwdAgeDays}} days</strong> ({{.HygieneResult.KrbtgtLastSet}})</span>
    {{else}}
    <span style="color:#718096;font-size:0.85rem">krbtgt data not available</span>
    {{end}}
    {{end}}
  </div>

  <!-- passwords in description -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Passwords in Description</div>
  {{if .HygieneResult}}{{if .HygieneResult.PasswordInDesc}}
  <div style="margin-bottom:8px">
    <button class="acc-toggle" onclick="toggleAcc(this)" style="background:#2a1a1a;color:#fc8181;margin-bottom:4px">
      ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix — Cleartext Credentials
    </button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">Use credentials found in description to authenticate: net use \\DC\IPC$ /user:domain\user &lt;password&gt;</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:#a0aec0">Remove passwords from all AD object description/info fields. Audit with: <span class="acc-cmd">Get-ADUser -Filter * -Properties Description | Where {$_.Description -match "pass"}</span></div>
    </div>
  </div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Account</th><th>Type</th><th>Description (potential password)</th></tr></thead>
    <tbody>
    {{range .HygieneResult.PasswordInDesc}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td><span class="badge" style="background:#2d3748;color:#a0aec0">{{.ObjectType}}</span></td>
      <td style="color:#fc8181;font-family:monospace;font-size:0.8rem">{{.Description}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391;margin-bottom:20px">✓ No passwords found in description attributes.</p>{{end}}{{end}}

  <!-- stale accounts -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Stale User Accounts (90+ days no logon, enabled)</div>
  {{if .HygieneResult}}{{if .HygieneResult.StaleUsers}}
  <div class="table-wrap" style="margin-bottom:20px">
  <table>
    <thead><tr><th>Account</th><th>Display Name</th><th>Last Logon</th><th>Pwd Last Set</th><th>AdminCount</th></tr></thead>
    <tbody>
    {{range .HygieneResult.StaleUsers}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.DisplayName}}</td>
      <td class="mono" style="color:#f6ad55">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391;margin-bottom:20px">✓ No stale user accounts found.</p>{{end}}{{end}}

  <!-- stale computers -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Stale Computers (45+ days no logon, enabled)</div>
  {{if .HygieneResult}}{{if .HygieneResult.StaleComputers}}
  <div class="table-wrap">
  <table>
    <thead><tr><th>Computer</th><th>OS</th><th>Last Logon</th><th>Domain</th></tr></thead>
    <tbody>
    {{range .HygieneResult.StaleComputers}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.OperatingSystem}}</td>
      <td class="mono" style="color:#f6ad55">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
      <td style="font-size:0.78rem;color:#718096">{{.Domain}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391">✓ No stale computers found.</p>{{end}}{{end}}

  <!-- PSO -->
  {{if .PSOResult}}{{if .PSOResult.PSOs}}
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-top:24px;margin-bottom:8px">Fine-Grained Password Policy (PSO)</div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>PSO Name</th><th>Precedence</th><th>Min Length</th><th>Complexity</th><th>Lockout</th><th>Max Age</th><th>Applies To</th><th>Status</th></tr></thead>
    <tbody>
    {{range .PSOResult.PSOs}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td>{{.Precedence}}</td>
      <td>{{.MinLength}}</td>
      <td>{{if .Complexity}}<span class="badge badge-ok">ON</span>{{else}}<span class="badge badge-critical">OFF</span>{{end}}</td>
      <td>{{if eq .LockoutThreshold 0}}<span class="badge badge-critical">∞</span>{{else}}{{.LockoutThreshold}}{{end}}</td>
      <td>{{if eq .MaxAgeDays 0}}<span class="badge badge-critical">Never</span>{{else}}{{.MaxAgeDays}}d{{end}}</td>
      <td style="font-size:0.78rem;color:#a0aec0">{{joinSPNs .AppliesTo}}</td>
      <td>{{if .IsWeak}}<span class="badge badge-critical">Weak</span>{{else}}<span class="badge badge-ok">OK</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}{{end}}
</div>

<!-- GPO TAB -->
<div id="tab-gpo" class="tab-pane">
  <h2 class="section-title">Group Policy Analysis</h2>
  {{if .GPOResult}}

  {{if .GPOResult.DefaultPolicy}}
  <h3 class="section-title" style="font-size:0.95rem; margin-top:16px">
    Default Domain Password Policy
  </h3>
  <div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))">
    {{$pp := .GPOResult.DefaultPolicy}}
    <div class="card {{if lt $pp.MinLength 8}}critical{{else if lt $pp.MinLength 12}}warning{{else}}ok{{end}}">
      <div class="value">{{$pp.MinLength}}</div>
      <div class="label">Min Password Length</div>
    </div>
    <div class="card {{if not $pp.Complexity}}critical{{else}}ok{{end}}">
      <div class="value">{{if $pp.Complexity}}ON{{else}}OFF{{end}}</div>
      <div class="label">Complexity</div>
    </div>
    <div class="card {{if eq $pp.LockoutThreshold 0}}critical{{else if gt $pp.LockoutThreshold 10}}warning{{else}}ok{{end}}">
      <div class="value">{{if eq $pp.LockoutThreshold 0}}∞{{else}}{{$pp.LockoutThreshold}}{{end}}</div>
      <div class="label">Lockout Threshold</div>
    </div>
    <div class="card {{if or (eq $pp.MaxAge 0) (gt $pp.MaxAge 3650)}}critical{{else if gt $pp.MaxAge 90}}warning{{else}}ok{{end}}">
      <div class="value">{{if or (eq $pp.MaxAge 0) (gt $pp.MaxAge 3650)}}∞{{else}}{{$pp.MaxAge}}d{{end}}</div>
      <div class="label">Max Password Age</div>
    </div>
    <div class="card {{if $pp.ReversibleEncryption}}critical{{else}}ok{{end}}">
      <div class="value">{{if $pp.ReversibleEncryption}}ON{{else}}OFF{{end}}</div>
      <div class="label">Reversible Encryption</div>
    </div>
  </div>
  {{end}}

  {{if .GPOResult.GPOFindings}}
  <h3 class="section-title" style="font-size:0.95rem; margin-top:24px">
    Dangerous GPO Findings <span>{{len .GPOResult.GPOFindings}}</span>
  </h3>
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>GPO Name</th><th>GUID</th><th>Linked To</th><th>Risk</th></tr>
    </thead>
    <tbody>
    {{range .GPOResult.GPOFindings}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td class="mono" style="font-size:0.75rem">{{.GUID}}</td>
      <td style="font-size:0.8rem">{{joinSPNs .LinkedTo}}</td>
      <td style="color:#fc8181; font-size:0.8rem">{{index .RiskReasons 0}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}

  {{else}}<p style="color:#718096">GPO data not available.</p>{{end}}
</div>

</div><!-- /content -->

<script>

// Findings calculation
(function() {
  var chart = document.getElementById('findings-chart');
  if (!chart) return;

  var findings = [
    {
      label: 'Critical',
      color: '#e53e3e',
      bg: '#742a2a',
      count: {{.Summary.CriticalCount}} + {{.Summary.DangerousACLCount}}
    },
    {
      label: 'High',
      color: '#dd6b20',
      bg: '#7b341e',
      count: {{.Summary.KerberoastableCount}} + {{.Summary.ASREPCount}} + {{.Summary.DelegationCount}}
    },
    {
      label: 'Medium',
      color: '#d69e2e',
      bg: '#744210',
      count: {{.Summary.PasswordNeverExpires}} + {{.Summary.AdminCount}}
    },
    {
      label: 'Info',
      color: '#4299e1',
      bg: '#2a4365',
      count: {{.Summary.TotalUsers}} + {{.Summary.TotalGroups}} + {{.Summary.TotalComputers}}
    }
  ];

  var max = Math.max.apply(null, findings.map(function(f){ return f.count; }));
  if (max === 0) max = 1;

  findings.forEach(function(f) {
    var pct = Math.round((f.count / max) * 100);
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:12px';
    row.innerHTML =
      '<div style="width:64px;font-size:12px;color:#718096;text-align:right">' + f.label + '</div>' +
      '<div style="flex:1;background:#2d3748;border-radius:4px;height:24px;overflow:hidden">' +
        '<div style="width:'+pct+'%;background:'+f.color+';height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px;transition:width .3s;min-width:'+(f.count > 0 ? '32px' : '0')+';">' +
          (f.count > 0 ? '<span style="font-size:12px;font-weight:500;color:#fff">'+f.count+'</span>' : '') +
        '</div>' +
      '</div>' +
      '<div style="width:32px;font-size:13px;font-weight:500;color:'+f.color+'">'+f.count+'</div>';
    chart.appendChild(row);
  });
})();
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

function showTabByClick(e, name) {
  e.stopPropagation();
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  const btn = document.querySelector('.nav button[onclick="showTab(\'' + name + '\')"]');
  if (btn) btn.classList.add('active');
  if (name === 'graph') initGraph();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============================================================
// Accordion toggle
// ============================================================
function toggleAcc(btn) {
  const body = btn.nextElementSibling;
  const open = body.classList.toggle('open');
  btn.textContent = btn.textContent.replace(/^[▶▼]/, open ? '▼' : '▶');
}

// ============================================================
// D3.js attack path graph (improved)
// ============================================================
let graphInitialized = false;
let zoomBehavior = null;
let svgRoot = null;

function resetZoom() {
  if (svgRoot && zoomBehavior) {
    svgRoot.transition().duration(400).call(zoomBehavior.transform, d3.zoomIdentity);
  }
}

function initGraph() {
  if (graphInitialized) return;
  graphInitialized = true;

  const data = {{.GraphJSON}};
  if (!data.nodes || data.nodes.length === 0) {
    document.getElementById('graph-container').innerHTML =
      '<p style="padding:40px;color:#718096;text-align:center">No attack paths to visualize.</p>';
    return;
  }

  // Count how many paths each node appears in (for sizing)
  const pathCount = {};
  data.nodes.forEach(n => { pathCount[n.id] = 0; });
  data.edges.forEach(e => {
    pathCount[e.source] = (pathCount[e.source] || 0) + 1;
    pathCount[e.target] = (pathCount[e.target] || 0) + 1;
  });
  const maxCount = Math.max(1, ...Object.values(pathCount));

  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight;

  const svg = d3.select('#graph-svg');
  svgRoot = svg;

  // Arrow marker
  svg.append('defs').selectAll('marker').data(['arrow','arrow-admin']).enter()
    .append('marker')
    .attr('id', d => d)
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 28).attr('refY', 0)
    .attr('markerWidth', 5).attr('markerHeight', 5)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', (d, i) => i === 1 ? '#fc8181' : '#4a5568');

  const g = svg.append('g');

  zoomBehavior = d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', e => g.attr('transform', e.transform));
  svg.call(zoomBehavior);

  // Simulation with stronger repulsion to prevent overlap
  const simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.edges).id(d => d.id).distance(150).strength(0.7))
    .force('charge', d3.forceManyBody().strength(-600))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(d => nodeRadius(d, pathCount, maxCount) + 15));

  // Edges
  const link = g.append('g').attr('class', 'links').selectAll('line')
    .data(data.edges).enter().append('line')
    .attr('stroke', d => {
      const tgt = data.nodes.find(n => n.id === (d.target.id || d.target));
      return (tgt && tgt.adminCount) ? '#fc8181' : '#4a5568';
    })
    .attr('stroke-opacity', 0.7)
    .attr('stroke-width', 2)
    .attr('marker-end', d => {
      const tgt = data.nodes.find(n => n.id === (d.target.id || d.target));
      return (tgt && tgt.adminCount) ? 'url(#arrow-admin)' : 'url(#arrow)';
    });

  // Edge type labels
  const edgeLabel = g.append('g').selectAll('text')
    .data(data.edges).enter().append('text')
    .attr('font-size', 9)
    .attr('fill', '#4a5568')
    .attr('text-anchor', 'middle')
    .text(d => d.type || '');

  // Node groups
  const tooltip = document.getElementById('graph-tooltip');

  const node = g.append('g').attr('class', 'nodes').selectAll('g')
    .data(data.nodes).enter().append('g')
    .on('mouseover', (e, d) => {
      const r = nodeRadius(d, pathCount, maxCount);
      tooltip.style.display = 'block';
      tooltip.innerHTML =
        '<div style="font-weight:600;color:#e2e8f0;margin-bottom:4px">' + d.label + '</div>' +
        '<div style="color:#718096;font-size:0.75rem;word-break:break-all">' + d.id + '</div>' +
        '<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">' +
        (d.adminCount ? '<span style="background:#742a2a;color:#fc8181;padding:2px 6px;border-radius:3px;font-size:11px">AdminCount</span>' : '') +
        (d.kerberoastable ? '<span style="background:#744210;color:#f6ad55;padding:2px 6px;border-radius:3px;font-size:11px">Kerberoastable</span>' : '') +
        (d.asrepRoastable ? '<span style="background:#742a2a;color:#feb2b2;padding:2px 6px;border-radius:3px;font-size:11px">AS-REP</span>' : '') +
        '<span style="background:#2d3748;color:#a0aec0;padding:2px 6px;border-radius:3px;font-size:11px">' + d.type + '</span>' +
        '<span style="background:#2d3748;color:#a0aec0;padding:2px 6px;border-radius:3px;font-size:11px">' + (pathCount[d.id]||0) + ' edge(s)</span>' +
        '</div>';
    })
    .on('mousemove', e => {
      const rect = container.getBoundingClientRect();
      let x = e.clientX - rect.left + 12, y = e.clientY - rect.top + 12;
      if (x + 290 > rect.width) x = e.clientX - rect.left - 290;
      tooltip.style.left = x + 'px';
      tooltip.style.top = y + 'px';
    })
    .on('mouseout', () => { tooltip.style.display = 'none'; })
    .call(d3.drag()
      .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (e, d) => { d.fx=e.x; d.fy=e.y; })
      .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }));

  node.append('circle')
    .attr('r', d => nodeRadius(d, pathCount, maxCount))
    .attr('fill', d => nodeColor(d))
    .attr('stroke', d => d.asrepRoastable ? '#fc8181' : (d.adminCount ? '#feb2b2' : '#2d3748'))
    .attr('stroke-width', d => d.adminCount || d.asrepRoastable ? 3 : 1.5)
    .attr('cursor', 'pointer');

  node.append('text')
    .attr('dy', d => nodeRadius(d, pathCount, maxCount) + 14)
    .attr('text-anchor', 'middle')
    .attr('font-size', 11)
    .attr('fill', '#e2e8f0')
    .attr('pointer-events', 'none')
    .text(d => d.label);

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    edgeLabel
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2 - 4);
    node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
  });
}

function nodeRadius(d, pathCount, maxCount) {
  const base = 16;
  const bonus = Math.round(((pathCount[d.id] || 0) / maxCount) * 10);
  return base + bonus;
}

function nodeColor(d) {
  if (d.adminCount)     return '#fc8181';
  if (d.kerberoastable) return '#f6ad55';
  if (d.asrepRoastable) return '#feb2b2';
  if (d.type === 'group')    return '#b794f4';
  if (d.type === 'computer') return '#90cdf4';
  return '#63b3ed';
}
</script>

</body>
</html>`