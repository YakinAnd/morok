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
	// v0.7
	UserPrivGroups map[string]string   // user DN → comma-separated privileged group names
	ADCSResult     *analysis.ADCSResult
	// v0.8.1
	ProtectedUsersResult *analysis.ProtectedUsersResult
	AdminSDHolderResult  *analysis.AdminSDHolderResult
	// v0.8.2
	TrustResult *analysis.TrustResult
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
	// v0.7
	NoLAPSCount             int
	ADCSTemplateCount       int
	ADCSCriticalCount       int
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
	adcsResult *analysis.ADCSResult,
	puResult *analysis.ProtectedUsersResult,
	adminSDResult *analysis.AdminSDHolderResult,
	trustResult *analysis.TrustResult,
	authMethod string,
) error {

	data := ReportData{
	Domain:               result.Domain,
	GeneratedAt:          time.Now().Format("2006-01-02 15:04:05"),
	AuthMethod:           authMethod,
	Users:                result.Users,
	Groups:               result.Groups,
	Computers:            result.Computers,
	AttackPaths:          paths,
	Summary:              buildSummary(result, paths, kr, aclResult, dr, gr, hr, adcsResult),
	GraphJSON:            template.JS(buildD3JSON(g, paths)),
	KerberosResult:       kr,
	ACLResult:            aclResult,
	DelegationResult:     dr,
	GPOResult:            gr,
	HygieneResult:        hr,
	PSOResult:            psoResult,
	ADCSResult:           adcsResult,
	ForestWide:           result.ForestWide,
	UserPrivGroups:       buildUserPrivGroups(result),
	ProtectedUsersResult: puResult,
	AdminSDHolderResult:  adminSDResult,
	TrustResult:          trustResult,
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

	color.Cyan("\n  report saved to: %s", outputPath)
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
	adcsResult *analysis.ADCSResult,
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
		s.NoLAPSCount = hr.NoLAPSCount
	}

	if adcsResult != nil {
		s.ADCSTemplateCount = len(adcsResult.TemplateFindings)
		for _, f := range adcsResult.TemplateFindings {
			if f.Severity == "Critical" {
				s.ADCSCriticalCount++
			}
		}
	}

	return s
}

// buildUserPrivGroups повертає map[userDN]→"DA, EA, ..." для кожного юзера
// що є членом привілейованих груп.
func buildUserPrivGroups(result *adldap.EnumerationResult) map[string]string {
	privNames := map[string]bool{
		"domain admins":              true,
		"enterprise admins":          true,
		"administrators":             true,
		"backup operators":           true,
		"account operators":          true,
		"schema admins":              true,
		"server operators":           true,
		"print operators":            true,
		"dnsadmins":                  true,
		"group policy creator owners": true,
	}
	// DN групи → коротка назва
	groupByDN := make(map[string]string, len(result.Groups))
	for _, g := range result.Groups {
		if privNames[strings.ToLower(g.SAMAccountName)] {
			groupByDN[strings.ToLower(g.DN)] = g.SAMAccountName
		}
	}
	out := make(map[string]string)
	for _, u := range result.Users {
		var found []string
		for _, dn := range u.MemberOf {
			if name, ok := groupByDN[strings.ToLower(dn)]; ok {
				found = append(found, name)
			}
		}
		if len(found) > 0 {
			out[u.DN] = strings.Join(found, ", ")
		}
	}
	return out
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
<title>adpath — {{.Domain}} — {{.GeneratedAt}}</title>
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

/* Global search */
.global-search-wrap { padding: 10px 40px; background: #1a1f2e; border-bottom: 1px solid #2d3748;
  display: flex; align-items: center; gap: 12px; }
.global-search-wrap input { flex: 1; max-width: 420px; padding: 7px 14px;
  background: #0f1117; border: 1px solid #2d3748; border-radius: 6px;
  color: #e2e8f0; font-size: 0.9rem; outline: none; }
.global-search-wrap input:focus { border-color: #63b3ed; }
.global-search-wrap input::placeholder { color: #4a5568; }
#gs-results { font-size: 0.82rem; color: #718096; min-width: 120px; }
.gs-match { background: #744210 !important; color: #fef3c7 !important;
  border-radius: 2px; padding: 0 2px; }

/* Nav tabs */
.nav { display: flex; gap: 2px; padding: 0 40px;
  background: #1a1f2e; border-bottom: 1px solid #2d3748; flex-wrap: wrap; }
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
  padding-bottom: 8px; border-bottom: 1px solid #2d3748; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.section-title span { color: #718096; font-size: 0.85rem; font-weight: 400; }

/* Help icon tooltip */
.help-icon { display:inline-flex; align-items:center; justify-content:center;
  width:16px; height:16px; border-radius:50%; background:#2d3748; color:#a0aec0;
  font-size:10px; font-weight:700; cursor:default; position:relative;
  flex-shrink:0; margin-left:2px; }
.help-icon::after { content: attr(data-tip);
  display:none; position:absolute; left:50%; bottom:calc(100% + 8px);
  transform:translateX(-50%); background:#1a202c; border:1px solid #4a5568;
  color:#e2e8f0; font-size:0.78rem; font-weight:400; line-height:1.5;
  padding:10px 14px; border-radius:6px; white-space:pre-wrap; width:300px;
  z-index:100; pointer-events:none; box-shadow:0 4px 16px rgba(0,0,0,.5); }
.help-icon:hover::after { display:block; }

/* Table filters */
.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; align-items: center; }
.filter-bar input[type=text] {
  background: #1a1f2e; border: 1px solid #2d3748; border-radius: 6px;
  color: #e2e8f0; padding: 6px 10px; font-size: 0.8rem; outline: none;
  min-width: 180px; }
.filter-bar input[type=text]:focus { border-color: #63b3ed; }
.filter-bar select {
  background: #1a1f2e; border: 1px solid #2d3748; border-radius: 6px;
  color: #e2e8f0; padding: 6px 10px; font-size: 0.8rem; outline: none;
  cursor: pointer; }
.filter-bar select:focus { border-color: #63b3ed; }
.filter-bar .filter-count { font-size: 0.78rem; color: #718096; margin-left: auto; }
.filter-bar button {
  background: #2d3748; border: none; border-radius: 6px; color: #a0aec0;
  padding: 6px 12px; font-size: 0.78rem; cursor: pointer; }
.filter-bar button:hover { background: #4a5568; color: #e2e8f0; }

/* Sortable table headers */
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: #e2e8f0; background: #252b3b; }
th.sort-asc::after  { content: ' ▲'; color: #63b3ed; }
th.sort-desc::after { content: ' ▼'; color: #63b3ed; }
</style>
</head>
<body>

<div class="header">
  <h1>⚔ adpath v0.6 — {{.Domain}} — {{.GeneratedAt}}</h1>
  <div class="meta">
    Domain: <span class="domain">{{.Domain}}</span> &nbsp;|&nbsp;
    Auth: <span style="color:#68d391">{{.AuthMethod}}</span> &nbsp;|&nbsp;
    Generated: {{.GeneratedAt}}
  </div>
</div>

<div class="global-search-wrap">
  <input id="gs-input" type="text" placeholder="🔍  Global search across all tabs..."
    oninput="globalSearch(this.value)" autocomplete="off">
  <span id="gs-results"></span>
  <button onclick="clearGlobalSearch()" style="background:#2d3748;border:none;color:#a0aec0;
    padding:6px 12px;border-radius:6px;cursor:pointer;font-size:0.82rem">✕ Clear</button>
</div>

<div class="nav">
  <button class="active" onclick="showTab('summary')">Summary</button>
  <button onclick="showTab('paths')">Attack Paths ({{.Summary.AttackPathsCount}})</button>
  <button onclick="showTab('graph')">Graph</button>
  <button onclick="showTab('kerberos')">Kerberos</button>
  <button onclick="showTab('acl')">ACL ({{.Summary.DangerousACLCount}})</button>
  <button onclick="showTab('delegation')">Delegation ({{.Summary.DelegationCount}})</button>
  <button onclick="showTab('exposure')">Exposure</button>
  <button onclick="showTab('gpo')">GPO</button>
  <button onclick="showTab('adcs')">ADCS {{if gt .Summary.ADCSTemplateCount 0}}({{.Summary.ADCSTemplateCount}}){{end}}</button>
  <button onclick="showTab('trusts')">Trusts {{if .TrustResult}}{{if .TrustResult.Trusts}}({{len .TrustResult.Trusts}}){{end}}{{end}}</button>
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
    <div class="card {{if gt .Summary.AttackPathsCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'paths')" title="View Attack Paths to privileged groups">
      <div class="value">{{.Summary.AttackPathsCount}}</div>
      <div class="label">Attack Paths</div>
    </div>
    <div class="card {{if gt .Summary.CriticalCount 0}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'paths')" title="Short paths (depth ≤ 2) are easiest to exploit">
      <div class="value">{{.Summary.CriticalCount}}</div>
      <div class="label">Short Paths (≤2 hops)</div>
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

  <!-- Exposure -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Exposure</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px">
    <div class="card {{if gt .Summary.PasswordNeverExpires 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'users')" title="View users with non-expiring passwords">
      <div class="value">{{.Summary.PasswordNeverExpires}}</div>
      <div class="label">Pwd Never Expires</div>
    </div>
    <div class="card {{if gt .Summary.AdminCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'users')" title="View admin-flagged users">
      <div class="value">{{.Summary.AdminCount}}</div>
      <div class="label">Admins</div>
    </div>
    <div class="card" onclick="showTabByClick(event,'users')" title="View all users">
      <div class="value">{{.Summary.EnabledUsers}}</div>
      <div class="label">Enabled Users</div>
    </div>
    <div class="card" onclick="showTabByClick(event,'computers')" title="View computers">
      <div class="value">{{.Summary.TotalComputers}}</div>
      <div class="label">Computers</div>
    </div>
    <div class="card {{if gt .Summary.StaleUsersCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'exposure')" title="View stale accounts">
      <div class="value">{{.Summary.StaleUsersCount}}</div>
      <div class="label">Stale Users (90d)</div>
    </div>
    <div class="card {{if gt .Summary.PasswordInDescCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'exposure')" title="View all object descriptions">
      <div class="value">{{.Summary.PasswordInDescCount}}</div>
      <div class="label">Have Description</div>
    </div>
    <div class="card {{if .Summary.KrbtgtAtRisk}}critical{{else}}ok{{end}}" onclick="showTabByClick(event,'exposure')" title="View krbtgt status">
      <div class="value">{{if eq .Summary.KrbtgtPwdAgeDays 0}}?{{else}}{{.Summary.KrbtgtPwdAgeDays}}d{{end}}</div>
      <div class="label">Krbtgt Pwd Age</div>
    </div>
    <div class="card {{if gt .Summary.NoLAPSCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'computers')" title="Computers without LAPS">
      <div class="value">{{.Summary.NoLAPSCount}}</div>
      <div class="label">No LAPS</div>
    </div>
    <div class="card {{if gt .Summary.ADCSCriticalCount 0}}critical{{else if gt .Summary.ADCSTemplateCount 0}}warning{{else}}ok{{end}}" onclick="showTabByClick(event,'adcs')" title="Vulnerable certificate templates">
      <div class="value">{{.Summary.ADCSTemplateCount}}</div>
      <div class="label">ADCS Vulns</div>
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
    <span class="help-icon" data-tip="A chain of AD relationships (group memberships, ACL rights, delegation) that leads a low-privileged account to Domain Admins or another privileged group. Depth 1 = direct member. Depth 2+ = indirect via nested groups or ACL abuse. Shorter paths = higher priority.">?</span>
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

<!-- TRUSTS TAB -->
<div id="tab-trusts" class="tab-pane">
  <h2 class="section-title">Domain &amp; Forest Trusts
    <span class="help-icon" data-tip="Domain trusts define authentication paths between domains. SID filtering disabled on a trust allows SID history abuse — an attacker in a trusted domain can forge SIDs to escalate privileges in this domain. Bidirectional forest trusts create lateral movement paths between forests. Foreign Security Principals (FSPs) are accounts from trusted domains added to local groups.">?</span>
  </h2>

  {{if .TrustResult}}

  {{if not .TrustResult.Trusts}}
  <p style="color:#718096;margin-bottom:20px">No trusts found — this may be a standalone domain.</p>
  {{else}}

  <!-- Trust table -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Configured Trusts</div>
  <div class="table-wrap" style="margin-bottom:24px">
  <table>
    <thead>
      <tr><th>Trusted Domain</th><th>NetBIOS</th><th>Direction</th><th>Type</th><th>SID Filtering</th><th>Severity</th><th>Risks</th></tr>
    </thead>
    <tbody>
    {{range .TrustResult.Trusts}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td class="mono" style="color:#718096">{{.FlatName}}</td>
      <td>{{.Direction}}</td>
      <td style="color:#a0aec0;font-size:0.82rem">{{.TrustType}}</td>
      <td>
        {{if .SIDFilteringOn}}
          <span class="badge badge-ok">ON ✓</span>
        {{else if .IsWithinForest}}
          <span class="badge" style="background:#2d3748;color:#a0aec0">Internal</span>
        {{else}}
          <span class="badge badge-critical">OFF ⚠</span>
        {{end}}
      </td>
      <td>
        {{if eq .Severity "Critical"}}<span class="badge badge-critical">Critical</span>
        {{else if eq .Severity "High"}}<span class="badge badge-medium">High</span>
        {{else if eq .Severity "Medium"}}<span class="badge" style="background:#744210;color:#fef3c7">Medium</span>
        {{else}}<span class="badge" style="background:#2d3748;color:#a0aec0">Info</span>{{end}}
      </td>
      <td style="font-size:0.78rem;color:#fc8181">
        {{range .Risks}}<div>⚠ {{.}}</div>{{end}}
      </td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>

  {{end}}

  <!-- Foreign Security Principals -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;display:flex;align-items:center;gap:6px">
    Foreign Security Principals in Privileged Groups
    <span class="help-icon" data-tip="Foreign Security Principals (FSPs) are objects representing users or groups from trusted external domains. If an FSP is a member of a privileged local group (Domain Admins, Administrators), an attacker who compromises the external domain gains privilege in this domain too.">?</span>
  </div>
  {{if .TrustResult.FSPs}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px;border-color:#e53e3e">
    <span class="badge badge-critical" style="margin-bottom:8px;display:inline-block">⚠ {{len .TrustResult.FSPs}} external principal(s) in privileged groups</span>
  </div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>External SID</th><th>Severity</th><th>Member of</th></tr></thead>
    <tbody>
    {{range .TrustResult.FSPs}}
    <tr>
      <td class="mono" style="font-size:0.8rem">{{.ExternalSID}}</td>
      <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td style="font-size:0.82rem;color:#a0aec0">{{joinSPNs .MemberOfGroups}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <p style="color:#68d391">✓ No foreign security principals found in privileged groups.</p>
  {{end}}

  {{else}}
  <p style="color:#718096">Trust data not available.</p>
  {{end}}
</div>

<!-- USERS TAB -->
<div id="tab-users" class="tab-pane">
  <h2 class="section-title">Users <span>{{.Summary.TotalUsers}} total</span></h2>
  <div class="filter-bar">
    <input type="text" placeholder="Search users..." oninput="filterTable('tbl-users','cnt-users')">
    <select data-col="3" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Enabled: all</option>
      <option value="Yes">Enabled only</option>
      <option value="No">Disabled only</option>
    </select>
    <select data-col="4" data-match="notempty" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Privileged: all</option>
      <option value="Domain Admins">Domain Admins</option>
      <option value="Enterprise Admins">Enterprise Admins</option>
      <option value="Administrators">Administrators</option>
      <option value="Backup Operators">Backup Operators</option>
      <option value="__notempty__">Any privileged</option>
    </select>
    <select data-col="5" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Kerberoastable: all</option>
      <option value="Yes">Yes</option>
    </select>
    <select data-col="6" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">AS-REP: all</option>
      <option value="Yes">Yes</option>
    </select>
    <select data-col="7" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Pwd Exp: all</option>
      <option value="Yes">Never expires</option>
    </select>
    <span class="filter-count" id="cnt-users"></span>
    <button onclick="clearFilters('tbl-users','cnt-users')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-users">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable(this)">Account</th>
        <th class="sortable" onclick="sortTable(this)">Display Name</th>
        <th class="sortable" onclick="sortTable(this)">Email</th>
        <th class="sortable" onclick="sortTable(this)">Enabled</th>
        <th class="sortable" onclick="sortTable(this)">Privileged Groups</th>
        <th class="sortable" onclick="sortTable(this)">Kerberoastable</th>
        <th class="sortable" onclick="sortTable(this)">AS-REP</th>
        <th class="sortable" onclick="sortTable(this)">Pwd Never Exp</th>
        <th class="sortable" onclick="sortTable(this)">Last Logon</th>
        <th class="sortable" onclick="sortTable(this)">Pwd Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .Users}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.DisplayName}}</td>
      <td style="font-size:0.78rem;color:#a0aec0">{{.Mail}}</td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:#2d3748;color:#718096">No</span>{{end}}</td>
      <td>{{with index $.UserPrivGroups .DN}}<span class="badge badge-critical" style="font-size:0.72rem">{{.}}</span>{{else}}—{{end}}</td>
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
  <div class="filter-bar">
    <input type="text" placeholder="Search groups..." oninput="filterTable('tbl-groups','cnt-groups')">
    <select data-col="1" onchange="filterTable('tbl-groups','cnt-groups')">
      <option value="">Type: all</option>
      <option value="Security">Security</option>
      <option value="Distribution">Distribution</option>
      <option value="Global">Global</option>
      <option value="Universal">Universal</option>
      <option value="Local">Local</option>
    </select>
    <select data-col="3" data-match="exact" onchange="filterTable('tbl-groups','cnt-groups')">
      <option value="">Admin: all</option>
      <option value="Yes">Admins only</option>
    </select>
    <span class="filter-count" id="cnt-groups"></span>
    <button onclick="clearFilters('tbl-groups','cnt-groups')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-groups">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable(this)">Name</th>
        <th class="sortable" onclick="sortTable(this)">Type</th>
        <th class="sortable" onclick="sortTable(this)">Members</th>
        <th class="sortable" onclick="sortTable(this)">Admin</th>
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
  <div class="filter-bar">
    <input type="text" placeholder="Search computers..." oninput="filterTable('tbl-computers','cnt-computers')">
    <select data-col="4" data-match="exact" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">Enabled: all</option>
      <option value="Yes">Enabled only</option>
      <option value="No">Disabled only</option>
    </select>
    <select data-col="5" data-match="exact" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">LAPS: all</option>
      <option value="Yes">LAPS enabled</option>
      <option value="No">No LAPS</option>
    </select>
    <span class="filter-count" id="cnt-computers"></span>
    <button onclick="clearFilters('tbl-computers','cnt-computers')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-computers">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable(this)">Name</th>
        <th class="sortable" onclick="sortTable(this)">Domain</th>
        <th class="sortable" onclick="sortTable(this)">OS</th>
        <th class="sortable" onclick="sortTable(this)">Version</th>
        <th class="sortable" onclick="sortTable(this)">Enabled</th>
        <th class="sortable" onclick="sortTable(this)">LAPS</th>
        <th class="sortable" onclick="sortTable(this)">Uncons. Deleg.</th>
        <th class="sortable" onclick="sortTable(this)">Last Logon</th>
        <th class="sortable" onclick="sortTable(this)">Created</th>
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
  <h2 class="section-title">Kerberos Attack Surface
    <span class="help-icon" data-tip="Kerberos is the primary authentication protocol in AD. Misconfigurations allow offline password cracking (Kerberoasting, AS-REP roasting) without triggering lockouts or alerts — attacker gets a hash and cracks it locally.">?</span>
  </h2>
  {{if .KerberosResult}}

  <h3 class="section-title" style="font-size:0.95rem; margin-top:16px">
    Kerberoastable Accounts
    <span>{{len .KerberosResult.KerberoastableAccounts}}</span>
    <span class="help-icon" data-tip="Accounts with a Service Principal Name (SPN) set. Any authenticated user can request a Kerberos ticket (TGS) for them and crack the hash offline. Severity rises sharply if the account has AdminCount=1 or is in a privileged group.">?</span>
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
    <span class="help-icon" data-tip="Accounts with 'Do not require Kerberos preauthentication' enabled. An attacker can request an AS-REP blob for these accounts without any credentials and crack the hash offline. No authentication required — works from outside the domain.">?</span>
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
    <span class="help-icon" data-tip="Access Control Lists define who can do what to each AD object. Misconfigurations like GenericAll, WriteDACL or ForceChangePassword allow an attacker to take over accounts or escalate to Domain Admin without exploiting any software vulnerability — just abusing legitimate AD permissions.">?</span>
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
  <div class="filter-bar" style="margin-bottom:12px">
    <input type="text" id="acl-search" placeholder="Search principal or target..." oninput="filterACL()" style="min-width:220px">
    <select id="acl-severity" onchange="filterACL()">
      <option value="">Severity: all</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
    </select>
    <select id="acl-right" onchange="filterACL()">
      <option value="">Right: all</option>
      <option value="GenericAll">GenericAll</option>
      <option value="WriteDACL">WriteDACL</option>
      <option value="WriteOwner">WriteOwner</option>
      <option value="ForceChangePassword">ForceChangePassword</option>
      <option value="AddMember">AddMember</option>
      <option value="GenericWrite">GenericWrite</option>
    </select>
    <span class="filter-count" id="cnt-acl"></span>
    <button onclick="document.getElementById('acl-search').value='';document.getElementById('acl-severity').value='';document.getElementById('acl-right').value='';filterACL()">Clear</button>
    <button id="btn-group-acl" onclick="toggleGroupACL()" style="margin-left:8px">⊞ Group</button>
  </div>
  <div id="acl-grouped" style="display:none"></div>
  <div id="acl-findings">
  {{range $i, $f := .ACLResult.Findings}}
  <div class="path-card acl-card" style="margin-bottom:10px" data-severity="{{$f.Severity}}" data-right="{{$f.Right}}" data-text="{{$f.PrincipalName}} {{$f.TargetName}}">
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
  </div>{{/* end acl-findings */}}
  {{else}}<p style="color:#68d391">✓ No dangerous ACL findings.</p>{{end}}
  {{else}}<p style="color:#718096">ACL data not available.</p>{{end}}
</div>

<!-- DELEGATION TAB -->
<div id="tab-delegation" class="tab-pane">
  <h2 class="section-title">
    Delegation Configurations
    <span>{{.Summary.DelegationCount}} finding(s)</span>
    <span class="help-icon" data-tip="Delegation allows a service to impersonate a user when accessing other services. Unconstrained delegation is the most dangerous — any account authenticating to that machine gives up their Kerberos ticket, which the attacker can reuse. Constrained and RBCD are less severe but still abusable.">?</span>
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

<!-- EXPOSURE TAB -->
<div id="tab-exposure" class="tab-pane">
  <h2 class="section-title">Exposure &amp; Attack Surface
    <span class="help-icon" data-tip="Attack surface metrics: stale accounts are unused entry points, LAPS absence means shared local admin passwords enabling lateral movement, old krbtgt password enables persistent Golden Ticket attacks, descriptions often leak credentials or internal IP ranges.">?</span>
  </h2>

  <!-- krbtgt -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;display:flex;align-items:center;gap:6px">Kerberos Ticket Granting Ticket <span class="help-icon" data-tip="The krbtgt account's password hash is used to sign all Kerberos tickets in the domain. If an attacker obtains this hash (e.g. via DCSync), they can forge Golden Tickets — valid for any user, including DA — that persist until the password is rotated TWICE. Microsoft recommends rotating every 180 days.">?</span></div>
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

  <!-- descriptions -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Description Notes — Users / Computers / Groups</div>
  <p style="color:#718096;font-size:0.8rem;margin-bottom:10px">All AD objects with a non-empty description are listed. Admins often leave credentials, IP addresses, or other sensitive information in these fields.</p>
  {{if .HygieneResult}}{{if .HygieneResult.PasswordInDesc}}
  <div class="filter-bar">
    <input type="text" placeholder="Search..." oninput="filterTable('tbl-desc','cnt-desc')">
    <select data-col="1" onchange="filterTable('tbl-desc','cnt-desc')">
      <option value="">Type: all</option>
      <option value="user">user</option>
      <option value="computer">computer</option>
      <option value="group">group</option>
    </select>
    <span class="filter-count" id="cnt-desc"></span>
    <button onclick="clearFilters('tbl-desc','cnt-desc')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-desc">
    <thead><tr><th>Account</th><th>Type</th><th>Description</th></tr></thead>
    <tbody>
    {{range .HygieneResult.PasswordInDesc}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td><span class="badge" style="background:#2d3748;color:#a0aec0">{{.ObjectType}}</span></td>
      <td style="font-family:monospace;font-size:0.8rem;color:#e2e8f0">{{.Description}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391;margin-bottom:20px">✓ No description attributes found.</p>{{end}}{{end}}

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

  <!-- LAPS -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-top:24px;margin-bottom:8px">Computers Without LAPS</div>
  {{if .HygieneResult}}
  {{if gt .Summary.NoLAPSCount 0}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px">
    <span class="badge badge-medium" style="margin-bottom:8px;display:inline-block">{{.Summary.NoLAPSCount}} / {{.Summary.TotalComputers}} computers have no LAPS</span>
    <div style="color:#a0aec0;font-size:0.85rem;margin-bottom:10px">Local Administrator Password Solution not deployed — local admin passwords may be identical across machines, enabling lateral movement.</div>
  </div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Computer</th><th>OS</th><th>Domain</th><th>Last Logon</th></tr></thead>
    <tbody>
    {{range .HygieneResult.NoLAPSComputers}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{.OperatingSystem}}</td>
      <td style="font-size:0.78rem;color:#718096">{{.Domain}}</td>
      <td class="mono" style="color:#a0aec0">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#68d391">✓ All enabled computers have LAPS deployed.</p>{{end}}
  {{end}}

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

  <!-- Protected Users -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-top:28px;margin-bottom:8px;display:flex;align-items:center;gap:6px">
    Protected Users Group
    <span class="help-icon" data-tip="Members of Protected Users cannot authenticate with NTLM, use RC4 encryption, or be subject to unconstrained delegation. DA/EA accounts outside this group are higher-risk credentials — an attacker capturing their NTLM hash can relay or crack it.">?</span>
  </div>
  {{if .ProtectedUsersResult}}
  {{if not .ProtectedUsersResult.ProtectedUsersExists}}
  <p style="color:#fc8181;font-size:0.85rem;margin-bottom:16px">⚠ Protected Users group not found — may not exist in this domain.</p>
  {{else if .ProtectedUsersResult.PrivilegedNotProtected}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px">
    <span class="badge badge-critical" style="margin-bottom:8px;display:inline-block">{{len .ProtectedUsersResult.PrivilegedNotProtected}} privileged accounts not in Protected Users</span>
    <div style="color:#a0aec0;font-size:0.8rem;margin-bottom:10px">NTLM auth, RC4 encryption, and unconstrained delegation are not blocked for these accounts.</div>
  </div>
  <div class="table-wrap" style="margin-bottom:20px">
  <table>
    <thead><tr><th>Account</th><th>Severity</th><th>Privileged Groups</th></tr></thead>
    <tbody>
    {{range .ProtectedUsersResult.PrivilegedNotProtected}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td style="font-size:0.82rem;color:#a0aec0">{{joinSPNs .Groups}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <p style="color:#68d391;margin-bottom:16px">✓ All privileged accounts are in Protected Users ({{len .ProtectedUsersResult.Members}} members).</p>
  {{end}}
  {{end}}

  <!-- AdminSDHolder -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:8px;display:flex;align-items:center;gap:6px">
    AdminSDHolder
    <span class="help-icon" data-tip="AdminSDHolder (CN=AdminSDHolder,CN=System) is a template object whose ACL is copied to all protected objects every 60 minutes by SDProp. A custom ACE here is a persistence backdoor — attacker retains access even after password reset. Orphaned adminCount=1 accounts had their ACL hardened but are no longer monitored.">?</span>
  </div>
  {{if .AdminSDHolderResult}}
  {{if .AdminSDHolderResult.CustomACEs}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px;border-color:#e53e3e">
    <span class="badge badge-critical" style="margin-bottom:8px;display:inline-block">⚠ {{len .AdminSDHolderResult.CustomACEs}} backdoor ACE(s) on AdminSDHolder</span>
    <div style="color:#fc8181;font-size:0.8rem;margin-bottom:10px">These ACEs are replicated to ALL protected objects every 60 min. Remove immediately.</div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Principal</th><th>SID</th><th>Rights</th></tr></thead>
      <tbody>
      {{range .AdminSDHolderResult.CustomACEs}}
      <tr>
        <td class="mono" style="color:#fc8181">{{.PrincipalName}}</td>
        <td class="mono" style="font-size:0.75rem;color:#718096">{{.PrincipalSID}}</td>
        <td style="color:#f6ad55;font-size:0.82rem">{{joinSPNs .Rights}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}
  {{if .AdminSDHolderResult.OrphanedAdminCount}}
  <div style="margin-bottom:16px">
    <span class="badge badge-medium" style="margin-bottom:8px;display:inline-block">{{len .AdminSDHolderResult.OrphanedAdminCount}} orphaned adminCount=1 account(s)</span>
    <div style="color:#a0aec0;font-size:0.8rem;margin-bottom:8px">adminCount=1 but not in any privileged group — SDProp no longer manages these objects.</div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Account</th><th>Status</th></tr></thead>
      <tbody>
      {{range .AdminSDHolderResult.OrphanedAdminCount}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td>{{if .Enabled}}<span class="badge badge-medium">enabled</span>{{else}}<span class="badge" style="background:#2d3748;color:#718096">disabled</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}
  {{if and (not .AdminSDHolderResult.CustomACEs) (not .AdminSDHolderResult.OrphanedAdminCount)}}
  <p style="color:#68d391;margin-bottom:16px">✓ No AdminSDHolder issues found.</p>
  {{end}}
  {{end}}

</div>

<!-- GPO TAB -->
<div id="tab-gpo" class="tab-pane">
  <h2 class="section-title">Group Policy Analysis
    <span class="help-icon" data-tip="Group Policy controls security settings across the domain: password complexity, lockout thresholds, audit logging. Weak password policy (min length &lt;8, no complexity, no lockout) makes brute-force and spray attacks viable. GPP Preferences may contain encrypted passwords (MS14-025) decryptable with a public AES key.">?</span>
  </h2>
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

  <!-- GPO ACL -->
  {{if .GPOResult}}{{if .GPOResult.GPOACLFindings}}
  <h3 class="section-title" style="font-size:0.95rem;margin-top:28px;display:flex;align-items:center;gap:6px">
    GPO Write ACL Findings
    <span class="help-icon" data-tip="Low-privileged principals with WriteDACL, WriteOwner, GenericAll, or GenericWrite on GPO objects can modify them to add malicious startup scripts, logon tasks, or local admin accounts. GPOs linked to Domain Controllers OU are Critical — compromise affects all DCs.">?</span>
  </h3>
  <div class="table-wrap">
  <table>
    <thead><tr><th>GPO</th><th>Severity</th><th>Principal</th><th>Rights</th><th>Linked To</th></tr></thead>
    <tbody>
    {{range .GPOResult.GPOACLFindings}}
    <tr>
      <td class="mono">{{.GPOName}}</td>
      <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td class="mono">{{.PrincipalName}}</td>
      <td style="color:#f6ad55;font-size:0.82rem">{{joinSPNs .Rights}}</td>
      <td style="font-size:0.78rem;color:#a0aec0">{{joinSPNs .GPOLinkedTo}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}{{end}}

  {{else}}<p style="color:#718096">GPO data not available.</p>{{end}}
</div>

<!-- ADCS TAB -->
<div id="tab-adcs" class="tab-pane">
  <h2 class="section-title">
    Active Directory Certificate Services
    <span class="help-icon" data-tip="ADCS misconfigurations allow attackers to forge certificates and authenticate as any domain user including Domain Admins. ESC1: attacker controls Subject Alternative Name → impersonate DA. ESC6: CA-level flag allows SAN injection for all templates. ESC8: NTLM relay to HTTP enrollment endpoint.">?</span>
  </h2>

  {{if .ADCSResult}}

  <!-- CAs -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Certificate Authorities</div>
  {{if .ADCSResult.CAs}}
  <div class="table-wrap" style="margin-bottom:20px">
  <table>
    <thead><tr><th>CA Name</th><th>Server</th><th>ESC6</th><th>ESC8 (check)</th></tr></thead>
    <tbody>
    {{range .ADCSResult.CAs}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td class="mono" style="color:#a0aec0">{{.Server}}</td>
      <td>{{if gt .EditFlags 262143}}<span class="badge badge-critical">YES</span>{{else}}—{{end}}</td>
      <td style="font-size:0.78rem;color:#718096">http://{{.Server}}/certsrv/</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:#718096">No CAs found.</p>{{end}}

  <!-- CA Findings (ESC6) -->
  {{range .ADCSResult.CAFindings}}
  {{if eq (index .VulnTypes 0) "ESC6"}}
  <div class="path-card" style="margin-bottom:10px;border-color:#e53e3e">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge badge-critical">Critical</span>
      <span class="badge badge-critical" style="font-family:monospace">ESC6</span>
      <span class="mono" style="color:#e2e8f0">{{.CAName}}</span>
    </div>
    <div style="padding:8px 16px">
      <div style="color:#a0aec0;font-size:0.85rem;margin-bottom:8px">{{.Details}}</div>
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;Exploit &nbsp;/&nbsp; Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit</div>
        <span class="acc-cmd">certipy req -u user@{{$.ADCSResult.Domain}} -p pass -ca {{.CAName}} -template User -upn admin@{{$.ADCSResult.Domain}}</span>
        <span class="acc-cmd" style="margin-top:4px">certipy auth -pfx admin.pfx -domain {{$.ADCSResult.Domain}} -dc-ip &lt;DC&gt;</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:#a0aec0">Run: <code>certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2</code> on CA, then restart CertSvc.</div>
      </div>
    </div>
  </div>
  {{end}}
  {{end}}

  <!-- Template Findings -->
  <div style="font-size:11px;font-weight:500;color:#718096;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;margin-top:8px">Vulnerable Templates ({{.Summary.ADCSTemplateCount}})</div>
  {{if .ADCSResult.TemplateFindings}}
  {{range .ADCSResult.TemplateFindings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span>
      {{range .VulnTypes}}<span class="badge badge-critical" style="font-family:monospace">{{.}}</span>{{end}}
      <span class="mono" style="color:#e2e8f0">{{.TemplateName}}</span>
      {{if .EKUs}}<span class="badge" style="background:#2d3748;color:#a0aec0;margin-left:auto">{{range $i,$e := .EKUs}}{{if $i}}, {{end}}{{$e}}{{end}}</span>{{end}}
    </div>
    <div style="padding:0 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;Exploit &nbsp;/&nbsp; Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{range $i,$v := .VulnTypes}}{{if $i}}, {{end}}{{$v}}{{end}})</div>
        {{if .AllowsSANInject}}
        <span class="acc-cmd">certipy req -u user@{{$.ADCSResult.Domain}} -p pass -ca &lt;CA&gt; -template {{.TemplateName}} -upn admin@{{$.ADCSResult.Domain}}</span>
        <span class="acc-cmd" style="margin-top:4px">certipy auth -pfx admin.pfx -domain {{$.ADCSResult.Domain}} -dc-ip &lt;DC&gt;</span>
        {{else}}
        <span class="acc-cmd">certipy find -u user@{{$.ADCSResult.Domain}} -p pass -dc-ip &lt;DC&gt; -vulnerable</span>
        {{end}}
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:#a0aec0">Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from template, restrict enrollment to specific groups, require CA manager approval, or disable the template if unused.</div>
      </div>
    </div>
  </div>
  {{end}}
  {{else}}<p style="color:#68d391">✓ No vulnerable certificate templates found.</p>{{end}}

  {{else}}<p style="color:#718096">ADCS data not available — run with full enum or use adpath adcs command.</p>{{end}}
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
  // replace only the arrow character, preserve the rest of innerHTML
  btn.innerHTML = btn.innerHTML.replace(/[▶▼]/, open ? '▼' : '▶');
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
        (d.adminCount ? '<span style="background:#742a2a;color:#fc8181;padding:2px 6px;border-radius:3px;font-size:11px">Admin</span>' : '') +
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

// ── Table sorting ─────────────────────────────────────────────
// Cycle: none → asc (▲) → desc (▼) → none (original order restored)
function sortTable(th) {
  const table = th.closest('table');
  const tbody = table.tBodies[0];
  const ths   = Array.from(th.closest('tr').querySelectorAll('th.sortable'));
  const col   = ths.indexOf(th);

  // save original order once per table
  if (!table._origOrder) {
    table._origOrder = Array.from(tbody.rows).map(r => r);
  }

  // determine next state: none→asc, asc→desc, desc→none
  const wasAsc  = th.classList.contains('sort-asc');
  const wasDesc = th.classList.contains('sort-desc');

  // reset all headers
  ths.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));

  if (!wasAsc && !wasDesc) {
    // none → asc
    th.classList.add('sort-asc');
    const rows = Array.from(tbody.rows).sort((a, b) => cmp(a, b, col, true));
    rows.forEach(r => tbody.appendChild(r));
  } else if (wasAsc) {
    // asc → desc
    th.classList.add('sort-desc');
    const rows = Array.from(tbody.rows).sort((a, b) => cmp(a, b, col, false));
    rows.forEach(r => tbody.appendChild(r));
  } else {
    // desc → none: restore original order
    table._origOrder.forEach(r => tbody.appendChild(r));
  }
}

function cmp(a, b, col, asc) {
  const ta = a.cells[col]?.textContent?.trim() ?? '';
  const tb = b.cells[col]?.textContent?.trim() ?? '';
  const na = parseFloat(ta), nb = parseFloat(tb);
  if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
  return asc ? ta.localeCompare(tb) : tb.localeCompare(ta);
}

// ── Table filters ─────────────────────────────────────────────
// ── Highlight helpers ─────────────────────────────────────────
function highlightCell(cell, query) {
  // restore original innerHTML before re-highlighting
  if (cell._origHTML !== undefined) cell.innerHTML = cell._origHTML;
  else cell._origHTML = cell.innerHTML;
  if (!query) return;
  const re = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  // only walk text nodes to avoid breaking badge HTML
  const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);
  nodes.forEach(tn => {
    if (!re.test(tn.textContent)) return;
    re.lastIndex = 0;
    const wrap = document.createElement('span');
    wrap.innerHTML = tn.textContent.replace(re,
      m => '<mark style="background:#f6e05e;color:#1a202c;border-radius:2px;padding:0 1px">' + m + '</mark>');
    tn.parentNode.replaceChild(wrap, tn);
  });
}

function restoreCell(cell) {
  if (cell._origHTML !== undefined) {
    cell.innerHTML = cell._origHTML;
  }
}

// ── Table filters ─────────────────────────────────────────────
function filterTable(tableId, countId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const wrap = table.closest('.table-wrap');
  const bar  = wrap ? wrap.previousElementSibling : table.previousElementSibling;

  // single search input — searches ALL columns
  const searchInput = bar ? bar.querySelector('input[type=text]') : null;
  const query = searchInput ? searchInput.value.trim() : '';
  const queryLow = query.toLowerCase();

  // dropdown filters — still column-specific
  const selects = bar ? bar.querySelectorAll('select') : [];

  const rows = table.tBodies[0].rows;
  let visible = 0;

  for (const row of rows) {
    let show = true;

    // text: check against full row text
    if (queryLow && !row.textContent.toLowerCase().includes(queryLow)) show = false;

    // dropdowns
    if (show) {
      selects.forEach(sel => {
        if (!sel.value) return;
        const col  = parseInt(sel.dataset.col ?? '0');
        const cell = row.cells[col]?.textContent?.trim() ?? '';
        if (sel.dataset.match === 'exact') {
          if (cell !== sel.value) show = false;
        } else if (sel.dataset.match === 'notempty') {
          if (sel.value === '__notempty__') {
            if (cell === '' || cell === '—') show = false;
          } else {
            if (!cell.toLowerCase().includes(sel.value.toLowerCase())) show = false;
          }
        } else {
          if (!cell.toLowerCase().includes(sel.value.toLowerCase())) show = false;
        }
      });
    }

    row.style.display = show ? '' : 'none';
    if (show) visible++;

    // highlight / restore each cell
    Array.from(row.cells).forEach(cell => {
      if (show && queryLow) highlightCell(cell, query);
      else restoreCell(cell);
    });
  }

  if (countId) {
    const el = document.getElementById(countId);
    if (el) el.textContent = visible + ' / ' + rows.length;
  }
}

function clearFilters(tableId, countId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const wrap = table.closest('.table-wrap');
  const bar  = wrap ? wrap.previousElementSibling : table.previousElementSibling;
  if (bar) {
    bar.querySelectorAll('input[type=text]').forEach(i => i.value = '');
    bar.querySelectorAll('select').forEach(s => s.value = '');
  }
  filterTable(tableId, countId);
}

function filterACL() {
  const q        = (document.getElementById('acl-search')?.value   ?? '').toLowerCase();
  const severity = (document.getElementById('acl-severity')?.value ?? '');
  const right    = (document.getElementById('acl-right')?.value    ?? '');
  const cards    = document.querySelectorAll('#acl-findings .acl-card');
  let visible = 0;
  cards.forEach(card => {
    const text = (card.dataset.text ?? '').toLowerCase();
    const show =
      (!q        || text.includes(q)) &&
      (!severity || card.dataset.severity === severity) &&
      (!right    || card.dataset.right === right);
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const cnt = document.getElementById('cnt-acl');
  if (cnt) cnt.textContent = visible + ' / ' + cards.length;
}

// ── Global search ─────────────────────────────────────────────
// Searches all text in all tab-panes, highlights matches, shows result count.
// Navigates to the tab with the most matches on Enter.
let _gsMatches = []; // [{tabName, el, origHTML}]

function globalSearch(query) {
  // restore all previous highlights
  _gsMatches.forEach(m => { if (m.el) m.el.innerHTML = m.origHTML; });
  _gsMatches = [];

  const q = query.trim();
  if (!q) {
    document.getElementById('gs-results').textContent = '';
    return;
  }

  const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(' + escaped + ')', 'gi');

  // count matches per tab
  const tabCounts = {};
  document.querySelectorAll('.tab-pane').forEach(pane => {
    const tabName = pane.id.replace('tab-', '');
    let count = 0;
    // walk text nodes — highlight only leaf text
    const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT, {
      acceptNode: n => {
        const p = n.parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        const tag = p.tagName;
        if (tag === 'SCRIPT' || tag === 'STYLE') return NodeFilter.FILTER_REJECT;
        if (!n.textContent.toLowerCase().includes(q.toLowerCase())) return NodeFilter.FILTER_SKIP;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(textNode => {
      const span = textNode.parentElement;
      if (!span || span.classList.contains('gs-match')) return;
      const orig = span.innerHTML;
      const highlighted = orig.replace(re, '<mark class="gs-match">$1</mark>');
      if (highlighted !== orig) {
        _gsMatches.push({ el: span, origHTML: orig });
        span.innerHTML = highlighted;
        count += (orig.match(re) || []).length;
      }
    });
    if (count > 0) tabCounts[tabName] = count;
  });

  const total = Object.values(tabCounts).reduce((a, b) => a + b, 0);
  const tabList = Object.entries(tabCounts).map(([t, c]) => t + '(' + c + ')').join(', ');
  document.getElementById('gs-results').textContent =
    total > 0 ? total + ' matches — ' + tabList : 'no matches';

  // auto-navigate to tab with most matches
  if (total > 0) {
    const best = Object.entries(tabCounts).sort((a, b) => b[1] - a[1])[0][0];
    const btn = document.querySelector('.nav button[onclick="showTab(\'' + best + '\')"]');
    if (btn) {
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-' + best).classList.add('active');
      btn.classList.add('active');
      if (best === 'graph') initGraph();
    }
  }
}

function clearGlobalSearch() {
  _gsMatches.forEach(m => { if (m.el) m.el.innerHTML = m.origHTML; });
  _gsMatches = [];
  const inp = document.getElementById('gs-input');
  if (inp) inp.value = '';
  document.getElementById('gs-results').textContent = '';
}

let _aclGrouped = false;
function toggleGroupACL() {
  _aclGrouped = !_aclGrouped;
  const btn     = document.getElementById('btn-group-acl');
  const flat    = document.getElementById('acl-findings');
  const grouped = document.getElementById('acl-grouped');
  const bar     = document.querySelector('#tab-acl .filter-bar');
  if (_aclGrouped) {
    buildGroupedACL();
    flat.style.display    = 'none';
    grouped.style.display = '';
    if (bar) bar.style.opacity = '0.4';
    if (btn) btn.textContent = '\u2630 Flat';
  } else {
    flat.style.display    = '';
    grouped.style.display = 'none';
    if (bar) bar.style.opacity = '';
    if (btn) btn.textContent = '\u229e Group';
  }
}

function buildGroupedACL() {
  const cards = document.querySelectorAll('#acl-findings .acl-card');
  const groups = {};
  const order  = [];
  const sevOrder = { 'Critical': 0, 'High': 1, 'Medium': 2 };
  cards.forEach(function(card) {
    const right = card.dataset.right || 'Unknown';
    const sev   = card.dataset.severity || 'Medium';
    if (!groups[right]) { groups[right] = { cards: [], severity: sev }; order.push(right); }
    groups[right].cards.push(card);
  });
  order.sort(function(a, b) {
    return (sevOrder[groups[a].severity] ?? 9) - (sevOrder[groups[b].severity] ?? 9);
  });

  const container = document.getElementById('acl-grouped');
  container.innerHTML = '';
  order.forEach(function(right) {
    const g     = groups[right];
    const count = g.cards.length;
    const sevClass = g.severity === 'Critical' ? 'badge-critical' : g.severity === 'High' ? 'badge-medium' : 'badge-ok';

    const section = document.createElement('div');
    section.style.cssText = 'margin-bottom:12px;border:1px solid #2d3748;border-radius:8px;overflow:hidden';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:10px;padding:12px 16px;background:#1a202c;cursor:pointer;user-select:none';
    header.innerHTML =
      '<span class="chevron" style="color:#718096;font-size:12px;min-width:10px">&#9658;</span>' +
      '<span class="badge badge-critical" style="font-family:monospace">' + right + '</span>' +
      '<span style="color:#e2e8f0;font-weight:600">' + count + ' finding' + (count !== 1 ? 's' : '') + '</span>' +
      '<span class="badge ' + sevClass + '" style="margin-left:auto">' + g.severity + '</span>';

    const body = document.createElement('div');
    body.style.display = 'none';
    body.style.padding = '8px';
    g.cards.forEach(function(card) {
      var clone = card.cloneNode(true);
      clone.style.display = '';
      body.appendChild(clone);
    });

    header.onclick = function() {
      var open = body.style.display !== 'none';
      body.style.display = open ? 'none' : '';
      header.querySelector('.chevron').innerHTML = open ? '&#9658;' : '&#9660;';
    };

    section.appendChild(header);
    section.appendChild(body);
    container.appendChild(section);
  });
}
</script>

</body>
</html>`