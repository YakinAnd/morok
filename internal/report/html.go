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
	// v0.9.0
	ShadowCredentialsResult *analysis.ShadowCredentialsResult
	LDAPSecurityResult      *analysis.LDAPSecurityResult
	// v0.9.4
	AuditResult *analysis.AuditResult
	// v0.9.6
	SMBSigningResult *analysis.SMBSigningResult
	// header risk summary
	TotalCritical int
	TotalHigh     int
	TotalMedium   int
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
	// v0.9.0
	ShadowCredCount         int
	// v0.9.4
	AuditFindingCount       int
	RecycleBinEnabled       bool
	MachineAccountQuota     int
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
	shadowResult   *analysis.ShadowCredentialsResult,
	ldapSecResult  *analysis.LDAPSecurityResult,
	auditResult    *analysis.AuditResult,
	smbResult      *analysis.SMBSigningResult,
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
	Summary:              buildSummary(result, paths, kr, aclResult, dr, gr, hr, adcsResult, auditResult),
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
	ProtectedUsersResult:    puResult,
	AdminSDHolderResult:     adminSDResult,
	TrustResult:             trustResult,
	ShadowCredentialsResult: shadowResult,
	LDAPSecurityResult:      ldapSecResult,
	AuditResult:             auditResult,
	SMBSigningResult:        smbResult,
}
	if shadowResult != nil {
		data.Summary.ShadowCredCount = len(shadowResult.Findings)
	}
	data.TotalCritical, data.TotalHigh, data.TotalMedium = countRiskTotals(&data)

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
	auditResult *analysis.AuditResult,
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

	if auditResult != nil {
		s.AuditFindingCount = len(auditResult.Findings)
		s.RecycleBinEnabled = auditResult.RecycleBinEnabled
		s.MachineAccountQuota = auditResult.MachineAccountQuota
	}

	return s
}

// countRiskTotals aggregates Critical/High/Medium findings across all modules.
func countRiskTotals(d *ReportData) (critical, high, medium int) {
	bucket := func(sev string) {
		switch sev {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		}
	}
	if d.ACLResult != nil {
		for _, f := range d.ACLResult.Findings {
			bucket(f.Severity)
		}
		for range d.ACLResult.DCSyncFindings {
			critical++
		}
	}
	if d.KerberosResult != nil {
		for _, a := range d.KerberosResult.KerberoastableAccounts {
			bucket(a.Severity)
		}
		for _, a := range d.KerberosResult.ASREPAccounts {
			bucket(a.Severity)
		}
	}
	if d.ADCSResult != nil {
		for _, f := range d.ADCSResult.TemplateFindings {
			bucket(f.Severity)
		}
		for _, f := range d.ADCSResult.CAFindings {
			bucket(f.Severity)
		}
	}
	if d.DelegationResult != nil {
		for _, f := range d.DelegationResult.Findings {
			bucket(f.Severity)
		}
	}
	if d.TrustResult != nil {
		for _, t := range d.TrustResult.Trusts {
			bucket(t.Severity)
		}
		for _, f := range d.TrustResult.FSPs {
			bucket(f.Severity)
		}
	}
	if d.ShadowCredentialsResult != nil {
		for _, f := range d.ShadowCredentialsResult.Findings {
			bucket(f.Severity)
		}
	}
	if d.LDAPSecurityResult != nil {
		for _, f := range d.LDAPSecurityResult.Findings {
			bucket(f.Severity)
		}
	}
	if d.SMBSigningResult != nil {
		for _, f := range d.SMBSigningResult.Findings {
			bucket(f.Severity)
		}
	}
	if d.GPOResult != nil {
		for _, f := range d.GPOResult.GPOACLFindings {
			bucket(f.Severity)
		}
	}
	if d.AdminSDHolderResult != nil {
		for _, f := range d.AdminSDHolderResult.CustomACEs {
			bucket(f.Severity)
		}
	}
	return
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
		"mitreBadges": func(key string) template.HTML {
			techs := analysis.LookupTechniques(analysis.MitreKey(key))
			if len(techs) == 0 {
				return ""
			}
			var out string
			for _, t := range techs {
				out += `<a class="mitre-badge" href="` + t.URL() + `" target="_blank" rel="noopener" title="` + t.Name + `">` + t.ID + `</a>`
			}
			return template.HTML(out)
		},
		"mitreForRight": func(right string) template.HTML {
			keyMap := map[string]analysis.MitreKey{
				"GenericAll":          analysis.MitreACLAbuse,
				"WriteDACL":           analysis.MitreACLAbuse,
				"WriteOwner":          analysis.MitreACLAbuse,
				"GenericWrite":        analysis.MitreACLAbuse,
				"ForceChangePassword": analysis.MitreForceChangePwd,
				"AddMember":           analysis.MitreAddMember,
			}
			key, ok := keyMap[right]
			if !ok {
				return ""
			}
			techs := analysis.LookupTechniques(key)
			var out string
			for _, t := range techs {
				out += `<a class="mitre-badge" href="` + t.URL() + `" target="_blank" rel="noopener" title="` + t.Name + `">` + t.ID + `</a>`
			}
			return template.HTML(out)
		},
		"mitreForDeleg": func(delegType string) template.HTML {
			keyMap := map[string]analysis.MitreKey{
				"Unconstrained":           analysis.MitreUnconstrainedDel,
				"Constrained":             analysis.MitreConstrainedDel,
				"Resource-Based Constrained": analysis.MitreRBCD,
			}
			key, ok := keyMap[delegType]
			if !ok {
				return ""
			}
			techs := analysis.LookupTechniques(key)
			var out string
			for _, t := range techs {
				out += `<a class="mitre-badge" href="` + t.URL() + `" target="_blank" rel="noopener" title="` + t.Name + `">` + t.ID + `</a>`
			}
			return template.HTML(out)
		},
		"dialectName": func(d uint16) string {
			switch d {
			case 0x0202:
				return "SMB 2.0.2"
			case 0x0210:
				return "SMB 2.1"
			case 0x0300:
				return "SMB 3.0"
			case 0x0302:
				return "SMB 3.0.2"
			case 0x0311:
				return "SMB 3.1.1"
			default:
				return fmt.Sprintf("0x%04x", d)
			}
		},
		"pathExploit": func(nodes []graph.Node, targetGroup string) string {
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
			type tpl struct{ exploit string }
			exploits := map[string]string{
				"Domain Admins":              "Transitive DA membership — existing credentials grant full domain compromise via net use \\\\DC\\IPC$, WinRM, or DCSync",
				"Enterprise Admins":          "Transitive EA membership — forest-wide compromise; can modify schema and enterprise-level objects",
				"Group Policy Creator Owners": "Member of GPCO — can create/modify GPOs linked to OUs/domain → SYSTEM on any joined machine via scheduled task or startup script",
				"Account Operators":          "Member of Account Operators — can create/modify users and groups (except protected) → password reset on non-AdminSDHolder accounts",
				"Backup Operators":           "Member of Backup Operators — SeBackupPrivilege on DC → dump NTDS.dit via diskshadow + robocopy → offline DCSync",
				"Server Operators":           "Member of Server Operators — can manage services on DCs → install malicious service as SYSTEM → DA escalation",
				"Print Operators":            "Member of Print Operators — SeLoadDriverPrivilege → load malicious kernel driver on DC → SYSTEM",
				"DNSAdmins":                  "Member of DnsAdmins — DLL injection via dnscmd ServerLevelPluginDll → SYSTEM on DC running DNS service",
			}
			if e, ok := exploits[targetGroup]; ok {
				return e
			}
			return "Account has transitive membership in " + targetGroup + " — existing credentials grant privileged access"
		},
		"pathFix": func(targetGroup string) string {
			fixes := map[string]string{
				"Domain Admins":              "Enforce least-privilege; remove transitive paths; apply AD Tiered Administration. Audit: Get-ADGroupMember 'Domain Admins' -Recursive",
				"Enterprise Admins":          "EA should be empty in steady-state; populate only for forest-level changes. Audit: Get-ADGroupMember 'Enterprise Admins' -Recursive",
				"Group Policy Creator Owners": "Remove non-admins from GPCO; restrict GPO creation to dedicated T0 accounts; monitor SYSVOL for new GPOs. Audit: Get-GPOReport -All -ReportType XML",
				"Account Operators":          "Empty Account Operators in modern AD; use delegated OUs with specific permissions instead",
				"Backup Operators":           "Backup Operators on DCs is DA-equivalent; restrict to dedicated T0 backup tier only",
				"Server Operators":           "Empty Server Operators; use JEA (Just Enough Administration) for delegated server management",
				"Print Operators":            "Empty Print Operators; manage printers via dedicated service accounts with minimal rights",
				"DNSAdmins":                  "Restrict DnsAdmins membership; monitor changes to ServerLevelPluginDll registry value on DNS servers",
			}
			if f, ok := fixes[targetGroup]; ok {
				return f
			}
			return "Enforce least-privilege; remove transitive group membership paths; apply AD Tiered Administration model"
		},
	}
}

// ============================================================
// HTML шаблон
// ============================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>adpath — {{.Domain}} — {{.GeneratedAt}}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
/* ── Theme variables ─────────────────────────────────────────── */
html[data-theme="dark"] {
  --bg-page:       #0f1117;
  --bg-card:       #1a1f2e;
  --bg-hover:      #2d3748;
  --bg-code:       #111827;
  --bg-code-inner: #0a0e1a;
  --bg-grouped:    #1a202c;
  --bg-input:      #0f1117;
  --border:        #2d3748;
  --text-main:     #e2e8f0;
  --text-muted:    #718096;
  --text-secondary:#a0aec0;
  --text-subtle:   #4a5568;
  --accent:        #63b3ed;
  --accent-domain: #f6ad55;
  --color-ok:      #68d391;
  --sev-medium:    #faf089;
  --badge-ok-bg:   #1c4532;   --badge-ok-txt:   #68d391;
  --badge-med-bg:  #744210;   --badge-med-txt:  #f6ad55;
  --badge-high-bg: #7b2d12;   --badge-high-txt: #fdba74;
  --badge-crit-bg: #742a2a;   --badge-crit-txt: #e53e3e;
  --text-sev-critical: #fc8181;
  --text-sev-high:     #fbbf24;
  --text-sev-medium:   #fde68a;
  --gs-match-bg:   #1a56db;   --gs-match-txt:   #ffffff;
}
html[data-theme="light"] {
  --bg-page:       #f0f4f8;
  --bg-card:       #ffffff;
  --bg-hover:      #edf2f7;
  --bg-code:       #edf2f7;
  --bg-code-inner: #e2e8f0;
  --bg-grouped:    #f7fafc;
  --bg-input:      #ffffff;
  --border:        #cbd5e0;
  --text-main:     #1a202c;
  --text-muted:    #4a5568;
  --text-secondary:#718096;
  --text-subtle:   #a0aec0;
  --accent:        #2b6cb0;
  --accent-domain: #c05621;
  --color-ok:      #276749;
  --sev-medium:    #b7791f;
  --badge-ok-bg:   #c6f6d5;   --badge-ok-txt:   #276749;
  --badge-med-bg:  #feebc8;   --badge-med-txt:  #744210;
  --badge-high-bg: #fed7ae;   --badge-high-txt: #7b341e;
  --badge-crit-bg: #fed7d7;   --badge-crit-txt: #c53030;
  --text-sev-critical: #c53030;
  --text-sev-high:     #c2410c;
  --text-sev-medium:   #92400e;
  --gs-match-bg:   #1a56db;   --gs-match-txt:   #ffffff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-page); color: var(--text-main); }

/* Header */
.header { background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-page) 100%);
  border-bottom: 1px solid var(--border); padding: 20px 40px; position: relative;
  display: flex; align-items: center; gap: 18px; }
.header-logo { display: flex; align-items: center; gap: 14px; flex-shrink: 0; }
.header-logo-text { display: flex; flex-direction: column; gap: 2px; }
.header-logo-name { font-size: 1.5rem; font-weight: 800; letter-spacing: -0.03em; color: var(--text-main); line-height: 1; }
.header-logo-name em { color: #9b5ffe; font-style: normal; }
.header-logo-tag { font-size: 0.68rem; letter-spacing: 0.14em; color: var(--text-muted); text-transform: uppercase; }
.header .meta { color: var(--text-muted); font-size: 0.82rem; margin-left: 8px; border-left: 1px solid var(--border); padding-left: 18px; }
.header .domain { color: var(--accent-domain); font-weight: 600; }

/* Theme toggle button */
#theme-toggle { position: absolute; right: 40px; top: 50%; transform: translateY(-50%);
  background: var(--bg-hover); border: 1px solid var(--border); color: var(--text-muted);
  border-radius: 6px; padding: 5px 11px; cursor: pointer; font-size: 1rem;
  transition: background 0.2s, border-color 0.2s; }
#theme-toggle:hover { border-color: var(--accent); color: var(--text-main); }

/* Global search */
.global-search-wrap { padding: 10px 40px; background: var(--bg-card); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px; }
.global-search-wrap input { flex: 1; max-width: 420px; padding: 7px 14px;
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-main); font-size: 0.9rem; outline: none; }
.global-search-wrap input:focus { border-color: var(--accent); }
.global-search-wrap input::placeholder { color: var(--text-subtle); }
#gs-results { display:flex; flex-wrap:wrap; gap:4px; align-items:center; min-width:0; }
.gs-tab-btn { background:var(--bg-hover); border:1px solid var(--border); border-radius:5px;
  color:var(--text-main); padding:3px 10px; font-size:0.78rem; cursor:pointer; white-space:nowrap; }
.gs-tab-btn:hover { border-color:var(--accent); background:var(--accent); color:#fff; }
.gs-no-match { font-size:0.82rem; color:var(--text-muted); }
.gs-match { background: var(--gs-match-bg) !important; color: var(--gs-match-txt) !important;
  border-radius: 2px; padding: 0 2px; }

/* Nav tabs */
.nav { display: flex; gap: 0; padding: 0 40px;
  background: var(--bg-card); border-bottom: 1px solid var(--border);
  flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; }
.nav::-webkit-scrollbar { display: none; }
.nav button { padding: 12px 16px; border: none; background: transparent;
  color: var(--text-muted); cursor: pointer; font-size: 0.85rem; border-bottom: 2px solid transparent;
  transition: all 0.2s; white-space: nowrap; flex-shrink: 0; }
.nav button:hover { color: var(--text-main); }
.nav button.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Content */
.content { padding: 32px 40px; max-width: 1400px; }
.tab-pane { display: none; }
.tab-pane.active { display: block; }

/* Summary cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px; margin-bottom: 32px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  padding: 20px; }
.card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
.card .label { font-size: 0.8rem; color: var(--text-muted); margin-top: 4px;
  text-transform: uppercase; letter-spacing: 0.05em; }
.card.critical .value { color: #e53e3e; }
.card.warning .value { color: #f6ad55; }
.card.ok .value { color: var(--color-ok); }
.card[onclick] { cursor: pointer; transition: border-color 0.15s, transform 0.12s; }
.card[onclick]:hover { border-color: var(--accent); transform: translateY(-2px); }

/* Accordion */
.acc-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer;
  margin-top: 10px; padding: 7px 12px; background: var(--bg-hover); border-radius: 6px;
  font-size: 0.78rem; color: var(--text-secondary); user-select: none; border: none; width: 100%;
  text-align: left; }
.acc-toggle:hover { filter: brightness(1.08); color: var(--text-main); }
.acc-body { display: none; padding: 12px 14px; margin-top: 2px;
  background: var(--bg-code); border: 1px solid var(--border); border-radius: 6px;
  font-size: 0.82rem; line-height: 1.6; }
.acc-body.open { display: block; }
.acc-cmd { font-family: monospace; background: var(--bg-code-inner); padding: 4px 8px;
  border-radius: 4px; color: var(--color-ok); font-size: 0.78rem; display: block; margin-top: 4px;
  word-break: break-all; }
.acc-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; margin-top: 8px; }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-txt); }
.badge-medium { background: var(--badge-med-bg); color: var(--badge-med-txt); }
.badge-high { background: var(--badge-high-bg, #7b341e); color: var(--badge-high-txt, #fc8181); }
.badge-critical { background: var(--badge-crit-bg); color: var(--badge-crit-txt); }
.mitre-badge { display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 0.7rem; font-weight: 600; font-family: monospace;
  background: #2d1b69; color: #a78bfa; text-decoration: none;
  border: 1px solid #4c1d95; vertical-align: middle; margin-left: 4px; }
.mitre-badge:hover { background: #4c1d95; color: #c4b5fd; }
[data-theme="light"] .mitre-badge { background: #ede9fe; color: #5b21b6; border-color: #c4b5fd; }
[data-theme="light"] .mitre-badge:hover { background: #ddd6fe; }

/* Severity */
.sev-critical { color: var(--text-sev-critical); font-weight: 700; }
.sev-high     { color: var(--text-sev-high); font-weight: 600; }
.sev-medium   { color: var(--text-sev-medium); }

/* CVSS score pill */
.cvss-score {
  display: inline-block;
  font-size: 11px;
  font-weight: 700;
  font-family: var(--font-mono);
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 4px;
  padding: 1px 6px;
  color: var(--text-secondary);
  letter-spacing: 0.03em;
}
[data-theme="light"] .cvss-score {
  background: rgba(0,0,0,0.05);
  border-color: rgba(0,0,0,0.12);
}

/* Severity row left-border indicators */
tr.row-critical td:first-child { border-left: 3px solid #e53e3e; }
tr.row-high     td:first-child { border-left: 3px solid #dd6b20; }
tr.row-medium   td:first-child { border-left: 3px solid #d69e2e; }
tr.row-low      td:first-child { border-left: 3px solid #68d391; }

/* Tables */
.table-wrap { overflow-x: auto; border-radius: 8px;
  border: 1px solid var(--border); margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: var(--bg-card); color: var(--text-muted); padding: 10px 14px;
  text-align: left; font-weight: 500; text-transform: uppercase;
  font-size: 0.75rem; letter-spacing: 0.05em; }
td { padding: 10px 14px; border-top: 1px solid var(--border); }
tr:hover td { background: var(--bg-hover); }
.mono { font-family: monospace; font-size: 0.8rem; color: var(--text-secondary); }

/* Attack paths */
.path-card { background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.path-header { padding: 12px 16px; display: flex; align-items: center;
  gap: 12px; border-bottom: 1px solid var(--border); }
.path-body { padding: 16px; }
.path-chain { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.path-node { display: flex; align-items: center; gap: 6px;
  background: var(--bg-hover); border-radius: 6px; padding: 6px 12px;
  font-size: 0.85rem; }
.path-node.is-admin { border: 1px solid #fc8181; }
.path-node.is-kerb  { border: 1px solid #f6ad55; }
.path-arrow { color: var(--text-subtle); font-size: 1.2rem; }
.path-edge-label { font-size: 0.7rem; color: var(--text-subtle); }

/* D3 Graph */
#graph-container { background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; height: 500px; position: relative; overflow: hidden; }
#graph-svg { width: 100%; height: 100%; }
.node-label { font-size: 11px; fill: var(--text-main); pointer-events: none; }
.link { stroke: var(--text-subtle); stroke-opacity: 0.6; stroke-width: 1.5px; }
.node circle { stroke-width: 2px; cursor: pointer; }

/* Section title */
.section-title { font-size: 1.1rem; color: var(--text-main); margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid var(--border); display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.section-title span { color: var(--text-muted); font-size: 0.85rem; font-weight: 400; }

/* Help icon tooltip */
.help-icon { display:inline-flex; align-items:center; justify-content:center;
  width:16px; height:16px; border-radius:50%; background:var(--bg-hover); color:var(--text-secondary);
  font-size:10px; font-weight:700; cursor:default; position:relative;
  flex-shrink:0; margin-left:2px; }
.help-icon::after { content: attr(data-tip);
  display:none; position:absolute; left:50%; bottom:calc(100% + 8px);
  transform:translateX(-50%); background:var(--bg-grouped); border:1px solid var(--text-subtle);
  color:var(--text-main); font-size:0.78rem; font-weight:400; line-height:1.5;
  padding:10px 14px; border-radius:6px; white-space:pre-wrap; width:300px;
  z-index:100; pointer-events:none; box-shadow:0 4px 16px rgba(0,0,0,.4); }
.help-icon:hover::after { display:block; }

/* Table filters */
.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; align-items: center; }
.filter-bar input[type=text] {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-main); padding: 6px 10px; font-size: 0.8rem; outline: none;
  min-width: 180px; }
.filter-bar input[type=text]:focus { border-color: var(--accent); }
.filter-bar select {
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-main); padding: 6px 10px; font-size: 0.8rem; outline: none;
  cursor: pointer; }
.filter-bar select:focus { border-color: var(--accent); }
.filter-bar .filter-count { font-size: 0.78rem; color: var(--text-muted); margin-left: auto; }
.filter-bar button {
  background: var(--bg-hover); border: none; border-radius: 6px; color: var(--text-secondary);
  padding: 6px 12px; font-size: 0.78rem; cursor: pointer; }
.filter-bar button:hover { background: var(--border); color: var(--text-main); }

/* Sortable table headers */
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text-main); background: var(--bg-hover); }
th.sort-asc::after  { content: ' ▲'; color: var(--accent); }
th.sort-desc::after { content: ' ▼'; color: var(--accent); }

/* Collapsible exposure sections */
.exp-section { border:1px solid var(--border); border-radius:8px; margin-bottom:10px; }
.exp-header { display:flex; align-items:center; gap:10px; padding:12px 16px;
  background:var(--bg-grouped); cursor:pointer; user-select:none;
  border-radius:8px; }
.exp-section:has(.exp-body:not([style*="none"])) .exp-header { border-radius:8px 8px 0 0; }
.exp-header:hover { filter:brightness(1.06); }
.exp-header .exp-title { font-weight:600; color:var(--text-main); font-size:0.9rem; }
.exp-body { padding:16px; border-top:1px solid var(--border); }

/* Expand/Collapse all buttons */
.xp-btns { display:flex; gap:6px; margin-left:auto; }
.xp-btns button { background:var(--bg-hover); border:1px solid var(--border); border-radius:5px;
  color:var(--text-secondary); padding:4px 11px; font-size:0.76rem; cursor:pointer; white-space:nowrap; }
.xp-btns button:hover { border-color:var(--accent); color:var(--text-main); }

/* Row-limit "Show all" button */
.show-all-btn { display:block; width:100%; margin-top:6px; padding:8px;
  background:var(--bg-hover); border:1px solid var(--border); border-radius:6px;
  color:var(--accent); font-size:0.82rem; cursor:pointer; text-align:center; }
.show-all-btn:hover { border-color:var(--accent); background:var(--bg-card); }

/* Graph truncation warning */
.graph-warn { position:absolute; top:8px; left:50%; transform:translateX(-50%);
  background:var(--bg-grouped); border:1px solid var(--border); border-radius:6px;
  padding:5px 14px; font-size:0.78rem; color:var(--text-muted); white-space:nowrap; pointer-events:none; }
@media print {
  html { background: #fff !important; color: #000 !important; }
  html[data-theme="dark"] {
    --bg-page: #fff; --bg-card: #fff; --bg-hover: #f5f5f5;
    --bg-code: #f5f5f5; --bg-code-inner: #eee; --bg-grouped: #f9f9f9;
    --bg-input: #fff; --border: #ccc;
    --text-main: #000; --text-muted: #555; --text-secondary: #333; --text-subtle: #888;
    --accent: #1a56db; --accent-domain: #c05621; --color-ok: #166534;
  }
  .nav, .global-search-wrap, #theme-toggle, .xp-btns, .filter-bar,
  .show-all-btn, #gs-clear, #graph-tooltip { display: none !important; }
  .tab-pane { display: block !important; page-break-before: always; }
  .tab-pane:first-of-type { page-break-before: auto; }
  .acc-body, .exp-body, .group-body { display: block !important; }
  .path-card, .acl-card, .card, .exp-section { page-break-inside: avoid; }
  * { box-shadow: none !important; transition: none !important; }
  h2.section-title { page-break-after: avoid; }
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.7em; color: #666; }
}
</style>
</head>
<body>

<div class="header">
  <div class="header-logo">
    <svg width="38" height="38" viewBox="0 0 58 58" fill="none">
      <line x1="29" y1="29" x2="29" y2="6"  stroke="#7c3aed" stroke-width="1.5" opacity="0.5"/>
      <line x1="29" y1="29" x2="48" y2="14" stroke="#7c3aed" stroke-width="1.5" opacity="0.5"/>
      <line x1="29" y1="29" x2="52" y2="35" stroke="#7c3aed" stroke-width="1.5" opacity="0.5"/>
      <line x1="29" y1="29" x2="40" y2="52" stroke="#7c3aed" stroke-width="1.5" opacity="0.4"/>
      <line x1="29" y1="29" x2="18" y2="52" stroke="#7c3aed" stroke-width="1.5" opacity="0.4"/>
      <line x1="29" y1="29" x2="6"  y2="35" stroke="#7c3aed" stroke-width="1.5" opacity="0.5"/>
      <line x1="29" y1="29" x2="10" y2="14" stroke="#7c3aed" stroke-width="1.5" opacity="0.5"/>
      <circle cx="29" cy="6"  r="3"   fill="#5b21b6" opacity="0.8"/>
      <circle cx="48" cy="14" r="2.5" fill="#5b21b6" opacity="0.7"/>
      <circle cx="52" cy="35" r="3"   fill="#7c3aed" opacity="0.8"/>
      <circle cx="40" cy="52" r="2.5" fill="#5b21b6" opacity="0.6"/>
      <circle cx="18" cy="52" r="2.5" fill="#5b21b6" opacity="0.6"/>
      <circle cx="6"  cy="35" r="3"   fill="#5b21b6" opacity="0.7"/>
      <circle cx="10" cy="14" r="2.5" fill="#5b21b6" opacity="0.7"/>
      <circle cx="29" cy="29" r="10" fill="#7c3aed" opacity="0.08"/>
      <circle cx="29" cy="29" r="6"  fill="#4c1d95" opacity="0.8"/>
      <circle cx="29" cy="29" r="3.5" fill="#a855f7"/>
    </svg>
    <div class="header-logo-text">
      <div class="header-logo-name"><em>ad</em>path</div>
      <div class="header-logo-tag">v0.9.8 · AD Attack Path Analysis</div>
    </div>
  </div>
  <div class="meta">
    Domain: <span class="domain">{{.Domain}}</span> &nbsp;|&nbsp;
    Auth: <span style="color:var(--color-ok)">{{.AuthMethod}}</span> &nbsp;|&nbsp;
    Generated: {{.GeneratedAt}}
  </div>
  <div style="margin-left:auto;margin-right:60px;display:flex;gap:6px;align-items:center">
    {{if gt .TotalCritical 0}}<span class="badge badge-critical" style="font-size:0.76rem">{{.TotalCritical}} Critical</span>{{end}}
    {{if gt .TotalHigh 0}}<span class="badge badge-high" style="font-size:0.76rem">{{.TotalHigh}} High</span>{{end}}
    {{if gt .TotalMedium 0}}<span class="badge badge-medium" style="font-size:0.76rem">{{.TotalMedium}} Medium</span>{{end}}
    {{if and (eq .TotalCritical 0) (eq .TotalHigh 0) (eq .TotalMedium 0)}}<span class="badge badge-ok" style="font-size:0.76rem">Clean</span>{{end}}
  </div>
  <button id="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark mode">🌙</button>
</div>

<div class="global-search-wrap">
  <input id="gs-input" type="text" placeholder="🔍  Global search across all tabs..."
    oninput="gsHighlight(this.value)" onkeydown="if(event.key==='Enter'){event.preventDefault();gsNavigateFirst();}" autocomplete="off">
  <span id="gs-results"></span>
  <button id="gs-clear" onclick="clearGlobalSearch()" style="background:var(--bg-hover);border:none;color:var(--text-secondary);
    padding:6px 12px;border-radius:6px;cursor:pointer;font-size:0.82rem;display:none">✕ Clear</button>
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
  <button onclick="showTab('shadow')">Shadow Creds {{if gt .Summary.ShadowCredCount 0}}({{.Summary.ShadowCredCount}}){{end}}</button>
  <button onclick="showTab('ldapsec')">LDAP Security {{if .LDAPSecurityResult}}{{if not .LDAPSecurityResult.SigningEnforced}}⚠{{end}}{{end}}</button>
  <button onclick="showTab('audit')">Audit {{if gt .Summary.AuditFindingCount 0}}({{.Summary.AuditFindingCount}}){{end}}</button>
  <button onclick="showTab('users')">Users ({{.Summary.TotalUsers}})</button>
  <button onclick="showTab('groups')">Groups ({{.Summary.TotalGroups}})</button>
  <button onclick="showTab('computers')">Computers ({{.Summary.TotalComputers}})</button>
</div>

<div class="content">

<!-- SUMMARY TAB -->
<div id="tab-summary" class="tab-pane active">

  <!-- Findings Overview -->
  <div style="padding:20px 24px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;margin-bottom:24px">
   <div style="font-size:14px;font-weight:500;color:var(--text-main);margin-bottom:16px">
    Findings Overview — {{.Domain}}
   </div>
   <div id="findings-chart" style="display:flex;flex-direction:column;gap:10px"></div>
  </div>

  <!-- Attack Surface -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Attack Surface</div>
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
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Exposure</div>
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
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Policy & Configuration</div>
  <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;overflow:hidden">
    {{if .GPOResult}}{{if .GPOResult.DefaultPolicy}}
    {{$pp := .GPOResult.DefaultPolicy}}
    {{if not $pp.Complexity}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:var(--text-main)">Password complexity disabled</span>
    </div>
    {{end}}
    {{if lt $pp.MinLength 8}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:var(--text-main)">Minimum password length: {{$pp.MinLength}} chars</span>
    </div>
    {{end}}
    {{if or (eq $pp.MaxAge 0) (gt $pp.MaxAge 3650)}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:var(--text-main)">Passwords never expire</span>
    </div>
    {{end}}
    {{if $pp.ReversibleEncryption}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:var(--text-main)">Reversible encryption enabled</span>
    </div>
    {{end}}
    {{if eq $pp.LockoutThreshold 0}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-critical">Critical</span>
      <span style="font-size:13px;color:var(--text-main)">Account lockout disabled — brute force possible</span>
    </div>
    {{else}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <span class="badge badge-ok">OK</span>
      <span style="font-size:13px;color:var(--text-main)">Account lockout configured (threshold: {{$pp.LockoutThreshold}})</span>
    </div>
    {{end}}
    {{if not $pp.ReversibleEncryption}}
    <div style="display:flex;align-items:center;gap:12px;padding:10px 16px">
      <span class="badge badge-ok">OK</span>
      <span style="font-size:13px;color:var(--text-main)">Reversible encryption disabled</span>
    </div>
    {{end}}
    {{end}}{{else}}
    <div style="padding:16px;color:var(--text-muted);font-size:13px">GPO data not collected — run with --report to include policy analysis</div>
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
    <p style="color:var(--color-ok)">✓ No attack paths to Domain Admins found.</p>
  {{else}}
  {{range $i, $path := .AttackPaths}}
  <div class="path-card">
    <div class="path-header">
      <span class="badge {{pathSeverityClass $path.Depth}}">
        {{pathSeverity $path.Depth}}
      </span>
      {{if $path.TargetGroup}}
      <span class="badge" style="background:var(--bg-hover);color:#fc8181">→ {{$path.TargetGroup}}</span>
      {{end}}
      <span style="color:var(--text-muted); font-size:0.85rem">
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
        <span class="acc-cmd">{{pathExploit $path.Nodes $path.TargetGroup}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">{{pathFix $path.TargetGroup}}</div>
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
    <div style="font-size:0.8rem;color:var(--text-muted)">
      <span style="color:#fc8181">●</span> DA/Admin &nbsp;
      <span style="color:#f6ad55">●</span> Kerberoastable &nbsp;
      <span style="color:#b794f4">●</span> Group &nbsp;
      <span style="color:#90cdf4">●</span> Computer &nbsp;
      <span style="color:#63b3ed">●</span> User
    </div>
    <button onclick="resetZoom()" style="margin-left:auto;padding:4px 12px;background:var(--bg-hover);border:none;color:var(--text-secondary);border-radius:4px;cursor:pointer;font-size:0.8rem">Reset Zoom</button>
  </div>
  <div id="graph-container" style="position:relative">
    <svg id="graph-svg"></svg>
    <div id="graph-tooltip" style="display:none;position:absolute;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:0.8rem;pointer-events:none;max-width:280px;z-index:10"></div>
  </div>
  <div style="margin-top:8px;font-size:0.75rem;color:var(--text-subtle)">
    Drag to pan · Scroll to zoom · Hover node for details · Node size = number of paths through it
  </div>
</div>

<!-- TRUSTS TAB -->
<div id="tab-trusts" class="tab-pane">
  <h2 class="section-title">Domain &amp; Forest Trusts {{mitreBadges "trust_abuse"}}
    <span class="help-icon" data-tip="Domain trusts define authentication paths between domains. SID filtering disabled on a trust allows SID history abuse — an attacker in a trusted domain can forge SIDs to escalate privileges in this domain. Bidirectional forest trusts create lateral movement paths between forests. Foreign Security Principals (FSPs) are accounts from trusted domains added to local groups.">?</span>
  </h2>

  {{if .TrustResult}}

  {{if not .TrustResult.Trusts}}
  <p style="color:var(--text-muted);margin-bottom:20px">No trusts found — this may be a standalone domain.</p>
  {{else}}

  <!-- Trust table -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Configured Trusts</div>
  <div class="table-wrap" style="margin-bottom:24px">
  <table>
    <thead>
      <tr><th>Trusted Domain</th><th>NetBIOS</th><th>Direction</th><th>Type</th><th>SID Filtering</th><th>Severity</th><th>CVSS</th><th>Risks</th></tr>
    </thead>
    <tbody>
    {{range .TrustResult.Trusts}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td class="mono" style="color:var(--text-muted)">{{.FlatName}}</td>
      <td>{{.Direction}}</td>
      <td style="color:var(--text-secondary);font-size:0.82rem">{{.TrustType}}</td>
      <td>
        {{if .SIDFilteringOn}}
          <span class="badge badge-ok">ON ✓</span>
        {{else if .IsWithinForest}}
          <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Internal</span>
        {{else}}
          <span class="badge badge-critical">OFF ⚠</span>
        {{end}}
      </td>
      <td>
        {{if eq .Severity "Critical"}}<span class="badge badge-critical">Critical</span>
        {{else if eq .Severity "High"}}<span class="badge badge-high">High</span>
        {{else if eq .Severity "Medium"}}<span class="badge" style="background:#744210;color:#fef3c7">Medium</span>
        {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Info</span>{{end}}
      </td>
      <td>{{if gt .CVSS 0.0}}<span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>{{else}}—{{end}}</td>
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
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;display:flex;align-items:center;gap:6px">
    Foreign Security Principals in Privileged Groups
    <span class="help-icon" data-tip="Foreign Security Principals (FSPs) are objects representing users or groups from trusted external domains. If an FSP is a member of a privileged local group (Domain Admins, Administrators), an attacker who compromises the external domain gains privilege in this domain too.">?</span>
  </div>
  {{if .TrustResult.FSPs}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px;border-color:#e53e3e">
    <span class="badge badge-critical" style="margin-bottom:8px;display:inline-block">⚠ {{len .TrustResult.FSPs}} external principal(s) in privileged groups</span>
  </div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>External SID</th><th>Severity</th><th>CVSS</th><th>Member of</th></tr></thead>
    <tbody>
    {{range .TrustResult.FSPs}}
    <tr>
      <td class="mono" style="font-size:0.8rem">{{.ExternalSID}}</td>
      <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      <td style="font-size:0.82rem;color:var(--text-secondary)">{{joinSPNs .MemberOfGroups}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <p style="color:var(--color-ok)">✓ No foreign security principals found in privileged groups.</p>
  {{end}}

  {{else}}
  <p style="color:var(--text-muted)">Trust data not available.</p>
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
      <td style="font-size:0.78rem;color:var(--text-secondary)">{{.Mail}}</td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">No</span>{{end}}</td>
      <td>{{with index $.UserPrivGroups .DN}}<span class="badge" style="background:var(--badge-crit-bg);color:var(--badge-crit-txt);font-size:0.72rem">{{.}}</span>{{else}}—{{end}}</td>
      <td>{{if .SPNs}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Yes</span>{{else}}—{{end}}</td>
      <td>{{if .DontReqPreauth}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Yes</span>{{else}}—{{end}}</td>
      <td>{{if .PasswordNeverExpires}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Yes</span>{{else}}—{{end}}</td>
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
      <td>{{if .AdminCount}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Yes</span>{{else}}—{{end}}</td>
      <td style="color:var(--text-muted)">{{.Description}}</td>
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
        {{if .IsGC}}<span style="color:var(--text-subtle);font-size:0.7rem" title="Partial data from Global Catalog">&nbsp;(GC)</span>{{end}}
        {{if .DNSHostName}}<div style="color:var(--text-muted);font-size:0.75rem">{{.DNSHostName}}</div>{{end}}
      </td>
      <td style="font-size:0.78rem;color:var(--text-secondary)">{{.Domain}}</td>
      <td style="white-space:nowrap">
        {{if .OperatingSystem}}{{.OperatingSystem}}
        {{else}}<span style="color:var(--text-subtle)">—</span>{{end}}
      </td>
      <td class="mono" style="font-size:0.78rem;white-space:nowrap">
        {{if .OperatingSystemVersion}}{{.OperatingSystemVersion}}
        {{if .OperatingSystemSP}}&nbsp;{{.OperatingSystemSP}}{{end}}
        {{else}}—{{end}}
      </td>
      <td>{{if .Enabled}}<span class="badge badge-ok">Yes</span>
          {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">No</span>{{end}}</td>
      <td>{{if .LAPSEnabled}}<span class="badge badge-ok">✓</span>
          {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">No</span>{{end}}</td>
      <td>{{if .UnconstrainedDelegation}}<span class="badge badge-critical">Yes</span>
          {{else}}—{{end}}</td>
      <td class="mono" style="font-size:0.78rem">{{.LastLogon}}</td>
      <td class="mono" style="font-size:0.78rem">{{.WhenCreated}}</td>
      <td style="font-size:0.78rem;color:var(--text-muted)">{{.Description}}</td>
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
    {{mitreBadges "kerberoasting"}}
    <span class="help-icon" data-tip="Accounts with a Service Principal Name (SPN) set. Any authenticated user can request a Kerberos ticket (TGS) for them and crack the hash offline. Severity rises sharply if the account has AdminCount=1 or is in a privileged group.">?</span>
  </h3>
  {{if .KerberosResult.KerberoastableAccounts}}
  <div style="margin-bottom:8px">
    <button class="acc-toggle" onclick="toggleAcc(this)" style="background:#1a2a1a;color:var(--color-ok);margin-bottom:4px">
      ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix — Kerberoasting
    </button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">GetUserSPNs.py domain/user:pass -dc-ip &lt;DC&gt; -request-user &lt;account&gt; -outputfile kerberoast.txt</span>
      <span class="acc-cmd" style="margin-top:4px">hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:var(--text-secondary)">Use managed service accounts (gMSA) — auto-rotating 120-char passwords, not crackable. Remove SPNs from regular user accounts. Enable AES-only Kerberos encryption (no RC4).</div>
    </div>
  </div>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>SPNs</th>
        <th>Admin</th>
        <th>CVSS</th>
        <th>Last Logon</th>
        <th>Password Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .KerberosResult.KerberoastableAccounts}}
    <tr class="{{if .AdminCount}}row-critical{{else}}row-high{{end}}">
      <td class="mono">{{.SAMAccountName}}</td>
      <td class="mono" style="font-size:0.75rem">{{joinSPNs .SPNs}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:var(--color-ok)">✓ No Kerberoastable accounts found.</p>{{end}}

  <h3 class="section-title" style="font-size:0.95rem; margin-top:24px">
    AS-REP Roastable Accounts
    <span>{{len .KerberosResult.ASREPAccounts}}</span>
    {{mitreBadges "asrep"}}
    <span class="help-icon" data-tip="Accounts with 'Do not require Kerberos preauthentication' enabled. An attacker can request an AS-REP blob for these accounts without any credentials and crack the hash offline. No authentication required — works from outside the domain.">?</span>
  </h3>
  {{if .KerberosResult.ASREPAccounts}}
  <div style="margin-bottom:8px">
    <button class="acc-toggle" onclick="toggleAcc(this)" style="background:#1a2a1a;color:var(--color-ok);margin-bottom:4px">
      ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix — AS-REP Roasting
    </button>
    <div class="acc-body">
      <div class="acc-label">Exploit</div>
      <span class="acc-cmd">GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip &lt;DC&gt;</span>
      <span class="acc-cmd" style="margin-top:4px">hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt</span>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:var(--text-secondary)">Enable "Do not require Kerberos preauthentication" only if absolutely needed. Enforce strong passwords (&gt;25 chars) on affected accounts. Add to Protected Users security group (prevents AS-REP roasting).</div>
    </div>
  </div>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>Admin</th>
        <th>CVSS</th>
        <th>Last Logon</th>
        <th>Password Last Set</th>
      </tr>
    </thead>
    <tbody>
    {{range .KerberosResult.ASREPAccounts}}
    <tr class="{{if .AdminCount}}row-critical{{else}}row-high{{end}}">
      <td class="mono">{{.SAMAccountName}}</td>
      <td>{{if .AdminCount}}<span class="badge badge-critical">Yes</span>{{else}}—{{end}}</td>
      <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:var(--color-ok)">✓ No AS-REP Roastable accounts found.</p>{{end}}

  {{else}}<p style="color:var(--text-muted)">Kerberos data not available.</p>{{end}}
</div>

<!-- ACL TAB -->
<div id="tab-acl" class="tab-pane">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">
      Dangerous ACL Permissions
      <span>{{.Summary.DangerousACLCount}} finding(s)</span>
      {{mitreBadges "acl_abuse"}}
      <span class="help-icon" data-tip="Access Control Lists define who can do what to each AD object. Misconfigurations like GenericAll, WriteDACL or ForceChangePassword allow an attacker to take over accounts or escalate to Domain Admin without exploiting any software vulnerability — just abusing legitimate AD permissions.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-acl')">Expand all</button>
      <button onclick="collapseAllIn('#tab-acl')">Collapse all</button>
    </div>
  </div>

  {{if .ACLResult}}{{if .ACLResult.DCSyncFindings}}
  <div style="background:#2d1515;border:1px solid #e53e3e;border-radius:8px;padding:16px;margin-bottom:20px">
    <div style="font-size:0.9rem;font-weight:600;color:#fc8181;margin-bottom:10px">
      ☠ DCSync Rights Detected — {{len .ACLResult.DCSyncFindings}} principal(s) can dump all domain password hashes {{mitreBadges "dcsync"}}
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
      <div style="color:var(--text-secondary)">Remove DS-Replication-Get-Changes-All from non-DC accounts. Run: <span class="acc-cmd">Get-ObjectAcl -DistinguishedName "DC=domain,DC=local" | ? {$_.ActiveDirectoryRights -match "Replication"}</span> to audit. Only Domain Controllers and Administrators should have DCSync rights.</div>
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
  </div>
  <div id="acl-grouped"></div>
  <div id="acl-findings" style="display:none">
  {{range $i, $f := .ACLResult.Findings}}
  <div class="path-card acl-card" style="margin-bottom:10px" data-severity="{{$f.Severity}}" data-right="{{$f.Right}}" data-text="{{$f.PrincipalName}} {{$f.TargetName}}">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq $f.Severity "Critical"}}badge-critical{{else if eq $f.Severity "High"}}badge-medium{{else}}badge-ok{{end}}">{{$f.Severity}}</span>
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" $f.CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{$f.PrincipalName}}</span>
      <span style="color:var(--text-subtle)">─▶</span>
      <span class="mono" style="color:#f6ad55">{{$f.TargetName}}</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{$f.PrincipalType}} → {{$f.TargetType}}</span>
    </div>
    <div style="padding:0 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{$f.Right}})</div>
        <span class="acc-cmd">{{aclExploit (print $f.Right) $f.PrincipalName $f.TargetName $.ACLResult.Domain}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">{{aclFix (print $f.Right)}}</div>
      </div>
    </div>
  </div>
  {{end}}
  </div>{{/* end acl-findings */}}
  {{else}}<p style="color:var(--color-ok)">✓ No dangerous ACL findings.</p>{{end}}
  {{else}}<p style="color:var(--text-muted)">ACL data not available.</p>{{end}}
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
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{.SAMAccountName}}</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">{{.ObjectType}}</span>
      {{mitreForDeleg (print .DelegationType)}}
      {{if .AllowedServices}}<span style="color:var(--text-muted);font-size:0.78rem">→ {{joinSPNs .AllowedServices}}</span>{{end}}
    </div>
    <div style="padding:4px 16px 0">
      <div style="color:#fc8181;font-size:0.8rem;padding-bottom:4px">⚠ {{.RiskReason}}</div>
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{.DelegationType}})</div>
        <span class="acc-cmd">{{delegExploit (print .DelegationType)}}</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">{{delegFix (print .DelegationType)}}</div>
      </div>
    </div>
  </div>
  {{end}}
  {{else}}<p style="color:var(--color-ok)">✓ No dangerous delegation configurations.</p>{{end}}
  {{else}}<p style="color:var(--text-muted)">Delegation data not available.</p>{{end}}
</div>

<!-- EXPOSURE TAB -->
<div id="tab-exposure" class="tab-pane">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">Exposure &amp; Attack Surface
      <span class="help-icon" data-tip="Attack surface metrics: stale accounts are unused entry points, LAPS absence means shared local admin passwords enabling lateral movement, old krbtgt password enables persistent Golden Ticket attacks, descriptions often leak credentials or internal IP ranges.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-exposure')">Expand all</button>
      <button onclick="collapseAllIn('#tab-exposure')">Collapse all</button>
    </div>
  </div>

  <!-- krbtgt -->
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">krbtgt Password Age</span>
      {{if .HygieneResult}}{{if .HygieneResult.KrbtgtAtRisk}}
      <span class="badge badge-critical">&#9888; Golden Ticket Risk</span>
      <span class="badge badge-critical" style="margin-left:auto">Critical</span>
      {{else if gt .HygieneResult.KrbtgtPwdAgeDays 0}}
      <span class="badge badge-ok">&#10003; OK — {{.HygieneResult.KrbtgtPwdAgeDays}} days</span>
      {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">No data</span>
      {{end}}{{end}}
      <span class="help-icon" data-tip="The krbtgt account password hash signs all Kerberos tickets. If stolen (DCSync), attackers forge Golden Tickets valid for any user. Rotate every 180 days — must rotate TWICE to fully invalidate old tickets.">?</span>
    </div>
    <div class="exp-body">
    {{if .HygieneResult}}
    {{if .HygieneResult.KrbtgtAtRisk}}
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <span class="badge badge-critical">&#9888; Golden Ticket Risk</span>
      <span style="color:#fc8181;font-size:0.9rem">krbtgt password last changed <strong>{{.HygieneResult.KrbtgtPwdAgeDays}} days ago</strong> ({{.HygieneResult.KrbtgtLastSet}})</span>
      <div style="width:100%;font-size:0.8rem;color:var(--text-muted);margin-top:4px">Recommendation: reset krbtgt password twice (interval &gt;10h) to invalidate all existing Kerberos tickets</div>
    </div>
    {{else if gt .HygieneResult.KrbtgtPwdAgeDays 0}}
    <div style="display:flex;align-items:center;gap:12px">
      <span class="badge badge-ok">&#10003; OK</span>
      <span style="color:var(--color-ok);font-size:0.9rem">krbtgt password age: <strong>{{.HygieneResult.KrbtgtPwdAgeDays}} days</strong> ({{.HygieneResult.KrbtgtLastSet}})</span>
    </div>
    {{else}}
    <span style="color:var(--text-muted);font-size:0.85rem">krbtgt data not available</span>
    {{end}}
    {{end}}
    </div>
  </div>

  <!-- Descriptions -->
  {{if .HygieneResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Description Notes</span>
      {{if .HygieneResult.PasswordInDesc}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .HygieneResult.PasswordInDesc}} objects</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; Clean</span>{{end}}
    </div>
    <div class="exp-body">
    <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:10px">All AD objects with a non-empty description. Admins often leave credentials, IP addresses, or other sensitive data here.</p>
    {{if .HygieneResult.PasswordInDesc}}
    <div class="filter-bar" style="margin-bottom:8px">
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
        <td><span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">{{.ObjectType}}</span></td>
        <td style="font-family:monospace;font-size:0.8rem;color:var(--text-main)">{{.Description}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">&#10003; No description attributes found.</p>{{end}}
    </div>
  </div>
  {{end}}

  <!-- Stale Users -->
  {{if .HygieneResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Stale User Accounts <span style="font-size:0.78rem;color:var(--text-muted);font-weight:400">(90+ days no logon)</span></span>
      {{if .HygieneResult.StaleUsers}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .HygieneResult.StaleUsers}} accounts</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; None</span>{{end}}
    </div>
    <div class="exp-body">
    {{if .HygieneResult.StaleUsers}}
    <div class="table-wrap">
    <table id="tbl-stale-users">
      <thead><tr><th>Account</th><th>Display Name</th><th>Last Logon</th><th>Pwd Last Set</th><th>AdminCount</th></tr></thead>
      <tbody>
      {{range .HygieneResult.StaleUsers}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td>{{.DisplayName}}</td>
        <td class="mono" style="color:#f6ad55">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
        <td class="mono">{{.PasswordLastSet}}</td>
        <td>{{if .AdminCount}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Yes</span>{{else}}&#8212;{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">&#10003; No stale user accounts found.</p>{{end}}
    </div>
  </div>
  {{end}}

  <!-- Stale Computers -->
  {{if .HygieneResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Stale Computers <span style="font-size:0.78rem;color:var(--text-muted);font-weight:400">(45+ days no logon)</span></span>
      {{if .HygieneResult.StaleComputers}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .HygieneResult.StaleComputers}} hosts</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; None</span>{{end}}
    </div>
    <div class="exp-body">
    {{if .HygieneResult.StaleComputers}}
    <div class="table-wrap">
    <table id="tbl-stale-comp">
      <thead><tr><th>Computer</th><th>OS</th><th>Last Logon</th><th>Domain</th></tr></thead>
      <tbody>
      {{range .HygieneResult.StaleComputers}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td>{{.OperatingSystem}}</td>
        <td class="mono" style="color:#f6ad55">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
        <td style="font-size:0.78rem;color:var(--text-muted)">{{.Domain}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">&#10003; No stale computers found.</p>{{end}}
    </div>
  </div>
  {{end}}

  <!-- No LAPS -->
  {{if .HygieneResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Computers Without LAPS</span>
      {{if gt .Summary.NoLAPSCount 0}}
      <span class="badge badge-medium" style="margin-left:auto">{{.Summary.NoLAPSCount}} / {{.Summary.TotalComputers}} hosts</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; All managed</span>{{end}}
    </div>
    <div class="exp-body">
    {{if gt .Summary.NoLAPSCount 0}}
    <div style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">Local Administrator Password Solution not deployed — local admin passwords may be identical across machines, enabling lateral movement.</div>
    <div class="table-wrap">
    <table id="tbl-nolaps">
      <thead><tr><th>Computer</th><th>OS</th><th>Domain</th><th>Last Logon</th></tr></thead>
      <tbody>
      {{range .HygieneResult.NoLAPSComputers}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td>{{.OperatingSystem}}</td>
        <td style="font-size:0.78rem;color:var(--text-muted)">{{.Domain}}</td>
        <td class="mono" style="color:var(--text-secondary)">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">&#10003; All enabled computers have LAPS deployed.</p>{{end}}
    </div>
  </div>
  {{end}}

  <!-- PSO -->
  {{if .PSOResult}}{{if .PSOResult.PSOs}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Fine-Grained Password Policy (PSO)</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{len .PSOResult.PSOs}} PSO(s)</span>
    </div>
    <div class="exp-body">
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
        <td>{{if eq .LockoutThreshold 0}}<span class="badge badge-critical">&#8734;</span>{{else}}{{.LockoutThreshold}}{{end}}</td>
        <td>{{if eq .MaxAgeDays 0}}<span class="badge badge-critical">Never</span>{{else}}{{.MaxAgeDays}}d{{end}}</td>
        <td style="font-size:0.78rem;color:var(--text-secondary)">{{joinSPNs .AppliesTo}}</td>
        <td>{{if .IsWeak}}<span class="badge badge-critical">Weak</span>{{else}}<span class="badge badge-ok">OK</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  <!-- Protected Users -->
  {{if .ProtectedUsersResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">Protected Users Group</span>
      {{if not .ProtectedUsersResult.ProtectedUsersExists}}
      <span class="badge badge-medium" style="margin-left:auto">Group not found</span>
      {{else if .ProtectedUsersResult.PrivilegedNotProtected}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .ProtectedUsersResult.PrivilegedNotProtected}} privileged not protected</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; All protected</span>{{end}}
      <span class="help-icon" data-tip="Members of Protected Users cannot authenticate with NTLM, use RC4 encryption, or be subject to unconstrained delegation. DA/EA accounts outside this group are higher-risk credentials.">?</span>
    </div>
    <div class="exp-body">
    {{if not .ProtectedUsersResult.ProtectedUsersExists}}
    <p style="color:#fc8181;font-size:0.85rem">&#9888; Protected Users group not found — may not exist in this domain.</p>
    {{else if .ProtectedUsersResult.PrivilegedNotProtected}}
    <div style="color:var(--text-secondary);font-size:0.8rem;margin-bottom:10px">NTLM auth, RC4 encryption, and unconstrained delegation are not blocked for these accounts.</div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Account</th><th>Severity</th><th>Privileged Groups</th></tr></thead>
      <tbody>
      {{range .ProtectedUsersResult.PrivilegedNotProtected}}
      <tr class="{{if eq .Severity "Critical"}}row-critical{{else}}row-high{{end}}">
        <td class="mono">{{.SAMAccountName}}</td>
        <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
        <td style="font-size:0.82rem;color:var(--text-secondary)">{{joinSPNs .Groups}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}
    <p style="color:var(--color-ok)">&#10003; All privileged accounts are in Protected Users ({{len .ProtectedUsersResult.Members}} members).</p>
    {{end}}
    </div>
  </div>
  {{end}}

  <!-- AdminSDHolder -->
  {{if .AdminSDHolderResult}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>
      <span class="exp-title">AdminSDHolder</span>
      {{if .AdminSDHolderResult.CustomACEs}}
      <span class="badge badge-critical" style="margin-left:auto">{{len .AdminSDHolderResult.CustomACEs}} backdoor ACE(s)</span>
      {{else if .AdminSDHolderResult.OrphanedAdminCount}}
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{len .AdminSDHolderResult.OrphanedAdminCount}} orphaned adminCount</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; Clean</span>{{end}}
      <span class="help-icon" data-tip="AdminSDHolder ACL is copied to all protected objects every 60 minutes. A custom ACE here is a persistence backdoor. Orphaned adminCount=1 means the object is no longer monitored but still has hardened ACLs.">?</span>
    </div>
    <div class="exp-body">
    {{if .AdminSDHolderResult.CustomACEs}}
    <div style="color:#fc8181;font-size:0.8rem;margin-bottom:10px">&#9888; These ACEs are replicated to ALL protected objects every 60 min. Remove immediately.</div>
    <div class="table-wrap" style="margin-bottom:12px">
    <table>
      <thead><tr><th>Principal</th><th>SID</th><th>Rights</th><th>CVSS</th></tr></thead>
      <tbody>
      {{range .AdminSDHolderResult.CustomACEs}}
      <tr class="row-critical">
        <td class="mono" style="color:#fc8181">{{.PrincipalName}}</td>
        <td class="mono" style="font-size:0.75rem;color:var(--text-muted)">{{.PrincipalSID}}</td>
        <td style="color:#f6ad55;font-size:0.82rem">{{joinSPNs .Rights}}</td>
        <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{end}}
    {{if .AdminSDHolderResult.OrphanedAdminCount}}
    <div style="color:var(--text-secondary);font-size:0.8rem;margin-bottom:8px">adminCount=1 but not in any privileged group — SDProp no longer manages these objects.</div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Account</th><th>Status</th></tr></thead>
      <tbody>
      {{range .AdminSDHolderResult.OrphanedAdminCount}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td>{{if .Enabled}}<span class="badge badge-medium">enabled</span>{{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">disabled</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{end}}
    {{if and (not .AdminSDHolderResult.CustomACEs) (not .AdminSDHolderResult.OrphanedAdminCount)}}
    <p style="color:var(--color-ok)">&#10003; No AdminSDHolder issues found.</p>
    {{end}}
    </div>
  </div>
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
    {{mitreBadges "gpo_abuse"}}
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
    <thead><tr><th>GPO</th><th>Severity</th><th>CVSS</th><th>Principal</th><th>Rights</th><th>Linked To</th></tr></thead>
    <tbody>
    {{range .GPOResult.GPOACLFindings}}
    <tr>
      <td class="mono">{{.GPOName}}</td>
      <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      <td class="mono">{{.PrincipalName}}</td>
      <td style="color:#f6ad55;font-size:0.82rem">{{joinSPNs .Rights}}</td>
      <td style="font-size:0.78rem;color:var(--text-secondary)">{{joinSPNs .GPOLinkedTo}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}{{end}}

  {{else}}<p style="color:var(--text-muted)">GPO data not available.</p>{{end}}
</div>

<!-- ADCS TAB -->
<div id="tab-adcs" class="tab-pane">
  <h2 class="section-title">
    Active Directory Certificate Services
    <span class="help-icon" data-tip="ADCS misconfigurations allow attackers to forge certificates and authenticate as any domain user including Domain Admins. ESC1: attacker controls Subject Alternative Name → impersonate DA. ESC6: CA-level flag allows SAN injection for all templates. ESC8: NTLM relay to HTTP enrollment endpoint.">?</span>
  </h2>

  {{if .ADCSResult}}

  <!-- CAs -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Certificate Authorities</div>
  {{if .ADCSResult.CAs}}
  <div class="table-wrap" style="margin-bottom:20px">
  <table>
    <thead><tr><th>CA Name</th><th>Server</th><th>ESC6</th><th>ESC8 (check)</th></tr></thead>
    <tbody>
    {{range .ADCSResult.CAs}}
    <tr>
      <td class="mono">{{.Name}}</td>
      <td class="mono" style="color:var(--text-secondary)">{{.Server}}</td>
      <td>{{if gt .EditFlags 262143}}<span class="badge badge-critical">YES</span>{{else}}—{{end}}</td>
      <td style="font-size:0.78rem;color:var(--text-muted)">http://{{.Server}}/certsrv/</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{else}}<p style="color:var(--text-muted)">No CAs found.</p>{{end}}

  <!-- CA Findings (ESC6) -->
  {{range .ADCSResult.CAFindings}}
  {{if eq (index .VulnTypes 0) "ESC6"}}
  <div class="path-card" style="margin-bottom:10px;border-color:#e53e3e">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge badge-critical">Critical</span>
      <span class="badge badge-critical" style="font-family:monospace">ESC6</span>
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{.CAName}}</span>
    </div>
    <div style="padding:8px 16px">
      <div style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px">{{.Details}}</div>
      <button class="acc-toggle" onclick="toggleAcc(this)">▶ &nbsp;Exploit &nbsp;/&nbsp; Fix</button>
      <div class="acc-body">
        <div class="acc-label">Exploit</div>
        <span class="acc-cmd">certipy req -u user@{{$.ADCSResult.Domain}} -p pass -ca {{.CAName}} -template User -upn admin@{{$.ADCSResult.Domain}}</span>
        <span class="acc-cmd" style="margin-top:4px">certipy auth -pfx admin.pfx -domain {{$.ADCSResult.Domain}} -dc-ip &lt;DC&gt;</span>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">Run: <code>certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2</code> on CA, then restart CertSvc.</div>
      </div>
    </div>
  </div>
  {{end}}
  {{end}}

  <!-- Template Findings -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;margin-top:8px">Vulnerable Templates ({{.Summary.ADCSTemplateCount}}) {{mitreBadges "adcs"}}</div>
  {{if .ADCSResult.TemplateFindings}}
  {{range .ADCSResult.TemplateFindings}}
  {{$tmplSev := .Severity}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span>
      {{range .VulnTypes}}<span class="badge {{if eq $tmplSev "Critical"}}badge-critical{{else}}badge-medium{{end}}" style="font-family:monospace">{{.}}</span>{{end}}
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{.TemplateName}}</span>
      {{if .EnrollableBy}}<span class="badge" style="background:var(--bg-hover);color:var(--color-warn);margin-left:4px">enrollable by: {{range $i,$e := .EnrollableBy}}{{if $i}}, {{end}}{{$e}}{{end}}</span>{{end}}
      {{if .EKUs}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{range $i,$e := .EKUs}}{{if $i}}, {{end}}{{$e}}{{end}}</span>{{end}}
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
        <div style="color:var(--text-secondary)">Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from template, restrict enrollment to specific groups, require CA manager approval, or disable the template if unused.</div>
      </div>
    </div>
  </div>
  {{end}}
  {{else}}<p style="color:var(--color-ok)">✓ No vulnerable certificate templates found.</p>{{end}}

  {{else}}<p style="color:var(--text-muted)">ADCS data not available — run with full enum or use adpath adcs command.</p>{{end}}
</div>

<!-- SHADOW CREDENTIALS TAB -->
<div id="tab-shadow" class="tab-pane">
  <h2 class="section-title">
    Shadow Credentials {{mitreBadges "shadow_credentials"}}
    <span class="help-icon" data-tip="Shadow Credentials: writing msDS-KeyCredentialLink on a privileged object allows obtaining a TGT without knowing or changing the password. Exploitable via pywhisker or certipy shadow.">?</span>
  </h2>
  {{if .ShadowCredentialsResult}}
    {{if .ShadowCredentialsResult.Findings}}
    <div style="margin-bottom:16px">
      <span class="badge badge-critical">{{len .ShadowCredentialsResult.Findings}} dangerous write ACEs found</span>
    </div>
    <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Principal</th>
        <th>Type</th>
        <th>Target</th>
        <th>Target Type</th>
        <th>Right</th>
        <th>Severity</th>
        <th>CVSS</th>
      </tr></thead>
      <tbody>
      {{range .ShadowCredentialsResult.Findings}}
      <tr class="{{if eq .Severity "Critical"}}row-critical{{else}}row-high{{end}}">
        <td class="mono">{{.PrincipalName}}</td>
        <td>{{.PrincipalType}}</td>
        <td class="mono">{{.TargetName}}</td>
        <td>{{.TargetType}}</td>
        <td><span class="badge badge-medium" style="font-family:monospace;font-size:0.75rem">{{.Right}}</span></td>
        <td><span class="badge badge-critical">{{.Severity}}</span></td>
        <td><span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    <div class="path-card" style="margin-top:16px">
      <div class="path-header">Next Steps — exploit with pywhisker / certipy</div>
      <div style="padding:12px 16px">
        <span class="acc-cmd">pywhisker -d {{.ShadowCredentialsResult.Domain}} -u '&lt;principal&gt;' -p '&lt;pass&gt;' --target '&lt;target&gt;' --action add</span>
        <span class="acc-cmd" style="margin-top:4px">certipy shadow auto -u '&lt;principal&gt;@{{.ShadowCredentialsResult.Domain}}' -p '&lt;pass&gt;' -account '&lt;target&gt;'</span>
      </div>
    </div>
    {{else}}
    <p style="color:var(--color-ok)">✓ No dangerous write ACEs on msDS-KeyCredentialLink found.</p>
    {{end}}
  {{else}}
  <p style="color:var(--text-muted)">Shadow Credentials data not available.</p>
  {{end}}
</div>

<!-- LDAP SECURITY TAB -->
<div id="tab-ldapsec" class="tab-pane">
  <h2 class="section-title">
    LDAP Security {{mitreBadges "ldap_relay"}}
    <span class="help-icon" data-tip="LDAP signing prevents man-in-the-middle attacks on LDAP traffic. If signing is not enforced, an attacker between the client and DC can read or modify LDAP requests. NTLM relay to LDAP (via PetitPotam/Coercer) is possible when signing and channel binding are not enforced.">?</span>
  </h2>
  {{if .LDAPSecurityResult}}
  <div class="table-wrap" style="margin-bottom:20px"><table>
    <thead><tr><th>Setting</th><th>Status</th></tr></thead>
    <tbody>
      <tr>
        <td>Transport</td>
        <td>{{if .LDAPSecurityResult.PlainLDAP}}<span class="badge badge-medium">plain LDAP port 389</span>{{else}}<span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">LDAPS port 636</span>{{end}}</td>
      </tr>
      <tr>
        <td>LDAP signing</td>
        <td>{{if .LDAPSecurityResult.SigningEnforced}}<span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">✓ enforced</span>{{else}}<span class="badge badge-medium">⚠ NOT enforced</span>{{end}}</td>
      </tr>
      <tr>
        <td>SASL mechanisms</td>
        <td class="mono" style="font-size:0.82rem">{{range $i,$m := .LDAPSecurityResult.SASLMechanisms}}{{if $i}}, {{end}}{{$m}}{{end}}</td>
      </tr>
      <tr>
        <td>Capabilities (OIDs)</td>
        <td class="mono" style="font-size:0.75rem">{{range $i,$c := .LDAPSecurityResult.Capabilities}}{{if $i}}<br>{{end}}{{$c}}{{end}}</td>
      </tr>
    </tbody>
  </table></div>
  {{if .LDAPSecurityResult.Findings}}
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Findings</div>
  {{range .LDAPSecurityResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq .Severity "Medium"}}badge-medium{{else}}badge-critical{{end}}">{{.Severity}}</span>
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>
      <span style="margin-left:4px">{{.Title}}</span>
    </div>
    <div style="padding:8px 16px;color:var(--text-secondary);font-size:0.85rem">{{.Detail}}</div>
  </div>
  {{end}}
  {{else}}
  <p style="color:var(--color-ok)">✓ No LDAP security issues found.</p>
  {{end}}
  {{else}}
  <p style="color:var(--text-muted)">LDAP security data not available.</p>
  {{end}}

  {{if .SMBSigningResult}}
  <h3 class="section-title" style="font-size:0.95rem;margin-top:24px">SMB Signing (port 445)</h3>
  {{if .SMBSigningResult.Reachable}}
  <div class="table-wrap" style="margin-bottom:16px"><table>
    <thead><tr><th>Property</th><th>Value</th></tr></thead>
    <tbody>
      <tr>
        <td>Host</td>
        <td class="mono">{{.SMBSigningResult.Host}}</td>
      </tr>
      <tr>
        <td>Dialect</td>
        <td>{{dialectName .SMBSigningResult.Dialect}}</td>
      </tr>
      <tr>
        <td>Signing</td>
        <td>
          {{if .SMBSigningResult.SigningRequired}}<span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">✓ required</span>
          {{else if .SMBSigningResult.SigningEnabled}}<span class="badge badge-medium">enabled (not required)</span>
          {{else}}<span class="badge badge-high">not enabled</span>{{end}}
        </td>
      </tr>
    </tbody>
  </table></div>
  {{if .SMBSigningResult.Findings}}
  {{range .SMBSigningResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq .Severity "High"}}badge-high{{else if eq .Severity "Medium"}}badge-medium{{else}}badge-critical{{end}}">{{.Severity}}</span>
      <span class="cvss-score" title="CVSS 3.1 Base Score">{{printf "%.1f" .CVSS}}</span>
      <span style="margin-left:4px">{{.Title}}</span>
    </div>
    <div style="padding:8px 16px;color:var(--text-secondary);font-size:0.85rem">{{.Detail}}</div>
  </div>
  {{end}}
  {{else}}
  <p style="color:var(--color-ok)">✓ SMB signing is required.</p>
  {{end}}
  {{else}}
  <p style="color:var(--text-muted)">Port 445 not reachable — SMB signing check skipped.</p>
  {{end}}
  {{end}}
</div>

<div id="tab-audit" class="tab-pane">
  <h2 class="section-title">
    Audit Policy / Blue Team Visibility {{mitreBadges "audit_defense"}}
    <span class="help-icon" data-tip="Checks AD Recycle Bin status (deleted object recovery), legacy audit policy configuration (event log visibility), and machine account quota (RBCD abuse vector).">?</span>
  </h2>
  {{if .AuditResult}}
  <div class="table-wrap" style="margin-bottom:20px"><table>
    <thead><tr><th>Setting</th><th>Status</th></tr></thead>
    <tbody>
      <tr>
        <td>AD Recycle Bin</td>
        <td>
          {{if not .AuditResult.RecycleBinSupported}}
            <span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">Not supported (forest FFL &lt; 2008 R2)</span>
          {{else if .AuditResult.RecycleBinEnabled}}
            <span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">✓ Enabled</span>
          {{else}}
            <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">⚠ Disabled</span>
          {{end}}
        </td>
      </tr>
      <tr>
        <td>Legacy Audit Policy</td>
        <td>
          {{if .AuditResult.AuditingEnabled}}
            <span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">✓ Configured</span>
          {{else}}
            <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">⚠ NOT configured</span>
          {{end}}
        </td>
      </tr>
      <tr>
        <td>Machine Account Quota</td>
        <td>
          {{if eq .AuditResult.MachineAccountQuota 0}}
            <span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">0 — safe ✓</span>
          {{else}}
            <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">⚠ {{.AuditResult.MachineAccountQuota}} — any user can add computers</span>
          {{end}}
        </td>
      </tr>
    </tbody>
  </table></div>

  {{if .AuditResult.AuditingEnabled}}
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Audit Categories</div>
  <div class="table-wrap" style="margin-bottom:20px"><table>
    <thead><tr><th>Category</th><th>Success</th><th>Failure</th></tr></thead>
    <tbody>
      {{range .AuditResult.AuditCategories}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{if .Success}}<span style="color:var(--color-ok)">✓</span>{{else}}<span style="color:var(--text-muted)">—</span>{{end}}</td>
        <td>{{if .Failure}}<span style="color:var(--color-ok)">✓</span>{{else}}<span style="color:var(--text-muted)">—</span>{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table></div>
  {{end}}

  {{if .AuditResult.Findings}}
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Findings</div>
  {{range .AuditResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header">
      <span class="badge {{if eq .Severity "High"}}badge-high{{else if eq .Severity "Medium"}}badge-medium{{else}}badge-critical{{end}}">{{.Severity}}</span>
      <span style="margin-left:8px">{{.Title}}</span>
    </div>
    <div style="padding:8px 16px;color:var(--text-secondary);font-size:0.85rem">{{.Detail}}</div>
  </div>
  {{end}}
  {{else}}
  <p style="color:var(--color-ok)">✓ No audit visibility issues found.</p>
  {{end}}
  {{else}}
  <p style="color:var(--text-muted)">Audit policy data not available.</p>
  {{end}}
</div>

</div><!-- /content -->

<script>

// Findings chart
(function() {
  var chart = document.getElementById('findings-chart');
  if (!chart) return;

  var findings = [
    {
      label: 'Critical',
      color: '#e53e3e',
      count: {{.Summary.CriticalCount}} + {{.Summary.DangerousACLCount}} + {{.Summary.ADCSCriticalCount}} + {{.Summary.DCSyncCount}}
    },
    {
      label: 'High',
      color: '#dd6b20',
      count: {{.Summary.KerberoastableCount}} + {{.Summary.ASREPCount}} + {{.Summary.DelegationCount}} + {{.Summary.ShadowCredCount}}
    },
    {
      label: 'Medium',
      color: '#d69e2e',
      count: {{.Summary.PasswordNeverExpires}} + {{.Summary.AdminCount}} + {{.Summary.StaleUsersCount}} + {{.Summary.AuditFindingCount}}
    },
    {
      label: 'Info',
      color: 'var(--accent)',
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
      '<div style="width:64px;font-size:12px;color:var(--text-muted);text-align:right;font-weight:500">' + f.label + '</div>' +
      '<div style="flex:1;background:var(--bg-hover);border-radius:4px;height:22px;overflow:hidden">' +
        '<div style="width:'+pct+'%;background:'+f.color+';height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px;transition:width .5s ease;min-width:'+(f.count > 0 ? '28px' : '0')+';">' +
          (f.count > 0 ? '<span style="font-size:11px;font-weight:600;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.4)">'+f.count+'</span>' : '') +
        '</div>' +
      '</div>' +
      '<div style="width:36px;font-size:13px;font-weight:600;color:'+f.color+';text-align:right">'+f.count+'</div>';
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

  const rawData = {{.GraphJSON}};
  if (!rawData.nodes || rawData.nodes.length === 0) {
    document.getElementById('graph-container').innerHTML =
      '<p style="padding:40px;color:var(--text-muted);text-align:center">No attack paths to visualize.</p>';
    return;
  }

  // Cap nodes: privileged groups + path nodes first, then fill up
  const MAX_NODES = 80;
  let data = rawData;
  let truncated = false;
  if (rawData.nodes.length > MAX_NODES) {
    truncated = true;
    const priv  = rawData.nodes.filter(n => n.type === 'group' || n.adminCount);
    const other = rawData.nodes.filter(n => n.type !== 'group' && !n.adminCount);
    const kept  = [...priv, ...other.slice(0, MAX_NODES - priv.length)];
    const keptIds = new Set(kept.map(n => n.id));
    data = {
      nodes: kept,
      edges: rawData.edges.filter(e => keptIds.has(e.source) && keptIds.has(e.target))
    };
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

  // Show truncation warning
  if (truncated) {
    const warn = document.createElement('div');
    warn.className = 'graph-warn';
    warn.textContent = 'Graph truncated: showing ' + MAX_NODES + ' of ' + rawData.nodes.length + ' nodes — use --json for full export';
    container.appendChild(warn);
  }

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
        '<div style="font-weight:600;color:var(--text-main);margin-bottom:4px">' + d.label + '</div>' +
        '<div style="color:var(--text-muted);font-size:0.75rem;word-break:break-all">' + d.id + '</div>' +
        '<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">' +
        (d.adminCount ? '<span style="background:#742a2a;color:#fc8181;padding:2px 6px;border-radius:3px;font-size:11px">Admin</span>' : '') +
        (d.kerberoastable ? '<span style="background:#744210;color:#f6ad55;padding:2px 6px;border-radius:3px;font-size:11px">Kerberoastable</span>' : '') +
        (d.asrepRoastable ? '<span style="background:#742a2a;color:#feb2b2;padding:2px 6px;border-radius:3px;font-size:11px">AS-REP</span>' : '') +
        '<span style="background:var(--bg-hover);color:var(--text-secondary);padding:2px 6px;border-radius:3px;font-size:11px">' + d.type + '</span>' +
        '<span style="background:var(--bg-hover);color:var(--text-secondary);padding:2px 6px;border-radius:3px;font-size:11px">' + (pathCount[d.id]||0) + ' edge(s)</span>' +
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
    .attr('stroke', d => d.asrepRoastable ? '#fc8181' : (d.adminCount ? '#feb2b2' : getComputedStyle(document.documentElement).getPropertyValue('--border').trim()))
    .attr('stroke-width', d => d.adminCount || d.asrepRoastable ? 3 : 1.5)
    .attr('cursor', 'pointer');

  node.append('text')
    .attr('dy', d => nodeRadius(d, pathCount, maxCount) + 14)
    .attr('text-anchor', 'middle')
    .attr('font-size', 11)
    .style('fill', 'var(--text-main)')
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
    card.dataset.filtered = show ? 'false' : 'true';
    if (show) visible++;
  });
  const cnt = document.getElementById('cnt-acl');
  if (cnt) cnt.textContent = visible + ' / ' + cards.length;
  buildGroupedACL();
}

// ── Global search ─────────────────────────────────────────────
// Searches all text in all tab-panes, highlights matches, shows result count.
// Global search state
let _gsMatches = []; // [{tabName, el, origHTML}]
let _gsTabCounts = {};

function gsHighlight(query) {
  // restore previous highlights
  _gsMatches.forEach(m => { if (m.el) m.el.innerHTML = m.origHTML; });
  _gsMatches = [];
  _gsTabCounts = {};

  const resultsEl = document.getElementById('gs-results');
  resultsEl.innerHTML = '';

  const q = query.trim();
  const clearBtn = document.getElementById('gs-clear');
  if (clearBtn) clearBtn.style.display = q ? '' : 'none';
  if (!q) return;

  const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(' + escaped + ')', 'gi');

  // walk all tab panes (including hidden ones) for text matches
  document.querySelectorAll('.tab-pane').forEach(pane => {
    const tabName = pane.id.replace('tab-', '');
    let count = 0;
    const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT, {
      acceptNode: n => {
        const p = n.parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        const tag = p.tagName;
        if (tag === 'SCRIPT' || tag === 'STYLE') return NodeFilter.FILTER_REJECT;
        // Skip #acl-findings — it's display:none, content is mirrored in #acl-grouped
        if (p.closest && p.closest('#acl-findings')) return NodeFilter.FILTER_REJECT;
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
        _gsMatches.push({ tabName, el: span, origHTML: orig });
        span.innerHTML = highlighted;
        count += (orig.match(re) || []).length;
      }
    });
    if (count > 0) _gsTabCounts[tabName] = count;
  });

  const total = Object.values(_gsTabCounts).reduce((a, b) => a + b, 0);

  if (total === 0) {
    resultsEl.innerHTML = '<span class="gs-no-match">no matches</span>';
    return;
  }

  // Build clickable tab buttons
  const tabLabels = {
    overview:'Overview', paths:'Paths', kerberos:'Kerberos', acl:'ACL',
    delegation:'Delegation', adcs:'ADCS', trust:'Trust', shadow:'Shadow',
    ldap:'LDAP', audit:'Audit', exposure:'Exposure', users:'Users',
    groups:'Groups', computers:'Computers', smb:'SMB', graph:'Graph'
  };
  Object.entries(_gsTabCounts)
    .sort((a, b) => b[1] - a[1])
    .forEach(([tab, cnt]) => {
      const label = tabLabels[tab] || tab;
      const btn = document.createElement('button');
      btn.className = 'gs-tab-btn';
      btn.textContent = label + ' (' + cnt + ')';
      btn.onclick = function(e) { e.preventDefault(); gsGoTab(tab); };
      resultsEl.appendChild(btn);
    });

  // Auto-expand collapsed sections that contain matches
  _gsMatches.forEach(m => {
    // Expand .exp-section bodies (Exposure tab)
    const expBody = m.el.closest('.exp-body');
    if (expBody && expBody.style.display === 'none') {
      const expHeader = expBody.previousElementSibling;
      if (expHeader && expHeader.classList.contains('exp-header')) {
        expBody.style.display = '';
        const ch = expHeader.querySelector('.chevron');
        if (ch) ch.innerHTML = '&#9660;';
      }
    }
  });

  // Expand ACL groups in #acl-grouped whose body contains highlighted matches
  document.querySelectorAll('#acl-grouped [data-right]').forEach(function(groupHeader) {
    const body = groupHeader.nextElementSibling;
    if (!body || !body.classList.contains('group-body')) return;
    if (body.querySelector('.gs-match') && body.style.display === 'none') {
      body.style.display = '';
      const ch = groupHeader.querySelector('.group-chevron');
      if (ch) ch.innerHTML = '&#9660;';
    }
  });
}

// Navigate to a specific tab from search results
function gsGoTab(tabName) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  const pane = document.getElementById('tab-' + tabName);
  if (pane) pane.classList.add('active');
  const btn = document.querySelector('.nav button[onclick="showTab(\'' + tabName + '\')"]');
  if (btn) btn.classList.add('active');
  if (tabName === 'graph') initGraph();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  // Scroll first match in this tab into view
  const firstMatch = document.querySelector('#tab-' + tabName + ' .gs-match');
  if (firstMatch) {
    setTimeout(() => firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' }), 150);
  }
}

// Navigate to tab with most matches (called on Enter key)
function gsNavigateFirst() {
  const entries = Object.entries(_gsTabCounts).sort((a, b) => b[1] - a[1]);
  if (entries.length > 0) gsGoTab(entries[0][0]);
}

function clearGlobalSearch() {
  _gsMatches.forEach(m => { if (m.el) m.el.innerHTML = m.origHTML; });
  _gsMatches = [];
  _gsTabCounts = {};
  const inp = document.getElementById('gs-input');
  if (inp) inp.value = '';
  document.getElementById('gs-results').innerHTML = '';
  const clearBtn = document.getElementById('gs-clear');
  if (clearBtn) clearBtn.style.display = 'none';
}

// MITRE badge HTML per ACL right
const _aclMitre = {
  'GenericAll':          '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'WriteDACL':           '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'WriteOwner':          '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'GenericWrite':        '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'ForceChangePassword': '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1098/" target="_blank" title="Account Manipulation">T1098</a>',
  'AddMember':           '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1098/" target="_blank" title="Account Manipulation">T1098</a>',
};

function buildGroupedACL() {
  const allCards = document.querySelectorAll('#acl-findings .acl-card');
  const groups = {};
  const order  = [];
  const sevOrder = { 'Critical': 0, 'High': 1, 'Medium': 2 };

  allCards.forEach(function(card) {
    if (card.dataset.filtered === 'true') return;
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

  if (order.length === 0) {
    container.innerHTML = '<p style="color:var(--text-muted);padding:12px">No findings match the current filter.</p>';
    return;
  }

  order.forEach(function(right) {
    const g     = groups[right];
    const count = g.cards.length;
    const sevClass = g.severity === 'Critical' ? 'badge-critical' : g.severity === 'High' ? 'badge-medium' : 'badge-ok';
    const mitreBadges = _aclMitre[right] || '';

    const section = document.createElement('div');
    section.style.cssText = 'margin-bottom:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--bg-grouped);border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
    header.dataset.right = right;
    header.innerHTML =
      '<span class="chevron" style="color:var(--text-muted);font-size:12px;min-width:10px">&#9660;</span>' +
      '<span class="badge badge-critical" style="font-family:monospace">' + right + '</span>' +
      '<span style="color:var(--text-main);font-weight:600">' + count + ' finding' + (count !== 1 ? 's' : '') + '</span>' +
      mitreBadges +
      '<span class="badge ' + sevClass + '" style="margin-left:auto">' + g.severity + '</span>';

    const body = document.createElement('div');
    body.className = 'group-body';
    body.style.padding = '8px';
    g.cards.forEach(function(card) {
      var clone = card.cloneNode(true);
      clone.style.display = '';
      body.appendChild(clone);
    });

    const chevron = header.querySelector('.chevron');
    if (chevron) chevron.classList.add('group-chevron');

    header.onclick = function() {
      var open = body.style.display !== 'none';
      body.style.display = open ? 'none' : '';
      const ch = header.querySelector('.group-chevron');
      if (ch) ch.innerHTML = open ? '&#9658;' : '&#9660;';
    };

    section.appendChild(header);
    section.appendChild(body);
    container.appendChild(section);
  });
}

document.addEventListener('DOMContentLoaded', function() {
  if (document.querySelector('#acl-findings .acl-card')) buildGroupedACL();
});

// ── Collapsible exposure sections ────────────────────────────
function toggleExpSection(header) {
  const body = header.nextElementSibling;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  header.querySelector('.chevron').innerHTML = open ? '&#9658;' : '&#9660;';
}

function expandAllIn(sel) {
  // Exposure static sections
  document.querySelectorAll(sel + ' .exp-body').forEach(function(b) { b.style.display = ''; });
  document.querySelectorAll(sel + ' .exp-header .chevron').forEach(function(c) { c.innerHTML = '&#9660;'; });
  // ACL dynamically built groups
  document.querySelectorAll(sel + ' .group-body').forEach(function(b) { b.style.display = ''; });
  document.querySelectorAll(sel + ' .group-chevron').forEach(function(c) { c.innerHTML = '&#9660;'; });
}

function collapseAllIn(sel) {
  document.querySelectorAll(sel + ' .exp-body').forEach(function(b) { b.style.display = 'none'; });
  document.querySelectorAll(sel + ' .exp-header .chevron').forEach(function(c) { c.innerHTML = '&#9658;'; });
  document.querySelectorAll(sel + ' .group-body').forEach(function(b) { b.style.display = 'none'; });
  document.querySelectorAll(sel + ' .group-chevron').forEach(function(c) { c.innerHTML = '&#9658;'; });
}

// ── Row limit (large tables) ──────────────────────────────────
const _ROW_LIMIT = 100;
function limitTableRows(tableId) {
  const tbody = document.querySelector('#' + tableId + ' tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.rows);
  if (rows.length <= _ROW_LIMIT) return;
  rows.slice(_ROW_LIMIT).forEach(function(r) { r.style.display = 'none'; r.dataset.limited = '1'; });
  const wrap = tbody.closest('.table-wrap') || tbody.closest('table');
  const btn = document.createElement('button');
  btn.className = 'show-all-btn';
  btn.textContent = 'Show all ' + rows.length + ' rows (currently showing ' + _ROW_LIMIT + ')';
  btn.onclick = function() {
    rows.forEach(function(r) { if (r.dataset.limited) r.style.display = ''; });
    btn.remove();
  };
  (wrap || tbody).after(btn);
}
document.addEventListener('DOMContentLoaded', function() {
  ['tbl-users', 'tbl-groups', 'tbl-computers',
   'tbl-desc', 'tbl-stale-users', 'tbl-stale-comp', 'tbl-nolaps'].forEach(limitTableRows);
});

// ── Theme toggle ──────────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('adpath-theme', next);
  document.getElementById('theme-toggle').textContent = next === 'dark' ? '🌙' : '☀️';
}
function initTheme() {
  const saved = localStorage.getItem('adpath-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  const btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
}
initTheme();
</script>

</body>
</html>`