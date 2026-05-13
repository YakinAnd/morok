// gendemo2 generates two morok HTML reports (before/after remediation) for History tab demo.
package main

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/YakinAnd/morok/internal/analysis"
	"github.com/YakinAnd/morok/internal/graph"
	adldap "github.com/YakinAnd/morok/internal/ldap"
	"github.com/YakinAnd/morok/internal/report"
)

const dom = "sevenkingdoms.local"
const base = "DC=sevenkingdoms,DC=local"

func main() {
	// Generate "before" report (bad state — 3 months ago)
	if err := generate("demo-before.html", buildBefore(), "2026-02-14 09:00:00"); err != nil {
		fmt.Fprintln(os.Stderr, "before:", err)
		os.Exit(1)
	}
	fmt.Println("Written: demo-before.html")

	// Generate "after" report (post-remediation — today)
	if err := generate("demo-after.html", buildAfter(), time.Now().Format("2006-01-02 15:04:05")); err != nil {
		fmt.Fprintln(os.Stderr, "after:", err)
		os.Exit(1)
	}
	fmt.Println("Written: demo-after.html")
	fmt.Println("\nOpen demo-after.html in your browser,")
	fmt.Println("go to the History tab, and load demo-before.html as baseline.")
}

type scenario struct {
	kerberos    *analysis.KerberosResult
	acl         *analysis.ACLResult
	delegation  *analysis.DelegationResult
	shadow      *analysis.ShadowCredentialsResult
	adcs        *analysis.ADCSResult
	g           *graph.Graph
	paths       []graph.AttackPath
}

func generate(outPath string, s scenario, timestamp string) error {
	result := &adldap.EnumerationResult{
		Domain:      dom,
		BaseDN:      base,
		CollectedAt: time.Now(),
		Users:       sharedUsers(),
		Groups:      sharedGroups(),
		Computers:   sharedComputers(),
	}

	err := report.Generate(
		outPath, result,
		s.g, s.paths,
		s.kerberos, s.acl,
		buildDelegation(), buildGPO(),
		buildHygiene(result), nil,
		s.adcs,
		buildProtectedUsers(), buildAdminSDHolder(), buildTrusts(),
		s.shadow,
		buildLDAPSec(), buildAudit(), buildSMB(), buildSYSVOL(), buildLAPSACL(),
		nil, "Password",
	)
	if err != nil {
		return err
	}
	// Patch the embedded snapshot timestamp so the timeline looks realistic
	return patchTimestamp(outPath, timestamp)
}

// patchTimestamp rewrites generated_at inside the morok-data JSON blob.
func patchTimestamp(path, ts string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`("generated_at"\s*:\s*)"[^"]*"`)
	patched := re.ReplaceAll(data, []byte(`${1}"`+ts+`"`))
	return os.WriteFile(path, patched, 0644)
}

// ── Before: bad state ─────────────────────────────────────────

func buildBefore() scenario {
	s := scenario{}
	s.kerberos = &analysis.KerberosResult{
		Domain: dom,
		KerberoastableAccounts: []analysis.KerberoastableAccount{
			{SAMAccountName: "svc_sql",    SPNs: []string{"MSSQLSvc/kingslanding.sevenkingdoms.local:1433"}, CVSS: 8.8, Severity: "High"},
			{SAMAccountName: "svc_backup", SPNs: []string{"backup/kingslanding.sevenkingdoms.local"},        CVSS: 9.1, Severity: "Critical"},
			{SAMAccountName: "jsnow",      SPNs: []string{"HTTP/winterfell.sevenkingdoms.local"},            CVSS: 7.5, Severity: "High"},
		},
		ASREPAccounts: []analysis.ASREPAccount{
			{SAMAccountName: "tyrion", CVSS: 7.5, Severity: "High"},
		},
	}
	s.acl = &analysis.ACLResult{
		Domain: dom,
		Findings: []analysis.ACLFinding{
			{PrincipalName: "Night's Watch", TargetName: "Domain Admins",    Right: analysis.RightGenericAll,          Severity: "Critical", CVSS: 9.9},
			{PrincipalName: "tyrion",        TargetName: "Small Council",    Right: analysis.RightWriteDACL,           Severity: "Critical", CVSS: 9.1},
			{PrincipalName: "cersei",        TargetName: "jsnow",            Right: analysis.RightForceChangePassword, Severity: "High",     CVSS: 8.1},
			{PrincipalName: "Small Council", TargetName: "Remote Desktop Users", Right: analysis.RightAddMember,       Severity: "High",     CVSS: 8.0},
		},
		DCSyncFindings: []analysis.DCSyncFinding{
			{PrincipalName: "cersei", PrincipalType: "user", Severity: "Critical", CVSS: 10.0},
		},
	}
	s.shadow = &analysis.ShadowCredentialsResult{
		Domain: dom,
		Findings: []analysis.ShadowCredentialFinding{
			{PrincipalName: "Night's Watch", PrincipalType: "group", TargetName: "KINGSLANDING$", TargetType: "computer", Right: "WriteProperty(msDS-KeyCredentialLink)", Severity: "Critical", CVSS: 9.0},
			{PrincipalName: "tyrion",        PrincipalType: "user",  TargetName: "Administrator",  TargetType: "user",     Right: "WriteProperty(msDS-KeyCredentialLink)", Severity: "High",     CVSS: 8.5},
		},
	}
	s.adcs = &analysis.ADCSResult{
		Domain: dom,
		CAs: []analysis.CAInfo{{Name: "SEVENKINGDOMS-CA", DN: "CN=SEVENKINGDOMS-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + base, Server: "kingslanding.sevenkingdoms.local"}},
		TemplateFindings: []analysis.CertTemplateFinding{
			{TemplateName: "UserTemplate", CAName: "SEVENKINGDOMS-CA", VulnTypes: []analysis.ADCSVulnType{analysis.ESC1}, EnrollableBy: []string{"Domain Users"}, AllowsSANInject: true, AuthEnabled: true, EKUs: []string{"Client Authentication"}, Severity: "Critical", CVSS: 9.8},
			{TemplateName: "WebServer",    CAName: "SEVENKINGDOMS-CA", VulnTypes: []analysis.ADCSVulnType{analysis.ESC3}, EnrollableBy: []string{"Night's Watch"}, AuthEnabled: true, EKUs: []string{"Certificate Request Agent"}, Severity: "High", CVSS: 8.1},
		},
	}
	s.g, s.paths = buildPaths(true)
	return s
}

// ── After: post-remediation ───────────────────────────────────

func buildAfter() scenario {
	s := scenario{}
	s.kerberos = &analysis.KerberosResult{
		Domain: dom,
		KerberoastableAccounts: []analysis.KerberoastableAccount{
			// jsnow SPNs removed, svc_backup SPN removed — only svc_sql remains
			{SAMAccountName: "svc_sql", SPNs: []string{"MSSQLSvc/kingslanding.sevenkingdoms.local:1433"}, CVSS: 8.8, Severity: "High"},
		},
		// tyrion preauth enabled — no ASREP
		ASREPAccounts: []analysis.ASREPAccount{},
	}
	s.acl = &analysis.ACLResult{
		Domain: dom,
		Findings: []analysis.ACLFinding{
			// GenericAll and WriteDACL removed; cersei's ForceChangePassword and AddMember still pending
			{PrincipalName: "cersei",        TargetName: "jsnow",            Right: analysis.RightForceChangePassword, Severity: "High", CVSS: 8.1},
			{PrincipalName: "Small Council", TargetName: "Remote Desktop Users", Right: analysis.RightAddMember,       Severity: "High", CVSS: 8.0},
		},
		DCSyncFindings: []analysis.DCSyncFinding{
			{PrincipalName: "cersei", PrincipalType: "user", Severity: "Critical", CVSS: 10.0},
		},
	}
	s.shadow = &analysis.ShadowCredentialsResult{
		Domain:   dom,
		Findings: []analysis.ShadowCredentialFinding{}, // fully remediated
	}
	s.adcs = &analysis.ADCSResult{
		Domain: dom,
		CAs: []analysis.CAInfo{{Name: "SEVENKINGDOMS-CA", DN: "CN=SEVENKINGDOMS-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + base, Server: "kingslanding.sevenkingdoms.local"}},
		TemplateFindings: []analysis.CertTemplateFinding{
			// WebServer ESC3 remediated; UserTemplate ESC1 still open
			{TemplateName: "UserTemplate", CAName: "SEVENKINGDOMS-CA", VulnTypes: []analysis.ADCSVulnType{analysis.ESC1}, EnrollableBy: []string{"Domain Users"}, AllowsSANInject: true, AuthEnabled: true, EKUs: []string{"Client Authentication"}, Severity: "Critical", CVSS: 9.8},
		},
	}
	s.g, s.paths = buildPaths(false)
	return s
}

// ── Graph / paths ─────────────────────────────────────────────

func buildPaths(full bool) (*graph.Graph, []graph.AttackPath) {
	g := graph.NewGraph()
	jsnow     := &graph.Node{DN: "CN=jsnow,CN=Users," + base,       SAMAccountName: "jsnow",       Type: graph.NodeUser,  Kerberoastable: full}
	nw        := &graph.Node{DN: "CN=Night's Watch,CN=Users," + base, SAMAccountName: "Night's Watch", Type: graph.NodeGroup}
	da        := &graph.Node{DN: "CN=Domain Admins,CN=Users," + base, SAMAccountName: "Domain Admins", Type: graph.NodeGroup, AdminCount: true}
	svcBackup := &graph.Node{DN: "CN=svc_backup,CN=Users," + base,   SAMAccountName: "svc_backup",   Type: graph.NodeUser}
	bo        := &graph.Node{DN: "CN=Backup Operators,CN=Builtin," + base, SAMAccountName: "Backup Operators", Type: graph.NodeGroup, AdminCount: true}
	tyrion    := &graph.Node{DN: "CN=tyrion,CN=Users," + base,       SAMAccountName: "tyrion",       Type: graph.NodeUser}
	council   := &graph.Node{DN: "CN=Small Council,CN=Users," + base, SAMAccountName: "Small Council", Type: graph.NodeGroup}
	rdu       := &graph.Node{DN: "CN=Remote Desktop Users,CN=Builtin," + base, SAMAccountName: "Remote Desktop Users", Type: graph.NodeGroup}

	for _, n := range []*graph.Node{jsnow, nw, da, svcBackup, bo, tyrion, council, rdu} {
		g.AddNode(n)
	}

	var paths []graph.AttackPath
	if full {
		paths = append(paths, graph.AttackPath{
			Nodes: []graph.Node{*jsnow, *nw, *da},
			Edges: []graph.Edge{{From: jsnow.DN, To: nw.DN, Type: "MemberOf"}, {From: nw.DN, To: da.DN, Type: "GenericAll"}},
			Depth: 2, TargetGroup: "Domain Admins",
		})
	}
	paths = append(paths, graph.AttackPath{
		Nodes: []graph.Node{*svcBackup, *bo},
		Edges: []graph.Edge{{From: svcBackup.DN, To: bo.DN, Type: "MemberOf"}},
		Depth: 1, TargetGroup: "Backup Operators",
	})
	if full {
		paths = append(paths, graph.AttackPath{
			Nodes: []graph.Node{*tyrion, *council, *rdu, *da},
			Edges: []graph.Edge{{From: tyrion.DN, To: council.DN, Type: "MemberOf"}, {From: council.DN, To: rdu.DN, Type: "WriteDACL"}, {From: rdu.DN, To: da.DN, Type: "AddMember"}},
			Depth: 3, TargetGroup: "Domain Admins",
		})
	}
	return g, paths
}

// ── Shared builders (same in both states) ─────────────────────

func sharedUsers() []adldap.LDAPUser {
	return []adldap.LDAPUser{
		{DN: "CN=Administrator,CN=Users," + base, SAMAccountName: "Administrator", Enabled: true, AdminCount: true, MemberOf: []string{"CN=Domain Admins,CN=Users," + base, "CN=Enterprise Admins,CN=Users," + base}},
		{DN: "CN=jsnow,CN=Users," + base, SAMAccountName: "jsnow", Enabled: true, MemberOf: []string{"CN=Night's Watch,CN=Users," + base}},
		{DN: "CN=cersei,CN=Users," + base, SAMAccountName: "cersei", Enabled: true, AdminCount: true, PasswordNeverExpires: true, Description: "Password: Cersei2024!", MemberOf: []string{"CN=Domain Admins,CN=Users," + base}},
		{DN: "CN=tyrion,CN=Users," + base, SAMAccountName: "tyrion", Enabled: true, DontReqPreauth: true, MemberOf: []string{"CN=Small Council,CN=Users," + base}},
		{DN: "CN=svc_sql,CN=Users," + base, SAMAccountName: "svc_sql", Enabled: true, PasswordNeverExpires: true, SPNs: []string{"MSSQLSvc/kingslanding.sevenkingdoms.local:1433"}, MemberOf: []string{"CN=Service Accounts,CN=Users," + base}},
		{DN: "CN=svc_backup,CN=Users," + base, SAMAccountName: "svc_backup", Enabled: true, PasswordNeverExpires: true, MemberOf: []string{"CN=Backup Operators,CN=Builtin," + base}},
		{DN: "CN=krbtgt,CN=Users," + base, SAMAccountName: "krbtgt", Enabled: false, PasswordLastSet: "2023-01-10 10:00:00"},
		{DN: "CN=stannis,CN=Users," + base, SAMAccountName: "stannis", Enabled: true, AdminCount: true, LastLogon: "2025-06-15 09:00:00", MemberOf: []string{"CN=Domain Admins,CN=Users," + base}},
	}
}

func sharedGroups() []adldap.LDAPGroup {
	return []adldap.LDAPGroup{
		{DN: "CN=Domain Admins,CN=Users," + base, SAMAccountName: "Domain Admins", AdminCount: true, Members: []string{"CN=Administrator,CN=Users," + base, "CN=cersei,CN=Users," + base, "CN=stannis,CN=Users," + base}},
		{DN: "CN=Enterprise Admins,CN=Users," + base, SAMAccountName: "Enterprise Admins", AdminCount: true, Members: []string{"CN=Administrator,CN=Users," + base}},
		{DN: "CN=Backup Operators,CN=Builtin," + base, SAMAccountName: "Backup Operators", AdminCount: true, Members: []string{"CN=svc_backup,CN=Users," + base}},
		{DN: "CN=Night's Watch,CN=Users," + base, SAMAccountName: "Night's Watch", Members: []string{"CN=jsnow,CN=Users," + base}},
		{DN: "CN=Small Council,CN=Users," + base, SAMAccountName: "Small Council", Members: []string{"CN=tyrion,CN=Users," + base}},
		{DN: "CN=Remote Desktop Users,CN=Builtin," + base, SAMAccountName: "Remote Desktop Users", Members: []string{"CN=cersei,CN=Users," + base}},
		{DN: "CN=Domain Users,CN=Users," + base, SAMAccountName: "Domain Users"},
		{DN: "CN=Service Accounts,CN=Users," + base, SAMAccountName: "Service Accounts", Members: []string{"CN=svc_sql,CN=Users," + base, "CN=svc_backup,CN=Users," + base}},
	}
}

func sharedComputers() []adldap.LDAPComputer {
	return []adldap.LDAPComputer{
		{DN: "CN=KINGSLANDING,OU=Domain Controllers," + base, SAMAccountName: "KINGSLANDING$", OperatingSystem: "Windows Server 2019 Datacenter", Enabled: true, LAPSEnabled: false, UnconstrainedDelegation: true, LastLogon: "2026-05-13 08:00:01", Domain: dom},
		{DN: "CN=WINTERFELL,OU=Servers," + base, SAMAccountName: "WINTERFELL$", OperatingSystem: "Windows Server 2016 Standard", Enabled: true, LAPSEnabled: true, LastLogon: "2026-05-12 22:10:33", Domain: dom},
		{DN: "CN=CASTLEBLACK,OU=Servers," + base, SAMAccountName: "CASTLEBLACK$", OperatingSystem: "Windows Server 2012 R2 Standard", Enabled: true, LAPSEnabled: false, LastLogon: "2026-05-11 04:01:44", Domain: dom},
		{DN: "CN=DRAGONSTONE,OU=Workstations," + base, SAMAccountName: "DRAGONSTONE$", OperatingSystem: "Windows 10 Enterprise", Enabled: true, LAPSEnabled: false, LastLogon: "2025-09-01 14:55:00", Domain: dom},
		{DN: "CN=REDKEEP,OU=Servers," + base, SAMAccountName: "REDKEEP$", OperatingSystem: "Windows Server 2022 Datacenter", Enabled: true, LAPSEnabled: true, LastLogon: "2026-05-13 07:45:00", Domain: dom},
	}
}

func buildDelegation() *analysis.DelegationResult {
	return &analysis.DelegationResult{
		Domain: dom,
		Findings: []analysis.DelegationFinding{
			{SAMAccountName: "KINGSLANDING$", ObjectType: "computer", DelegationType: analysis.DelegationUnconstrained, IsHighRisk: true, RiskReason: "Unconstrained delegation on DC.", Severity: "Critical", CVSS: 9.0},
		},
	}
}

func buildGPO() *analysis.GPOResult {
	return &analysis.GPOResult{
		Domain: dom,
		PasswordPolicy: &analysis.PasswordPolicy{MinLength: 7, Complexity: false, MaxAge: 42, LockoutThreshold: 5},
		GPOFindings: []analysis.GPOFinding{
			{Name: "Default Domain Policy", GUID: "{31B2F340-016D-11D2-945F-00C04FB984F9}", LinkedTo: []string{base}},
		},
	}
}

func buildHygiene(result *adldap.EnumerationResult) *analysis.HygieneResult {
	var stale []adldap.LDAPUser
	for _, u := range result.Users {
		if u.SAMAccountName == "stannis" {
			stale = append(stale, u)
		}
	}
	return &analysis.HygieneResult{
		StaleUsers:      stale,
		PasswordInDesc:  []analysis.PasswordInDescFinding{{SAMAccountName: "cersei", ObjectType: "user", Description: "Password: Cersei2024!"}},
		KrbtgtPwdAgeDays: 488, KrbtgtLastSet: "2023-01-10 10:00:00", KrbtgtAtRisk: true,
		NoLAPSCount: 3, TotalComputers: 5,
		NoLAPSComputers: result.Computers[:3],
	}
}

func buildProtectedUsers() *analysis.ProtectedUsersResult {
	return &analysis.ProtectedUsersResult{
		ProtectedUsersExists: true,
		Members:              []string{"Administrator"},
		PrivilegedNotProtected: []analysis.PrivNotProtectedFinding{
			{SAMAccountName: "cersei", Groups: []string{"Domain Admins"}, Severity: "High"},
		},
	}
}

func buildAdminSDHolder() *analysis.AdminSDHolderResult {
	return &analysis.AdminSDHolderResult{
		CustomACEs: []analysis.AdminSDHolderACEFinding{
			{PrincipalName: "Night's Watch", Rights: []string{"GenericAll"}, Severity: "Critical", CVSS: 9.9},
		},
	}
}

func buildTrusts() *analysis.TrustResult {
	return &analysis.TrustResult{
		Domain: dom,
		Trusts: []analysis.Trust{
			{Name: "north.sevenkingdoms.local", Direction: analysis.TrustDirectionBidirectional, TrustType: analysis.TrustTypeUplevel, SIDFilteringOn: false, IsWithinForest: true, Risks: []string{"SID filtering disabled"}, Severity: "High"},
		},
	}
}

func buildLDAPSec() *analysis.LDAPSecurityResult {
	return &analysis.LDAPSecurityResult{
		Domain: dom, PlainLDAP: true, SigningChecked: true, SigningEnforced: false,
		Findings: []analysis.LDAPSecurityFinding{
			{Title: "LDAP signing not enforced", Detail: "Relay attacks possible.", Severity: "High", CVSS: 8.1},
		},
	}
}

func buildAudit() *analysis.AuditResult {
	return &analysis.AuditResult{
		Domain: dom, RecycleBinEnabled: false, RecycleBinSupported: true,
		MachineAccountQuota: 10,
		Findings: []analysis.AuditFinding{
			{Title: "AD Recycle Bin disabled", Severity: "Medium"},
			{Title: "Machine Account Quota = 10", Severity: "High"},
		},
	}
}

func buildSMB() *analysis.SMBSigningResult {
	return &analysis.SMBSigningResult{
		Host: "kingslanding.sevenkingdoms.local", Reachable: true,
		Findings: []analysis.SMBSigningFinding{
			{Title: "SMB signing not required on CASTLEBLACK", Severity: "High", CVSS: 8.1},
		},
	}
}

func buildSYSVOL() *analysis.SYSVOLResult {
	return &analysis.SYSVOLResult{Domain: dom, Scanned: true}
}

func buildLAPSACL() *analysis.LAPSACLResult {
	return &analysis.LAPSACLResult{Domain: dom, LAPSFound: true}
}
